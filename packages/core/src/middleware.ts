/**
 * Express middleware factory (F5.3).
 *
 * On first call, spawns the worker_thread and opens the SQLite store. For
 * each request it:
 *   1. Extracts a CanonicalRequest from Express req
 *   2. Computes the 73-feature vector via @logsguardian/extractor
 *   3. Sends it to the worker with a timeout
 *   4. Applies the decision policy (docs/decision-policy.md §3)
 *   5. In 'block' mode: sends HTTP 403 if verdict is 'block'
 *   6. Logs the event asynchronously (after next/403)
 *
 * Fail-open guarantee: if the worker does not respond within timeoutMs, or if
 * the worker is not available, the request is always forwarded. A logsguardian
 * failure must never become a DoS vector against the host application.
 */
import { Worker } from "worker_threads";
import * as path from "path";
import type { Request, Response, NextFunction, RequestHandler } from "express";
import { normalizeCanonicalRequest } from "@logsguardian/extractor";
import { EventStore } from "./store";
import { sendWebhook } from "./webhook";
import type {
  AttackClass,
  DetectionEvent,
  MiddlewareOptions,
  Verdict,
  WorkerRequest,
  WorkerResponse,
} from "./types";

// Per-class thresholds calibrated on val + E2E test set (docs/decision-policy.md §3).
// Only sqli's threshold moves off the legacy 0.35 global default: short benign
// multi-field forms and short sqli payloads overlap in feature space just above
// 0.35 confidence, so sqli alone needed raising to clear that overlap. Raising
// xss/path_traversal/cmdi too (as a val-only sweep suggested) cost detection
// rate on E2E without any measurable FP benefit, so they stay at baseline.
const RF_THRESHOLDS: Record<AttackClass, number> = {
  benign: 0,
  sqli: 0.45,
  xss: 0.35,
  path_traversal: 0.35,
  cmdi: 0.35,
};
const DEFAULT_THRESHOLD = 0.35;
const IF_THRESHOLD = 0.006939247795563042;
const RF_CLASSES: AttackClass[] = ["benign", "cmdi", "path_traversal", "sqli", "xss"];

const DEFAULT_TIMEOUT_MS = 50;
const DEFAULT_MODEL_DIR = path.join(__dirname, "..", "models");

let _requestId = 0;

export function logsguardian(options: MiddlewareOptions = {}): RequestHandler {
  const mode = options.mode ?? "block";
  // options.threshold, if set, overrides every class threshold (simple global override).
  const userThreshold = options.threshold;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const modelDir = options.modelDir ?? DEFAULT_MODEL_DIR;
  const webhookUrl = options.webhookUrl;

  let store: EventStore | null = null;
  try {
    store = new EventStore(options.dbPath);
  } catch {
    // Store failures are non-fatal; events won't be persisted.
  }

  const pending = new Map<number, { resolve: (r: WorkerResponse) => void; timer: ReturnType<typeof setTimeout> }>();
  let worker: Worker | null = null;

  try {
    worker = new Worker(path.join(__dirname, "worker.js"), {
      workerData: { modelDir },
    });

    worker.on("message", (msg: WorkerResponse) => {
      const entry = pending.get(msg.id);
      if (!entry) return;
      clearTimeout(entry.timer);
      pending.delete(msg.id);
      entry.resolve(msg);
    });

    worker.on("error", () => {
      // Drain all pending with error so timeouts don't accumulate.
      for (const [id, entry] of pending) {
        clearTimeout(entry.timer);
        entry.resolve({ id, error: "worker error" });
        pending.delete(id);
      }
      worker = null;
    });
  } catch {
    // Worker failed to start (e.g., dist/worker.js not compiled yet).
    // Middleware remains in fail-open mode for all requests.
    worker = null;
  }

  function infer(canonical: import("@logsguardian/extractor").CanonicalRequest): Promise<WorkerResponse> {
    return new Promise((resolve) => {
      const id = ++_requestId;
      const timer = setTimeout(() => {
        pending.delete(id);
        resolve({ id, error: "timeout" });
      }, timeoutMs);
      pending.set(id, { resolve, timer });
      const req: WorkerRequest = { id, canonical };
      worker!.postMessage(req);
    });
  }

  function applyPolicy(
    response: WorkerResponse
  ): { verdict: Verdict; predicted_class: AttackClass; confidence: number; if_score: number; is_anomaly: boolean } {
    if (response.error || !response.rfProbs || response.ifScore === undefined) {
      return { verdict: "timeout", predicted_class: "benign", confidence: 0, if_score: 0, is_anomaly: false };
    }

    const { rfProbs, ifScore } = response;
    const maxIdx = rfProbs.reduce((best, p, i) => (p > rfProbs[best] ? i : best), 0);
    const predicted_class = RF_CLASSES[maxIdx];
    const confidence = rfProbs[maxIdx];
    const is_attack = predicted_class !== "benign";
    const is_anomaly = ifScore < IF_THRESHOLD;
    const threshold = userThreshold ?? RF_THRESHOLDS[predicted_class] ?? DEFAULT_THRESHOLD;

    let verdict: Verdict;
    if (is_attack && confidence >= threshold) {
      verdict = "block";
    } else if (is_anomaly) {
      verdict = "pass_anomaly";
    } else {
      verdict = "pass";
    }

    return { verdict, predicted_class, confidence, if_score: ifScore, is_anomaly };
  }

  return async function logsguardianMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    const t0 = Date.now();
    const queryString = typeof req.query === "string"
      ? req.query
      : new URLSearchParams(req.query as Record<string, string>).toString();
    const userAgent = (req.headers["user-agent"] as string) ?? "";
    const clientIp = req.ip ?? "";

    // Build CanonicalRequest — feature extraction runs inside the worker thread
    const canonical = normalizeCanonicalRequest({
      method: req.method,
      path: req.path,
      query: queryString,
      // req.body is {} by default when no body-parser populates it (truthy but empty).
      // Checking key count avoids treating "{}" as a real body, which would shadow
      // the query string — where SQLi/XSS/PT/CMDi payloads are overwhelmingly delivered.
      // Encoded the same way as the query string (URLSearchParams, not JSON.stringify):
      // the training corpus's body samples are raw form-encoded text, so wrapping parsed
      // body objects in JSON syntax ({, }, :, ,, extra ") introduced structural characters
      // the model was never trained to see in benign requests, causing false positives on
      // ordinary form POSTs (e.g. login) — see logSguarDian-vulnerable-project/docs/config2-results.md.
      body: typeof req.body === "string"
        ? req.body
        : (req.body && typeof req.body === "object" && Object.keys(req.body).length > 0
          ? new URLSearchParams(req.body as Record<string, string>).toString()
          : ""),
      userAgent,
      contentType: (req.headers["content-type"] as string) ?? "",
      referer: (req.headers["referer"] as string) ?? "",
      cookie: (req.headers["cookie"] as string) ?? "",
      extraHeaders: Object.fromEntries(
        Object.entries(req.headers)
          .filter(([k]) => !["host","user-agent","accept","content-type","content-length",
                            "authorization","cookie","referer","connection",
                            "accept-encoding","accept-language","cache-control"].includes(k))
          .map(([k, v]) => [k, Array.isArray(v) ? v[0] : (v ?? "")])
      ),
    });

    let result: { verdict: Verdict; predicted_class: AttackClass; confidence: number; if_score: number; is_anomaly: boolean };

    if (!worker) {
      result = { verdict: "timeout", predicted_class: "benign", confidence: 0, if_score: 0, is_anomaly: false };
    } else {
      const workerResp = await infer(canonical);
      result = applyPolicy(workerResp);
    }

    const needsWebhook = webhookUrl && (result.verdict === "block" || result.verdict === "pass_anomaly");
    const elapsedMs = Date.now() - t0;

    const event: DetectionEvent = {
      timestamp: t0,
      method: req.method,
      path: req.path,
      query_string: queryString,
      user_agent: userAgent,
      client_ip: clientIp,
      verdict: result.verdict,
      predicted_class: result.predicted_class,
      confidence: result.confidence,
      if_score: result.if_score,
      is_anomaly: result.is_anomaly,
      webhook_sent: !!needsWebhook,
      elapsed_ms: elapsedMs,
    };

    if (needsWebhook) sendWebhook(webhookUrl!, event);

    if (mode === "block" && result.verdict === "block") {
      try { store?.log(event); } catch { /* non-fatal */ }
      res.status(403).json({ error: "Forbidden", class: result.predicted_class });
      return;
    }

    next();
    try { store?.log(event); } catch { /* non-fatal */ }
  };
}
