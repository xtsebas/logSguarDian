/**
 * Express middleware factory (F5.3, revised for pool architecture).
 *
 * On first call, spawns a dedicated RF worker plus a small pool of IF
 * workers (round-robin dispatched), and opens the SQLite store. For
 * each request it:
 *   1. Extracts a CanonicalRequest from Express req
 *   2. Dispatches it to the RF worker AND to the next IF worker in rotation
 *   3. Resolves as soon as the RF hop answers (see below) — applies the
 *      decision policy (docs/decision-policy.md §3)
 *   4. In 'block' mode: sends HTTP 403 if verdict is 'block'
 *   5. Logs the event asynchronously (after next/403)
 *
 * Why two workers per request instead of one: onnxruntime-node's native
 * addon serializes concurrent InferenceSession.run() calls on the same
 * worker_thread — confirmed this is thread-scoped, not per-session (pooling
 * multiple sessions inside one thread doesn't help; separate worker_threads
 * do, each roughly halving queueing growth under concurrent load). RF alone
 * has no concurrency problem (near-zero, flat inference time), so only IF
 * is pooled across multiple dedicated worker_threads.
 *
 * RF is the sole blocking authority (decision-policy.md §3); IF is
 * log-only/diagnostic. But IF is consistently slower than RF (measured
 * p50/p95 of ~1-3.5ms vs RF's ~0.03-0.13ms) — resolving the instant RF
 * replies would mean IF almost never gets folded into the verdict, silently
 * gutting pass_anomaly/IF-driven detection. So: once RF replies, if IF
 * hasn't answered yet, wait a short bounded IF_GRACE_MS window (sized to
 * IF's own measured p95 + margin) before finalizing — not the full
 * fail-open timeoutMs, just enough to catch the common case where IF is
 * merely a few ms behind. If IF still hasn't answered when the grace
 * window expires (or its worker fails), finalize without it — accepted
 * data loss on the genuinely-slow-IF case, rather than a log-patch
 * mechanism. This bounds, but does not eliminate, added latency: every
 * request where IF is slower than RF (the common case) pays up to
 * IF_GRACE_MS extra, which is intentional — it's approximately the same
 * wait the original single-worker Promise.all design always paid, not new
 * overhead introduced by the pool.
 *
 * Fail-open guarantee: if the RF worker does not respond within timeoutMs,
 * or is not available, the request is always forwarded. A logsguardian
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

const RF_THRESHOLD = 0.35;
const IF_THRESHOLD = 0.002486040118540811;
const RF_CLASSES: AttackClass[] = ["benign", "cmdi", "path_traversal", "sqli", "xss"];

const DEFAULT_TIMEOUT_MS = 50;
const DEFAULT_MODEL_DIR = path.join(__dirname, "..", "models");
const IF_POOL_SIZE = 2;
// Sized to IF's measured p95 (~3.5ms, steady-state single-request) + margin.
// Not the same as ifTimer's full fail-open timeoutMs: this is a short window
// for the common case (IF just slightly behind RF), not a failure timeout.
const IF_GRACE_MS = 5;

type CombinedResult = {
  verdict: Verdict;
  predicted_class: AttackClass;
  confidence: number;
  if_score: number;
  is_anomaly: boolean;
};

interface PendingEntry {
  resolved: boolean;
  rfProbs?: number[];
  rfDone: boolean;
  ifDispatched: boolean;
  ifScore?: number;
  ifDone: boolean;
  rfTimer: ReturnType<typeof setTimeout>;
  ifTimer: ReturnType<typeof setTimeout>;
  graceTimer?: ReturnType<typeof setTimeout>;
  resolve: (r: CombinedResult) => void;
}

let _requestId = 0;

export function logsguardian(options: MiddlewareOptions = {}): RequestHandler {
  const mode = options.mode ?? "block";
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

  const pending = new Map<number, PendingEntry>();
  let rfWorker: Worker | null = null;
  let rfReady = false;
  let ifWorkers: Worker[] = [];
  // Only workers that have signaled readiness are dispatch targets — sending real
  // requests during a worker's model-load window causes a startup burst that
  // retriggers onnxruntime-node's concurrent-call growth (see worker.ts).
  let readyIfWorkers: Worker[] = [];
  let nextIfWorkerIndex = 0;

  function applyPolicy(rfProbs: number[] | undefined, ifScore: number | undefined): CombinedResult {
    if (!rfProbs) {
      return { verdict: "timeout", predicted_class: "benign", confidence: 0, if_score: 0, is_anomaly: false };
    }

    const maxIdx = rfProbs.reduce((best, p, i) => (p > rfProbs[best] ? i : best), 0);
    const predicted_class = RF_CLASSES[maxIdx];
    const confidence = rfProbs[maxIdx];
    const is_attack = predicted_class !== "benign";
    const is_anomaly = ifScore !== undefined ? ifScore < IF_THRESHOLD : false;
    const if_score = ifScore ?? 0;
    const threshold = userThreshold ?? RF_THRESHOLD;

    let verdict: Verdict;
    if (is_attack && confidence >= threshold) {
      verdict = "block";
    } else if (is_anomaly) {
      verdict = "pass_anomaly";
    } else {
      verdict = "pass";
    }

    return { verdict, predicted_class, confidence, if_score, is_anomaly };
  }

  function finalizeRequest(id: number, entry: PendingEntry): void {
    if (entry.resolved) return;
    entry.resolved = true;
    clearTimeout(entry.rfTimer);
    clearTimeout(entry.ifTimer);
    clearTimeout(entry.graceTimer);
    pending.delete(id);
    entry.resolve(applyPolicy(entry.rfProbs, entry.ifScore));
  }

  function handleRfMessage(msg: WorkerResponse): void {
    const entry = pending.get(msg.id);
    if (!entry || entry.resolved) return;
    clearTimeout(entry.rfTimer);
    entry.rfProbs = "error" in msg || msg.role !== "rf" ? undefined : msg.rfProbs;
    entry.rfDone = true;

    if (entry.ifDone || !entry.ifDispatched) {
      // IF already answered, OR was never dispatched (no ready IF worker available) —
      // nothing to wait for either way. Don't pay the grace window for a reply that can't come.
      if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error(JSON.stringify({ id: msg.id, path: entry.ifDone ? "if-beat-rf" : "no-if-dispatched-skip-grace" }));
      finalizeRequest(msg.id, entry);
    } else {
      // Common case: RF wins the race (it's consistently faster than IF). Give IF a short,
      // bounded window to catch up before finalizing without it — not the full fail-open
      // timeoutMs, just enough to catch the normal case where IF is merely a few ms behind.
      if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error(JSON.stringify({ id: msg.id, path: "rf-first-waiting" }));
      entry.graceTimer = setTimeout(() => {
        if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error(JSON.stringify({ id: msg.id, path: "grace-timer-fired", ifDone: entry.ifDone }));
        finalizeRequest(msg.id, entry);
      }, IF_GRACE_MS);
    }
  }

  function handleIfMessage(msg: WorkerResponse): void {
    const entry = pending.get(msg.id);
    // No entry means RF already resolved (or timed out) this request — late IF
    // reply, the accepted-loss case. Discard; do not resurrect a finished request.
    if (!entry || entry.resolved) {
      if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error(JSON.stringify({ id: msg.id, path: "if-message-DISCARDED-too-late" }));
      return;
    }
    if (!("error" in msg) && msg.role === "if") {
      entry.ifScore = msg.ifScore;
    }
    entry.ifDone = true;
    clearTimeout(entry.ifTimer);

    if (entry.rfDone) {
      // RF already arrived and is sitting in its grace window — no need to wait it out.
      if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error(JSON.stringify({ id: msg.id, path: "if-caught-rf-during-grace" }));
      clearTimeout(entry.graceTimer);
      finalizeRequest(msg.id, entry);
    } else if (process.env.LOGSGUARDIAN_GRACE_DEBUG) {
      console.error(JSON.stringify({ id: msg.id, path: "if-first-waiting-for-rf" }));
    }
    // Else RF hasn't arrived yet; ifScore is now stored and RF's own handler will pick it up.
  }

  try {
    const workerPath = path.join(__dirname, "worker.js");

    rfWorker = new Worker(workerPath, { workerData: { role: "rf", modelDir } });
    rfWorker.on("message", (msg: WorkerResponse | { ready: true; role: "rf" }) => {
      if ("ready" in msg) { rfReady = true; return; }
      handleRfMessage(msg);
    });
    rfWorker.on("error", () => {
      // RF worker is dead: drain all pending with fail-open (RF is sole blocking authority).
      for (const [id, entry] of pending) {
        finalizeRequest(id, entry);
      }
      rfWorker = null;
      rfReady = false;
    });

    ifWorkers = Array.from({ length: IF_POOL_SIZE }, () => {
      const w = new Worker(workerPath, { workerData: { role: "if", modelDir } });
      w.on("message", (msg: WorkerResponse | { ready: true; role: "if" }) => {
        if ("ready" in msg) { readyIfWorkers.push(w); return; }
        handleIfMessage(msg);
      });
      w.on("error", (err) => {
        if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error("IF WORKER ERROR", err);
        // Drop this worker from rotation; in-flight IF hops routed to it simply
        // never arrive, which is the same as an IF timeout (no-op — RF doesn't wait on it).
        ifWorkers = ifWorkers.filter((x) => x !== w);
        readyIfWorkers = readyIfWorkers.filter((x) => x !== w);
      });
      return w;
    });
    if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error("ifWorkers spawned:", ifWorkers.length);
  } catch {
    // Workers failed to start (e.g., dist/worker.js not compiled yet).
    // Middleware remains in fail-open mode for all requests.
    rfWorker = null;
    rfReady = false;
    ifWorkers = [];
    readyIfWorkers = [];
  }

  function infer(canonical: import("@logsguardian/extractor").CanonicalRequest): Promise<CombinedResult> {
    return new Promise((resolve) => {
      const id = ++_requestId;

      // Fail open if RF isn't available yet — either it never started, or its model
      // is still loading. Do NOT dispatch to a not-yet-ready worker: doing so is what
      // caused the startup burst / concurrent-call growth this readiness gate exists
      // to prevent (see worker.ts and the module doc above).
      if (!rfWorker || !rfReady) {
        resolve(applyPolicy(undefined, undefined));
        return;
      }

      const entry: PendingEntry = {
        resolved: false,
        rfDone: false,
        ifDispatched: readyIfWorkers.length > 0,
        ifDone: false,
        resolve,
        // RF never replying at all is the real fail-open timeout (RF is sole blocking authority).
        rfTimer: setTimeout(() => finalizeRequest(id, entry), timeoutMs),
        // IF timeout is a no-op beyond bookkeeping: the response never waits on it directly
        // (the short IF_GRACE_MS window above, started once RF replies, handles the common case).
        ifTimer: setTimeout(() => { /* intentionally no-op — see module doc */ }, timeoutMs),
      };
      pending.set(id, entry);

      const req: WorkerRequest = { id, canonical };
      rfWorker.postMessage(req);

      if (readyIfWorkers.length > 0) {
        const ifWorker = readyIfWorkers[nextIfWorkerIndex % readyIfWorkers.length];
        nextIfWorkerIndex = (nextIfWorkerIndex + 1) % readyIfWorkers.length;
        ifWorker.postMessage(req);
        if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error(JSON.stringify({ id, path: "dispatched-to-if", poolSize: ifWorkers.length }));
      } else if (process.env.LOGSGUARDIAN_GRACE_DEBUG) {
        console.error(JSON.stringify({ id, path: "NO-IF-WORKERS-AVAILABLE" }));
      }
      // If no IF worker is available, ifScore simply never arrives — same as an IF timeout.
    });
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

    // Build CanonicalRequest — feature extraction runs inside each worker thread
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

    const result = await infer(canonical);

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
