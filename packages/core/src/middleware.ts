/**
 * Express middleware factory (F5.3, revised for pool architecture; async
 * log-patch replacing the grace window per the F4.4-latency investigation).
 *
 * On first call, spawns a dedicated RF worker plus a small pool of IF
 * workers (round-robin dispatched), and opens the SQLite store. For
 * each request it:
 *   1. Extracts a CanonicalRequest from Express req
 *   2. Dispatches it to the RF worker AND to the next IF worker in rotation
 *   3. Resolves the INSTANT the RF hop answers — applies the decision
 *      policy (docs/decision-policy.md §3). Never waits for IF.
 *   4. In 'block' mode: sends HTTP 403 if verdict is 'block'
 *   5. Logs the event asynchronously (after next/403)
 *   6. If IF's reply arrives after the response already resolved (the
 *      common case — IF is consistently slower than RF), the log row is
 *      patched in place with IF's real score, and a 'pass' verdict flips
 *      to 'pass_anomaly' retroactively if IF found an anomaly.
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
 * log-only/diagnostic and never gates the response. An earlier design
 * (see docs/results.md, "grace window") gave IF a short bounded window to
 * catch up once RF replied, on the theory that IF is only a few ms behind
 * and folding it in matters for pass_anomaly/webhook fidelity. Measurement
 * (docs/results.md, latency investigation) found IF's own inference
 * (~0.9-1.2ms p50/p95, not IPC or extraction) IS almost the entire added
 * latency, because the grace window ends up genuinely waiting out IF's real
 * inference in ~99% of requests (IF replies just before the window expires,
 * not instead of it). Since IF never blocks anything, paying that wait on
 * every request bought nothing but log fidelity. This version removes the
 * wait entirely: RF resolves the response immediately; if IF's score
 * arrives afterward, it patches the already-logged DetectionEvent row
 * asynchronously (see `schedulePendingLogPatch` / `EventStore.patchIfScore`)
 * instead of being discarded. Diagnostic fidelity is preserved (log ends up
 * correct moments later for the vast majority of requests), latency is not
 * paid at all.
 *
 * Fail-open guarantee: if the RF worker does not respond within timeoutMs,
 * or is not available, the request is always forwarded. A logsguardian
 * failure must never become a DoS vector against the host application.
 */
import { Worker } from "worker_threads";
import * as path from "path";
import * as os from "os";
import type { Request, Response, NextFunction } from "express";
import { normalizeCanonicalRequest, extractFeatureVector } from "@logsguardian/extractor";
import { EventStore } from "./store";
import { WebhookStore } from "./webhook-store";
import { CanaryStore } from "./canary-store";
import { sendWebhook } from "./webhook";
import { sendTelemetry } from "./telemetry";
import type {
  AttackClass,
  CanaryComparison,
  DetectionEvent,
  LogsguardianHandler,
  MiddlewareOptions,
  Verdict,
  WorkerRequest,
  WorkerResponse,
} from "./types";

const RF_THRESHOLD = 0.35;
const IF_THRESHOLD = 0.002486040118540811;
const RF_CLASSES: AttackClass[] = ["benign", "cmdi", "path_traversal", "sqli", "xss"];

const DEFAULT_TIMEOUT_MS = 50;
// Fase 7: how long a canary comparison waits for its shadow reply before
// giving up, completely decoupled from the production request's own
// timeoutMs (which must stay short for real responsiveness — canary never
// blocks anything, so it can afford to be patient). A single canary worker
// has no pool the way IF does (see docs/results.md §A24's concurrent-call
// serialization finding — the same mechanism), so under a fast back-to-back
// corpus replay its queued inference calls can genuinely take tens of
// seconds; reusing the production timeoutMs (as low as the 50ms default)
// for canary's cleanup was dropping the vast majority of comparisons before
// their replies ever arrived — confirmed empirically during Fase 7's own
// verification (canary-replay.ts's Test 1).
const CANARY_CONTEXT_TIMEOUT_MS = 60_000;
const DEFAULT_MODEL_DIR = path.join(__dirname, "..", "models");
const IF_POOL_SIZE = 2;

type CombinedResult = {
  verdict: Verdict;
  predicted_class: AttackClass;
  confidence: number;
  if_score: number;
  is_anomaly: boolean;
  requestId: number;
  /** True if IF hadn't answered yet when the response resolved — a late
   *  reply for this request may still arrive and should be tracked for
   *  a log patch. Always false for the no-RF-worker early-return path. */
  ifPending: boolean;
};

/** A logged row awaiting a possible late IF patch (see schedulePendingLogPatch).
 *  cleanupTimer is independent of the request's own PendingEntry/ifTimer — this
 *  map entry is only created AFTER the entry has already been finalized and
 *  removed from `pending`, so it needs its own timeoutMs-bounded lifetime. */
interface PendingLogPatch {
  rowId: number;
  event: DetectionEvent;
  cleanupTimer: ReturnType<typeof setTimeout>;
}

/** Fase 7: the production event a late canary reply needs to compare
 * against. Parallel to PendingLogPatch, deliberately not shared with it —
 * see the pendingCanaryContext declaration for why. */
interface PendingCanaryContext {
  event: DetectionEvent;
  cleanupTimer: ReturnType<typeof setTimeout>;
}

/** Fase 7: a canary reply that arrived BEFORE trackForCanary() had a chance
 * to register the production event it needs to compare against. This is
 * the common case, not an edge case: canary is RF-shaped and comparably
 * fast, dispatched at the same instant as production RF, but
 * trackForCanary() doesn't run until well after infer() resolves (webhook
 * checks, telemetry, event construction) — there is no guarantee, unlike
 * IF's measured-slower-than-RF case, that canary is ever "late". Mirrors
 * PendingEntry's ifScore/ifDone fields, which handle the exact same
 * early-arrival case for IF beating RF — kept as its own map instead of
 * folding into PendingEntry because canary tracking must survive past
 * finalizeRequest() deleting the PendingEntry (production's response
 * doesn't wait for canary either way). */
interface EarlyCanaryReply {
  rfProbs: number[];
  cleanupTimer: ReturnType<typeof setTimeout>;
}

interface PendingEntry {
  resolved: boolean;
  rfProbs?: number[];
  rfDone: boolean;
  ifDispatched: boolean;
  ifScore?: number;
  ifDone: boolean;
  rfTimer: ReturnType<typeof setTimeout>;
  ifTimer: ReturnType<typeof setTimeout>;
  resolve: (r: CombinedResult) => void;
}

let _requestId = 0;

export function logsguardian(options: MiddlewareOptions = {}): LogsguardianHandler {
  const mode = options.mode ?? "block";
  const userThreshold = options.threshold;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const modelDir = options.modelDir ?? DEFAULT_MODEL_DIR;
  const webhookUrl = options.webhookUrl;
  const telemetryUrl = options.telemetryUrl;
  const sourceId = options.sourceId ?? os.hostname();

  let store: EventStore | null = null;
  try {
    store = new EventStore(options.dbPath);
  } catch {
    // Store failures are non-fatal; events won't be persisted.
  }

  // Same physical DB file as `store` (a separate connection, separate table) — registered
  // via `webhooks add`/`remove`/`list` (webhook-store.ts). Queried fresh per notifiable
  // event below, not cached at startup, so `webhooks add` on a running server takes effect
  // on the very next detection without a restart.
  let webhookStore: WebhookStore | null = null;
  try {
    webhookStore = new WebhookStore(options.dbPath);
  } catch {
    // Non-fatal; falls back to just the static webhookUrl, if any.
  }

  const pending = new Map<number, PendingEntry>();
  // Requests logged with ifPending=true, awaiting a possible late IF reply
  // to patch the row. Cleaned up either by a successful patch or by the
  // per-request ifTimer once timeoutMs has elapsed with no reply.
  const pendingLogPatches = new Map<number, PendingLogPatch>();
  let rfWorker: Worker | null = null;
  let rfReady = false;
  let ifWorkers: Worker[] = [];
  // Only workers that have signaled readiness are dispatch targets — sending real
  // requests during a worker's model-load window causes a startup burst that
  // retriggers onnxruntime-node's concurrent-call growth (see worker.ts).
  let readyIfWorkers: Worker[] = [];
  let nextIfWorkerIndex = 0;

  // Fase 7: canary/candidate model, on-demand only — never spawned by
  // default (see docs/results.md's real 4-worker memory measurement).
  // A completely separate tracking map from pendingLogPatches, even though
  // both exist to let a late worker reply find its request's already-sent
  // production result: IF's late-patch logic is proven, security-relevant
  // production behavior with real incident history (grace window, sync
  // double-write) — this keeps canary's parallel bookkeeping from ever
  // touching that code path, at the cost of one extra small map.
  let canaryWorker: Worker | null = null;
  let canaryReady = false;
  let canaryStore: CanaryStore | null = null;
  const pendingCanaryContext = new Map<number, PendingCanaryContext>();
  // Canary replies that arrived before trackForCanary() registered the
  // production event — see EarlyCanaryReply's doc comment for why this is
  // the common case, not an edge case.
  const earlyCanaryReplies = new Map<number, EarlyCanaryReply>();

  function applyPolicy(rfProbs: number[] | undefined, ifScore: number | undefined): Omit<CombinedResult, "requestId" | "ifPending"> {
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

  /** Attempts to patch a late IF reply into an already-logged row. No-op if the
   *  row was never registered (store disabled, verdict was 'timeout', or a
   *  patch/cleanup already consumed it). See module doc for the design. */
  function schedulePendingLogPatch(requestId: number, ifScore: number): void {
    const pending_ = pendingLogPatches.get(requestId);
    if (!pending_) return;
    clearTimeout(pending_.cleanupTimer);
    pendingLogPatches.delete(requestId);

    const is_anomaly = ifScore < IF_THRESHOLD;
    const becomesAnomaly = is_anomaly && pending_.event.verdict === "pass";
    const webhookFired = becomesAnomaly && !!webhookUrl;

    if (webhookFired) {
      sendWebhook(webhookUrl!, {
        ...pending_.event,
        if_score: ifScore,
        is_anomaly: true,
        verdict: "pass_anomaly",
        webhook_sent: true,
      });
    }

    try {
      store?.patchIfScore(pending_.rowId, ifScore, is_anomaly, webhookFired);
    } catch { /* non-fatal */ }
  }

  function finalizeRequest(id: number, entry: PendingEntry): void {
    if (entry.resolved) return;
    entry.resolved = true;
    clearTimeout(entry.rfTimer);
    clearTimeout(entry.ifTimer);
    pending.delete(id);
    const base = applyPolicy(entry.rfProbs, entry.ifScore);
    entry.resolve({ ...base, requestId: id, ifPending: !entry.ifDone });
  }

  function handleRfMessage(msg: WorkerResponse): void {
    const entry = pending.get(msg.id);
    if (!entry || entry.resolved) return;
    clearTimeout(entry.rfTimer);
    entry.rfProbs = "error" in msg || msg.role !== "rf" ? undefined : msg.rfProbs;
    entry.rfDone = true;

    // No grace window: resolve the instant RF answers. IF never blocks the
    // response (decision-policy.md §3) — if it hasn't answered yet, that's
    // fine, applyPolicy just uses whatever ifScore is present (usually none;
    // see module doc). A late IF reply patches the log asynchronously instead.
    if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error(JSON.stringify({ id: msg.id, path: "rf-resolved-immediately", ifDone: entry.ifDone }));
    finalizeRequest(msg.id, entry);
  }

  function handleIfMessage(msg: WorkerResponse): void {
    const entry = pending.get(msg.id);
    const ifScore = !("error" in msg) && msg.role === "if" ? msg.ifScore : undefined;

    // No entry means RF already resolved (or timed out) this request — the
    // common case now, since RF no longer waits. Try a log patch instead of
    // discarding.
    if (!entry || entry.resolved) {
      if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error(JSON.stringify({ id: msg.id, path: "if-late-patch-attempted" }));
      if (ifScore !== undefined) schedulePendingLogPatch(msg.id, ifScore);
      return;
    }

    // Rare: IF actually beat RF. Just record the score — RF's own handler
    // (or its fail-open timer) drives finalization, unchanged from before.
    entry.ifScore = ifScore;
    entry.ifDone = true;
    clearTimeout(entry.ifTimer);
    if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error(JSON.stringify({ id: msg.id, path: "if-beat-rf-waiting-for-rf" }));
  }

  /** Fase 7: computes and persists the comparison once both sides are known
   * — the production event (from trackForCanary) and canary's raw RF probs
   * (from whichever side of the race actually has them). Never touches the
   * response; called well after it's already gone out either way. */
  function logCanaryComparison(requestId: number, event: DetectionEvent, canaryRfProbs: number[] | undefined): void {
    const canaryPolicy = applyPolicy(canaryRfProbs, undefined);

    // 'pass' and 'pass_anomaly' are both "not blocked" (IF never has blocking
    // authority — decision-policy.md §3), and canary has no IF score of its
    // own so its verdict is always 'block' or 'pass'. Comparing raw block/
    // not-block avoids a misleading mismatch purely from the pass vs
    // pass_anomaly distinction, which says nothing about the candidate.
    const productionBlocked = event.verdict === "block";
    const canaryBlocked = canaryPolicy.verdict === "block";

    const comparison: CanaryComparison = {
      request_id: requestId,
      timestamp: event.timestamp,
      production_verdict: event.verdict,
      production_predicted_class: event.predicted_class,
      production_confidence: event.confidence,
      canary_verdict: canaryPolicy.verdict,
      canary_predicted_class: canaryPolicy.predicted_class,
      canary_confidence: canaryPolicy.confidence,
      verdict_match: productionBlocked === canaryBlocked,
      class_match: canaryPolicy.predicted_class === event.predicted_class,
      confidence_delta: Math.abs(canaryPolicy.confidence - event.confidence),
    };
    try { canaryStore?.log(comparison); } catch { /* non-fatal */ }
  }

  /** Fase 7: canary can arrive either before or after trackForCanary()
   * registers the production event (see EarlyCanaryReply's doc comment) —
   * this handles the "late" half of that race. The "early" half is handled
   * inline here too: if trackForCanary() hasn't run yet, buffer the raw
   * reply instead of dropping it. */
  function handleCanaryMessage(msg: WorkerResponse): void {
    if ("error" in msg) {
      if (process.env.LOGSGUARDIAN_GRACE_DEBUG) console.error(JSON.stringify({ id: msg.id, path: "canary-inference-error", error: msg.error }));
      return;
    }
    const canaryRfProbs = msg.role === "canary" ? msg.rfProbs : undefined;
    if (canaryRfProbs === undefined) return;

    const ctx = pendingCanaryContext.get(msg.id);
    if (ctx) {
      // Late case: production's event was already registered.
      clearTimeout(ctx.cleanupTimer);
      pendingCanaryContext.delete(msg.id);
      logCanaryComparison(msg.id, ctx.event, canaryRfProbs);
      return;
    }

    // Early case: canary beat trackForCanary() to it. Buffer the raw reply;
    // trackForCanary() will find it and log the comparison itself once the
    // production event is known. Bounded by the same timeout as the late
    // case so an early reply for a request that's later skipped (e.g. mode
    // check finds verdict === 'timeout') doesn't leak.
    const cleanupTimer = setTimeout(() => { earlyCanaryReplies.delete(msg.id); }, CANARY_CONTEXT_TIMEOUT_MS);
    earlyCanaryReplies.set(msg.id, { rfProbs: canaryRfProbs, cleanupTimer });
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

  /** Fase 7: spawns the on-demand canary worker, loading candidateModelPath
   * (an RF-shaped ONNX model, e.g. training/models/rf_candidate.onnx) via
   * worker.ts's modelFile override. Resolves once the worker signals
   * readiness — matching the same readiness-gate discipline as RF/IF (see
   * worker.ts's module doc on the cold-start burst bug this pattern
   * prevents). Rejects if the worker fails to start or load. Calling this
   * twice without closeCanaryWorker() in between leaks the previous worker;
   * callers (the corpus-replay script) are expected to spawn once per run. */
  function spawnCanaryWorker(candidateModelPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const workerPath = path.join(__dirname, "worker.js");
      const worker = new Worker(workerPath, {
        workerData: {
          role: "canary",
          modelDir: path.dirname(candidateModelPath),
          modelFile: path.basename(candidateModelPath),
        },
      });
      worker.on("message", (msg: WorkerResponse | { ready: true; role: "canary" }) => {
        if ("ready" in msg) {
          canaryReady = true;
          resolve();
          return;
        }
        handleCanaryMessage(msg);
      });
      worker.on("error", (err) => {
        canaryWorker = null;
        canaryReady = false;
        reject(err);
      });
      canaryWorker = worker;

      if (!canaryStore) {
        try { canaryStore = new CanaryStore(options.dbPath); } catch { /* non-fatal; comparisons won't persist */ }
      }
    });
  }

  /** Fase 7: tears down the canary worker and closes its store — safe to
   * call even if no canary worker was ever spawned. */
  function closeCanaryWorker(): void {
    // Same fire-and-forget rationale as close()'s worker termination.
    canaryWorker?.terminate();
    canaryWorker = null;
    canaryReady = false;
    for (const ctx of pendingCanaryContext.values()) clearTimeout(ctx.cleanupTimer);
    pendingCanaryContext.clear();
    for (const early of earlyCanaryReplies.values()) clearTimeout(early.cleanupTimer);
    earlyCanaryReplies.clear();
    canaryStore?.close();
    canaryStore = null;
  }

  function infer(canonical: import("@logsguardian/extractor").CanonicalRequest): Promise<CombinedResult> {
    return new Promise((resolve) => {
      const id = ++_requestId;

      // Fail open if RF isn't available yet — either it never started, or its model
      // is still loading. Do NOT dispatch to a not-yet-ready worker: doing so is what
      // caused the startup burst / concurrent-call growth this readiness gate exists
      // to prevent (see worker.ts and the module doc above).
      if (!rfWorker || !rfReady) {
        resolve({ ...applyPolicy(undefined, undefined), requestId: id, ifPending: false });
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
        // IF never blocks the response either way now — this timer is a no-op
        // beyond bookkeeping (entry.ifDone / clearing it in handleIfMessage's
        // "IF beat RF" branch). The separate pendingLogPatches.cleanupTimer (set
        // up later, in the middleware function, only if IF hadn't answered by
        // finalize time) is what actually bounds the late-patch map's lifetime —
        // this one can't do that job because finalizeRequest clears it immediately.
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

      // Fase 7: same fire-and-forget fan-out as IF — dispatched only when a
      // canary worker is active (the common case is no canary at all, in
      // which case this is a no-op). Never affects rfTimer/finalizeRequest.
      if (canaryWorker && canaryReady) {
        canaryWorker.postMessage(req);
      }
      // If no IF worker is available, ifScore simply never arrives — same as an IF timeout.
    });
  }

  const logsguardianMiddleware = async function logsguardianMiddleware(
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

    const isNotifiable = result.verdict === "block" || result.verdict === "pass_anomaly";
    const registeredWebhooks = isNotifiable
      ? (webhookStore?.list() ?? []).filter((w) => w.status === "active")
      : [];
    const needsWebhook = isNotifiable && (!!webhookUrl || registeredWebhooks.length > 0);
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

    if (needsWebhook) {
      if (webhookUrl) sendWebhook(webhookUrl, event);
      for (const w of registeredWebhooks) sendWebhook(w.url, event);
    }

    // Opt-in MLOps telemetry: fire-and-forget POST of the feature vector only,
    // never the raw payload. Sent for every request (not just notifiable ones)
    // so the collector sees a representative traffic sample, not just attacks.
    if (telemetryUrl) {
      sendTelemetry(telemetryUrl, {
        vector: extractFeatureVector(canonical),
        predicted_class: result.predicted_class,
        confidence: result.confidence,
        timestamp: t0,
        source_id: sourceId,
      });
    }

    // Track this row for a possible late IF patch — only when IF hadn't answered
    // yet (ifPending) and the verdict came from a real RF reply. 'timeout' rows
    // (RF itself failed) never get IF's score patched in, unchanged from before
    // this design: IF has no standing to override a fail-open decision.
    const trackForLatePatch = (rowId: number | undefined): void => {
      if (rowId !== undefined && result.ifPending && result.verdict !== "timeout") {
        const requestId = result.requestId;
        const cleanupTimer = setTimeout(() => { pendingLogPatches.delete(requestId); }, timeoutMs);
        pendingLogPatches.set(requestId, { rowId, event, cleanupTimer });
      }
    };

    // Fase 7: canary is comparably fast to production RF, so its reply can
    // easily arrive before this runs (id=1 hit this on the very first
    // request during Fase 7's own verification — not a rare edge case).
    // Check for an already-buffered early reply first; only fall back to
    // registering pendingCanaryContext (the "wait for a late reply" case)
    // if canary hasn't answered yet. Skipped for 'timeout' rows for the
    // same reason IF's patch is: a fail-open decision isn't a real
    // production verdict to hold a candidate model accountable to.
    const trackForCanary = (): void => {
      if (!canaryWorker || !canaryReady || result.verdict === "timeout") return;
      const requestId = result.requestId;

      const early = earlyCanaryReplies.get(requestId);
      if (early) {
        clearTimeout(early.cleanupTimer);
        earlyCanaryReplies.delete(requestId);
        logCanaryComparison(requestId, event, early.rfProbs);
        return;
      }

      const cleanupTimer = setTimeout(() => { pendingCanaryContext.delete(requestId); }, CANARY_CONTEXT_TIMEOUT_MS);
      pendingCanaryContext.set(requestId, { event, cleanupTimer });
    };

    if (mode === "block" && result.verdict === "block") {
      try { trackForLatePatch(store?.log(event)); } catch { /* non-fatal */ }
      trackForCanary();
      res.status(403).json({ error: "Forbidden", class: result.predicted_class });
      return;
    }

    next();
    try { trackForLatePatch(store?.log(event)); } catch { /* non-fatal */ }
    trackForCanary();
  };

  // Graceful shutdown: terminates the worker pool this call spawned. Not
  // needed by most consumers (workers are unref'd-equivalent from the
  // process's perspective — they don't block normal exit), but real apps
  // doing a clean SIGTERM shutdown, and tests that call logsguardian()
  // directly and need to release the real worker_threads it spawns (rather
  // than leaving them running until the process itself exits), need a way
  // to reach them — nothing else exposes these closed-over references.
  (logsguardianMiddleware as LogsguardianHandler).close = (): void => {
    // Deliberately fire-and-forget, not awaited: onnxruntime-node's native
    // addon has a known teardown race (the same "libc++abi ... Napi::Error"
    // crash seen elsewhere in this project under --forceExit) that measurably
    // triggers MORE often when terminate() is awaited (tested empirically —
    // awaiting each worker's actual thread-exit confirmation, one at a time,
    // gave the crash more chances to fire than just calling terminate() and
    // moving on). Not fully understood why; not worth digging further into
    // onnxruntime-node's native internals for a test-cleanup path.
    rfWorker?.terminate();
    for (const w of ifWorkers) w.terminate();
    store?.close();
    webhookStore?.close();
    closeCanaryWorker();
  };

  (logsguardianMiddleware as LogsguardianHandler).spawnCanaryWorker = spawnCanaryWorker;
  (logsguardianMiddleware as LogsguardianHandler).closeCanaryWorker = closeCanaryWorker;

  return logsguardianMiddleware as LogsguardianHandler;
}
