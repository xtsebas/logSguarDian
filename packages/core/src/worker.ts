/**
 * ONNX inference worker thread (F5.2, revised for pool architecture).
 *
 * Each worker is dedicated to exactly one model, selected by workerData.role
 * ('rf' | 'if'). The middleware spawns one RF worker and a small pool of IF
 * workers (round-robin dispatched) instead of a single worker running both
 * models — RF and IF calls into onnxruntime-node's native addon serialize
 * under concurrent load (confirmed process/thread-scoped, not per-session:
 * pooling multiple sessions inside one thread doesn't help, separate
 * worker_threads do). See docs/results.md for the concurrency investigation.
 *
 * Feature reduction (v8+): RF and IF use different slices of the same
 * 73-feature vector.
 *   - RF gets 67 features: the 73-feature vector from @logsguardian/extractor
 *     minus the 6 runtime-behavioral features (status_code, req_count_*,
 *     error_rate_4xx_60s, endpoint_diversity_60s), unavailable at request
 *     interception time.
 *   - IF gets 61 features: RF's 67 minus 6 further features confirmed to
 *     have zero/near-zero variance on benign traffic (dotdot_encoded_count,
 *     authorization_length, unusual_headers_count, null_byte_count,
 *     os_path_indicator, sensitive_file_target) — dead weight for anomaly
 *     detection, dropped to stabilize IsolationForest's run-to-run variance.
 * Both reductions are by feature name, not index. See docs/decision-policy.md §4.
 *
 * Feature extraction runs redundantly in each worker (both RF and IF workers
 * extract the full 73-dim vector independently from the same canonical
 * request) rather than extracting once and shipping the vector across an
 * extra hop — extraction costs ~0.04ms, negligible next to the concurrency
 * problem this architecture fixes, and it keeps the message contract simple.
 *
 * LOGSGUARDIAN_GRACE_DEBUG (env var, both this file and middleware.ts): kept
 * intentionally as permanent diagnostic tooling, not leftover debug cruft —
 * a no-op check when unset. Logs per-call queue_wait_ms separately from
 * inference_ms; this exact separation is what distinguished the cold-start
 * burst bug (session.run() itself growing unbounded, queue wait flat) from
 * a message-queueing artifact during the investigation, and is worth having
 * available for any future regression. See docs/results.md §A24.
 */
import { parentPort, workerData } from "worker_threads";
import * as ort from "onnxruntime-node";
import * as path from "path";
import { FEATURE_NAMES, extractFeatureVector } from "@logsguardian/extractor";
import type { WorkerRequest, WorkerResponse, WorkerRole } from "./types";

const RF_OUTPUT_IDX: number = 1;
const IF_OUTPUT_IDX: number = 1;

const EXCLUDED_NAMES = new Set([
  "status_code",
  "req_count_1s",
  "req_count_5s",
  "req_count_60s",
  "error_rate_4xx_60s",
  "endpoint_diversity_60s",
]);

const IF_ADDITIONAL_EXCLUDED = new Set([
  "dotdot_encoded_count",
  "authorization_length",
  "unusual_headers_count",
  "null_byte_count",
  "os_path_indicator",
  "sensitive_file_target",
]);

/** Positions in FEATURE_NAMES that rf.onnx expects (0-based, length=67). */
const RF_MODEL_INDICES: number[] = FEATURE_NAMES
  .map((name, i) => ({ name, i }))
  .filter(({ name }) => !EXCLUDED_NAMES.has(name))
  .map(({ i }) => i);

/** Positions in FEATURE_NAMES that if.onnx expects (0-based, length=61). */
const IF_MODEL_INDICES: number[] = FEATURE_NAMES
  .map((name, i) => ({ name, i }))
  .filter(({ name }) => !EXCLUDED_NAMES.has(name) && !IF_ADDITIONAL_EXCLUDED.has(name))
  .map(({ i }) => i);

if (RF_MODEL_INDICES.length !== 67) {
  throw new Error(`Expected 67 RF model feature indices, got ${RF_MODEL_INDICES.length}`);
}
if (IF_MODEL_INDICES.length !== 61) {
  throw new Error(`Expected 61 IF model feature indices, got ${IF_MODEL_INDICES.length}`);
}

const { role, modelDir } = workerData as { role: WorkerRole; modelDir: string };

async function loadSession(): Promise<ort.InferenceSession> {
  const modelFile = role === "rf" ? "rf.onnx" : "if.onnx";
  return ort.InferenceSession.create(path.join(modelDir, modelFile));
}

const sessionPromise = loadSession();

// Signal readiness once the session has fully loaded. The middleware withholds
// dispatch to this worker until it receives this — sending real requests during
// the (multi-second, for IF) model-load window causes many message handlers to
// pile up awaiting the same sessionPromise, then burst-call session.run()
// concurrently the instant it resolves, retriggering onnxruntime-node's
// confirmed concurrent-call serialization/growth behavior. See docs/results.md.
sessionPromise.then(() => {
  parentPort!.postMessage({ ready: true, role });
}).catch(() => { /* load error already surfaced per-message below; never becomes ready */ });

const DEBUG = !!process.env.LOGSGUARDIAN_GRACE_DEBUG;
let sessionReadyAt: bigint | undefined;
if (DEBUG) {
  const spawnedAt = process.hrtime.bigint();
  sessionPromise.then(() => {
    sessionReadyAt = process.hrtime.bigint();
    console.error(JSON.stringify({
      role,
      event: "session-ready",
      load_ms: Number(sessionReadyAt - spawnedAt) / 1e6,
    }));
  }).catch(() => { /* load error already handled below */ });
}

parentPort!.on("message", async (msg: WorkerRequest) => {
  const tStart = DEBUG ? process.hrtime.bigint() : undefined;
  let session: ort.InferenceSession;
  try {
    session = await sessionPromise;
  } catch (err) {
    const reply: WorkerResponse = { id: msg.id, role, error: `Model load failed: ${String(err)}` };
    parentPort!.postMessage(reply);
    return;
  }

  try {
    const vector73 = extractFeatureVector(msg.canonical);
    const tRunStart = DEBUG ? process.hrtime.bigint() : undefined;

    if (role === "rf") {
      const rfInput = Float32Array.from(RF_MODEL_INDICES.map((i) => vector73[i]));
      const rfTensor = new ort.Tensor("float32", rfInput, [1, 67]);
      const rfResult = await session.run({ float_input: rfTensor });
      const rfProbs = Array.from(
        rfResult[session.outputNames[RF_OUTPUT_IDX]].data as Float32Array
      );
      if (DEBUG) {
        const tEnd = process.hrtime.bigint();
        console.error(JSON.stringify({
          role, id: msg.id,
          queue_wait_ms: Number(tRunStart! - tStart!) / 1e6,
          inference_ms: Number(tEnd - tRunStart!) / 1e6,
          since_session_ready_ms: sessionReadyAt ? Number(tEnd - sessionReadyAt) / 1e6 : undefined,
        }));
      }
      const reply: WorkerResponse = { id: msg.id, role: "rf", rfProbs };
      parentPort!.postMessage(reply);
    } else {
      const ifInput = Float32Array.from(IF_MODEL_INDICES.map((i) => vector73[i]));
      const ifTensor = new ort.Tensor("float32", ifInput, [1, 61]);
      const ifResult = await session.run({ float_input: ifTensor });
      const ifScore = (
        ifResult[session.outputNames[IF_OUTPUT_IDX]].data as Float32Array
      )[0];
      if (DEBUG) {
        const tEnd = process.hrtime.bigint();
        console.error(JSON.stringify({
          role, id: msg.id,
          queue_wait_ms: Number(tRunStart! - tStart!) / 1e6,
          inference_ms: Number(tEnd - tRunStart!) / 1e6,
          since_session_ready_ms: sessionReadyAt ? Number(tEnd - sessionReadyAt) / 1e6 : undefined,
        }));
      }
      const reply: WorkerResponse = { id: msg.id, role: "if", ifScore };
      parentPort!.postMessage(reply);
    }
  } catch (err) {
    const reply: WorkerResponse = { id: msg.id, role, error: String(err) };
    parentPort!.postMessage(reply);
  }
});
