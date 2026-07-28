/**
 * ONNX inference worker thread (F5.2).
 *
 * Loaded once per middleware instance via worker_threads. Keeps RF and IF
 * sessions alive for the process lifetime. Receives WorkerRequest messages
 * from the parent, runs inference, and replies with WorkerResponse messages.
 *
 * Feature reduction: the 73-feature vector from @logsguardian/extractor is
 * reduced to 66 by dropping the 6 runtime-behavioral features plus
 * non_form_operator_count (not yet in rf_v7/if_v6, added ahead of the v8
 * retrain — see semantic.ts) by name (not by index) before passing to the
 * ONNX models. See docs/decision-policy.md §4.
 */
import { parentPort, workerData } from "worker_threads";
import * as ort from "onnxruntime-node";
import * as path from "path";
import { FEATURE_NAMES, extractFeatureVector } from "@logsguardian/extractor";
import type { WorkerRequest, WorkerResponse } from "./types";

const RF_OUTPUT_IDX: number = 1;
const IF_OUTPUT_IDX: number = 1;

const EXCLUDED_NAMES = new Set([
  "status_code",
  "req_count_1s",
  "req_count_5s",
  "req_count_60s",
  "error_rate_4xx_60s",
  "endpoint_diversity_60s",
  // Not yet trained into rf_v7/if_v6 — exclude until the v8 retrain picks it up.
  "non_form_operator_count",
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

const modelDir: string = (workerData as { modelDir: string }).modelDir;

async function loadSessions(): Promise<{
  rfSession: ort.InferenceSession;
  ifSession: ort.InferenceSession;
}> {
  const [rfSession, ifSession] = await Promise.all([
    ort.InferenceSession.create(path.join(modelDir, "rf.onnx")),
    ort.InferenceSession.create(path.join(modelDir, "if.onnx")),
  ]);
  return { rfSession, ifSession };
}

const sessionsPromise = loadSessions();

parentPort!.on("message", async (msg: WorkerRequest) => {
  let sessions: { rfSession: ort.InferenceSession; ifSession: ort.InferenceSession };
  try {
    sessions = await sessionsPromise;
  } catch (err) {
    const reply: WorkerResponse = { id: msg.id, error: `Model load failed: ${String(err)}` };
    parentPort!.postMessage(reply);
    return;
  }

  try {
    const { rfSession, ifSession } = sessions;
    const vector73 = extractFeatureVector(msg.canonical);
    const rfInput = Float32Array.from(RF_MODEL_INDICES.map((i) => vector73[i]));
    const ifInput = Float32Array.from(IF_MODEL_INDICES.map((i) => vector73[i]));
    const rfTensor = new ort.Tensor("float32", rfInput, [1, 67]);
    const ifTensor = new ort.Tensor("float32", ifInput, [1, 61]);

    const [rfResult, ifResult] = await Promise.all([
      rfSession.run({ float_input: rfTensor }),
      ifSession.run({ float_input: ifTensor }),
    ]);

    const rfProbs = Array.from(
      rfResult[rfSession.outputNames[RF_OUTPUT_IDX]].data as Float32Array
    );
    const ifScore = (
      ifResult[ifSession.outputNames[IF_OUTPUT_IDX]].data as Float32Array
    )[0];

    const reply: WorkerResponse = { id: msg.id, rfProbs, ifScore };
    parentPort!.postMessage(reply);
  } catch (err) {
    const reply: WorkerResponse = { id: msg.id, error: String(err) };
    parentPort!.postMessage(reply);
  }
});
