/**
 * ONNX inference worker thread (F5.2).
 *
 * Loaded once per middleware instance via worker_threads. Keeps RF and IF
 * sessions alive for the process lifetime. Receives WorkerRequest messages
 * from the parent, runs inference, and replies with WorkerResponse messages.
 *
 * Feature reduction: the 72-feature vector from @logsguardian/extractor is
 * reduced to 66 by dropping the 6 excluded features by name (not by index)
 * before passing to the ONNX models. See docs/decision-policy.md §4.
 */
import { parentPort, workerData } from "worker_threads";
import * as ort from "onnxruntime-node";
import * as path from "path";
import { FEATURE_NAMES } from "@logsguardian/extractor";
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
]);

/** Positions in FEATURE_NAMES that the model actually expects (0-based, length=66). */
const MODEL_INDICES: number[] = FEATURE_NAMES
  .map((name, i) => ({ name, i }))
  .filter(({ name }) => !EXCLUDED_NAMES.has(name))
  .map(({ i }) => i);

if (MODEL_INDICES.length !== 66) {
  throw new Error(`Expected 66 model feature indices, got ${MODEL_INDICES.length}`);
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
    const input66 = Float32Array.from(MODEL_INDICES.map((i) => msg.vector[i]));
    const tensor = new ort.Tensor("float32", input66, [1, 66]);

    const [rfResult, ifResult] = await Promise.all([
      rfSession.run({ float_input: tensor }),
      ifSession.run({ float_input: tensor }),
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
