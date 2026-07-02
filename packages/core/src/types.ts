export type AttackClass = "benign" | "cmdi" | "path_traversal" | "sqli" | "xss";
export type Verdict = "block" | "pass" | "pass_anomaly" | "timeout";
export type Mode = "block" | "monitor";
export type ModelSelection = "rf" | "if" | "hybrid";

export interface MiddlewareOptions {
  /** 'block' sends HTTP 403 on detected attacks. 'monitor' logs only. Default: 'block'. */
  mode?: Mode;
  /** RF detection confidence threshold (0–1). Requests with confidence >= threshold are blocked. Default: 0.70. */
  threshold?: number;
  /** Which model(s) to use for inference. Default: 'hybrid' (RF + IF). */
  model?: ModelSelection;
  /** Fail-open timeout in ms. If the worker doesn't respond, the request is passed. Default: 50. */
  timeoutMs?: number;
  /** Absolute path to the SQLite event log. Default: logsguardian.db in cwd. */
  dbPath?: string;
  /** Absolute path to the directory containing rf.onnx, if.onnx, model-metadata.json. */
  modelDir?: string;
}

/** Single detection event written to the SQLite log. */
export interface DetectionEvent {
  timestamp: number;
  method: string;
  path: string;
  verdict: Verdict;
  predicted_class: AttackClass;
  confidence: number;
  if_score: number;
  elapsed_ms: number;
}

/** Message sent from middleware to worker. */
export interface WorkerRequest {
  id: number;
  vector: number[];
}

/** Message sent from worker to middleware. */
export interface WorkerResponse {
  id: number;
  rfProbs?: number[];
  ifScore?: number;
  error?: string;
}
