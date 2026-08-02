export type AttackClass = "benign" | "cmdi" | "path_traversal" | "sqli" | "xss";
export type Verdict = "block" | "pass" | "pass_anomaly" | "timeout";
export type Mode = "block" | "monitor";
export type ModelSelection = "rf" | "if" | "hybrid";

export interface MiddlewareOptions {
  /** 'block' sends HTTP 403 on detected attacks. 'monitor' logs only. Default: 'block'. */
  mode?: Mode;
  /** Optional RF confidence threshold (0–1) overriding the calibrated per-class defaults for ALL classes. Default: unset (per-class thresholds apply). */
  threshold?: number;
  /** Which model(s) to use for inference. Default: 'hybrid' (RF + IF). */
  model?: ModelSelection;
  /** Fail-open timeout in ms. If the worker doesn't respond, the request is passed. Default: 50. */
  timeoutMs?: number;
  /** Absolute path to the SQLite event log. Default: logsguardian.db in cwd. */
  dbPath?: string;
  /** Absolute path to the directory containing rf.onnx, if.onnx, model-metadata.json. */
  modelDir?: string;
  /** HTTP(S) URL to POST a JSON DetectionEvent when verdict is 'block' or 'pass_anomaly'. */
  webhookUrl?: string;
}

/** Single detection event written to the SQLite log. */
export interface DetectionEvent {
  timestamp: number;
  method: string;
  path: string;
  query_string: string;
  user_agent: string;
  client_ip: string;
  verdict: Verdict;
  predicted_class: AttackClass;
  confidence: number;
  if_score: number;
  is_anomaly: boolean;
  webhook_sent: boolean;
  elapsed_ms: number;
}

/** Message sent from middleware to worker. */
export interface WorkerRequest {
  id: number;
  /** Raw normalised request — feature extraction runs inside the worker thread. */
  canonical: import("@logsguardian/extractor").CanonicalRequest;
}

/** Which model a worker in the pool is dedicated to. */
export type WorkerRole = "rf" | "if";

/** Message sent from worker to middleware. Always tagged with the sender's role. */
export type WorkerResponse =
  | { id: number; role: "rf"; rfProbs: number[] }
  | { id: number; role: "if"; ifScore: number }
  | { id: number; role: WorkerRole; error: string };
