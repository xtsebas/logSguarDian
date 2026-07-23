export type AttackClass = "benign" | "cmdi" | "path_traversal" | "sqli" | "xss";
export type Verdict = "block" | "pass" | "pass_anomaly" | "timeout";
export type Mode = "block" | "monitor";
export type ModelSelection = "rf" | "if" | "hybrid";

export interface MiddlewareOptions {
  /** 'block' sends HTTP 403 on detected attacks. 'monitor' logs only. Default: 'block'. */
  mode?: Mode;
  /** RF detection confidence threshold (0–1). Requests with confidence >= threshold are blocked. Default: 0.35. */
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

/** Message sent from worker to middleware. */
export interface WorkerResponse {
  id: number;
  rfProbs?: number[];
  ifScore?: number;
  error?: string;
}
