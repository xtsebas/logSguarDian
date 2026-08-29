/**
 * Payload validation for POST /telemetry (Fase 1 of the CT/CI/CD pipeline).
 *
 * Rejects malformed payloads before they reach TelemetryStore: wrong vector
 * length/type, out-of-range confidence, unknown predicted_class, etc.
 */
import { FEATURE_NAMES } from "@logsguardian/extractor";

const VALID_CLASSES = new Set(["benign", "cmdi", "path_traversal", "sqli", "xss"]);
const MAX_SOURCE_ID_LENGTH = 128;

export interface TelemetryPayload {
  vector: number[];
  predicted_class: string;
  confidence: number;
  timestamp: number;
  source_id: string;
}

export type ValidationResult =
  | { valid: true; payload: TelemetryPayload }
  | { valid: false; error: string };

export function validateTelemetryPayload(body: unknown): ValidationResult {
  if (typeof body !== "object" || body === null) {
    return { valid: false, error: "body must be a JSON object" };
  }
  const b = body as Record<string, unknown>;

  if (!Array.isArray(b.vector) || b.vector.length !== FEATURE_NAMES.length) {
    return { valid: false, error: `vector must be an array of ${FEATURE_NAMES.length} numbers` };
  }
  if (!b.vector.every((n) => typeof n === "number" && Number.isFinite(n))) {
    return { valid: false, error: "vector must contain only finite numbers" };
  }

  if (typeof b.predicted_class !== "string" || !VALID_CLASSES.has(b.predicted_class)) {
    return { valid: false, error: `predicted_class must be one of ${[...VALID_CLASSES].join(", ")}` };
  }

  if (typeof b.confidence !== "number" || !Number.isFinite(b.confidence) || b.confidence < 0 || b.confidence > 1) {
    return { valid: false, error: "confidence must be a number in [0, 1]" };
  }

  if (typeof b.timestamp !== "number" || !Number.isFinite(b.timestamp) || b.timestamp <= 0) {
    return { valid: false, error: "timestamp must be a positive number" };
  }

  if (typeof b.source_id !== "string" || b.source_id.length === 0 || b.source_id.length > MAX_SOURCE_ID_LENGTH) {
    return { valid: false, error: `source_id must be a non-empty string up to ${MAX_SOURCE_ID_LENGTH} characters` };
  }

  return {
    valid: true,
    payload: {
      vector: b.vector as number[],
      predicted_class: b.predicted_class,
      confidence: b.confidence,
      timestamp: b.timestamp,
      source_id: b.source_id,
    },
  };
}
