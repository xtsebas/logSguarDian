/**
 * body-parser.ts
 *
 * When a request body is application/x-www-form-urlencoded with multiple
 * fields, analyzes each field value separately and returns the value with
 * the highest attack signal.
 *
 * This prevents "multi-field dilution": an attack payload in one field
 * (e.g. content=<script>...) being diluted by benign fields
 * (e.g. title=Normal+Post&) in density-based features.
 *
 * Approach B: decode each field value, return the decoded value that
 * produces the highest attack score. This matches the training corpus
 * shape (raw HTML/SQL/shell payloads, no key name, no encoding).
 */
import { scoreAttackSignal } from "./attack-signal-score";

/**
 * Parse urlencoded body into field key-value pairs.
 * Returns null if body is not multi-field urlencoded (single field, no
 * '=' at all, or a raw payload that happens to contain a stray '=' but
 * no '&' — those still parse to exactly one pair and are left as-is so
 * the whole-body path, which already percent-decodes for XSS, handles them).
 */
export function parseUrlencodedFields(body: string): Map<string, string> | null {
  if (!body || !body.includes("=")) return null;

  try {
    const params = new URLSearchParams(body);
    const fields = new Map<string, string>();
    params.forEach((value, key) => {
      fields.set(key, value); // URLSearchParams auto-decodes
    });
    return fields.size > 1 ? fields : null;
  } catch {
    return null;
  }
}

/**
 * Given a multi-field urlencoded body, return the decoded field value
 * with the highest combined attack signal. Falls back to the whole body
 * if the body is not multi-field urlencoded.
 */
export function extractBestPayload(body: string): string {
  const fields = parseUrlencodedFields(body);

  // Single field or not urlencoded: use whole body as before.
  if (!fields) return body;

  // Fallback stays the whole body unless some field actually scores > 0.
  // (Previously started at -1, so when every field legitimately scored 0 —
  // the ordinary case for benign multi-field forms like login or new-post —
  // the first field in iteration order won by default. A bare few-character
  // field value (e.g. a username) then stood in for the entire request in
  // every downstream feature, which the model reads as attack-shaped.)
  let bestValue = body;
  let bestScore = 0;

  for (const [, value] of fields) {
    if (!value || value.length < 2) continue;

    // Score this field value using count-based features (not density),
    // since counts are invariant to how long the surrounding string is —
    // density would just reintroduce the dilution problem within a single
    // field's scoring. Shared with deriveRawPayload (index.ts) so both
    // call sites use the exact same formula — see attack-signal-score.ts.
    const score = scoreAttackSignal(value);

    if (score > bestScore) {
      bestScore = score;
      bestValue = value;
    }
  }

  return bestValue;
}
