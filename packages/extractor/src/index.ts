/**
 * Extractor canonico de 75 features para deteccion de SQLi, XSS,
 * Path Traversal y Command Injection.
 *
 * Puerto fiel de extract_features() en
 * data_manager/02_feature_engineering.ipynb (celdas cd_01/cd_03/cd_04),
 * mas non_form_operator_count, distinct_shell_command_count y
 * shell_to_path_ratio (3 features adicionales, no presentes en el notebook
 * original — ver packages/extractor/src/semantic.ts).
 * Este es el UNICO lugar donde se calculan las features (R1 del plan
 * de ejecucion): tanto los datasets de entrenamiento (via CLI) como el
 * middleware Express en runtime deben usar esta implementacion.
 */
import { CanonicalRequest, normalizeCanonicalRequest } from "./types";
import { computeLengthFeatures, computeHttpFeatures } from "./structural";
import { computeCompositionFeatures, computeEncodingFeatures } from "./encoding";
import {
  computeSqliFeatures,
  computeXssFeatures,
  computePathTraversalFeatures,
  computeCommandInjectionFeatures,
} from "./semantic";
import { extractBestPayload } from "./body-parser";
import { scoreAttackSignalWithDecoding } from "./attack-signal-score";

export * from "./types";

/** Orden canonico de las 75 columnas (72 de FEATURE_COLS de cd_01 + non_form_operator_count, distinct_shell_command_count, shell_to_path_ratio). */
export const FEATURE_NAMES: readonly string[] = [
  // Grupo 1: longitudes (10)
  "payload_length", "payload_entropy", "uri_length", "path_length",
  "query_string_length", "body_length", "body_entropy",
  "path_depth", "query_param_count", "fragment_present",
  // Grupo 2: composicion de caracteres (8)
  "special_char_ratio", "numeric_char_ratio", "uppercase_ratio",
  "whitespace_count", "newline_char_count", "null_byte_count",
  "extended_ascii_ratio", "payload_token_count",
  // Grupo 3: encoding (7)
  "url_encoded_ratio", "encoded_char_freq", "double_encoded_count",
  "hex_escape_count", "unicode_escape_count", "html_entity_count", "base64_like_count",
  // Grupo 4: SQLi (10)
  "sqli_keyword_count", "sqli_keyword_density", "sqli_comment_count",
  "sqli_operator_count", "non_form_operator_count", "quote_count",
  "semicolon_count", "parenthesis_count", "union_present", "select_present",
  // Grupo 5: XSS (9)
  "xss_marker_count", "xss_marker_density", "html_tag_count",
  "script_tag_present", "js_event_handler_count", "javascript_url_count",
  "html_entity_density", "alert_function_present", "inline_style_present",
  // Grupo 6: Path Traversal (7)
  "traversal_sequence_count", "path_separator_count", "absolute_path_indicator",
  "sensitive_file_target", "sensitive_extension_count", "file_extension_suspicious",
  "dotdot_encoded_count",
  // Grupo 7: Command Injection (10)
  "pipe_count", "backtick_count", "shell_command_count",
  "command_separator_count", "redirect_operator_count",
  "dollar_sign_count", "subshell_count", "os_path_indicator",
  "distinct_shell_command_count", "shell_to_path_ratio",
  // Grupo 8: HTTP request (9)
  "method_is_get", "method_is_post", "ua_present", "ua_length",
  "ua_suspicious", "content_type_encoded", "authorization_length",
  "unusual_headers_count", "status_code",
  // Grupo 9: temporal (5) - siempre 0, requiere estado entre requests
  "req_count_1s", "req_count_5s", "req_count_60s",
  "error_rate_4xx_60s", "endpoint_diversity_60s",
];

if (FEATURE_NAMES.length !== 75) {
  throw new Error(`FEATURE_NAMES debe tener 75 elementos, tiene ${FEATURE_NAMES.length}`);
}

/** Grupo 9: features temporales, requieren estado de sesion no disponible aqui. */
const TEMPORAL_FEATURES: Record<string, number> = {
  req_count_1s: 0,
  req_count_5s: 0,
  req_count_60s: 0,
  error_rate_4xx_60s: 0,
  endpoint_diversity_60s: 0,
};

/**
 * rawPayload: el campo sobre el que operan los grupos 1-7 (excepto las
 * longitudes especificas de uri/query/body). Diseno documentado en
 * CANONICAL_REQUEST_NOTES.md seccion 5 (Gap 1): "rawPayload = the
 * highest-signal text field available."
 *
 * When the body is a multi-field urlencoded form, an attack payload in
 * one field gets diluted by benign fields when the whole body string is
 * scored as one blob (density-style features shrink as the string grows).
 * extractBestPayload() isolates the decoded field value with the
 * strongest attack signal instead of the raw key=value&key=value string —
 * this matches the shape of the training corpus, which is raw attack
 * payloads (no key name, no encoding), not urlencoded form bodies.
 *
 * body/query/path candidates are then scored with the same
 * scoreAttackSignal() formula and the highest-signal one wins — a fixed
 * body > query > path priority previously discarded path's attack signal
 * whenever query was merely non-empty (e.g. a WordPress-style
 * `?ver=4.9.5` attached to a genuinely malicious path), a real
 * detection-bypass bug affecting both training data and live requests.
 * Ties (including the common all-zero-score benign case) resolve to the
 * original body > query > path order — score-based selection only
 * overrides priority when a candidate STRICTLY outscores the others,
 * so the fix cannot silently discard the highest-signal candidate the
 * way the earlier form-field tie-break bug did.
 */
export function deriveRawPayload(req: CanonicalRequest): string {
  const bodyPayload = req.body.length > 0 ? extractBestPayload(req.body) : "";

  const candidates: string[] = [];
  if (bodyPayload.length > 0) candidates.push(bodyPayload);
  if (req.query.length > 0) candidates.push(req.query);
  if (req.path.length > 1) candidates.push(req.path);

  if (candidates.length === 0) return req.path;
  if (candidates.length === 1) return candidates[0];

  let best = candidates[0];
  let bestScore = scoreAttackSignalWithDecoding(candidates[0]);
  for (let i = 1; i < candidates.length; i++) {
    const score = scoreAttackSignalWithDecoding(candidates[i]);
    if (score > bestScore) {
      bestScore = score;
      best = candidates[i];
    }
  }
  return best;
}

/**
 * Extrae las 73 features de una peticion HTTP canonica.
 * Acepta un CanonicalRequest parcial; los campos ausentes se normalizan
 * a sus valores por defecto.
 */
export function extractFeatures(req: Partial<CanonicalRequest>): Record<string, number> {
  const canonical = normalizeCanonicalRequest(req);
  const rawPayload = deriveRawPayload(canonical);

  // When rawPayload falls back to the path (no query/body), the leading
  // "/" mandated by HTTP is meaningless as a path-traversal signal — every
  // normal navigation request would otherwise trip absolute_path_indicator.
  const isPathFallback =
    rawPayload === canonical.path && canonical.body.length === 0 && canonical.query.length === 0;
  const pathTraversalPayload = isPathFallback ? rawPayload.replace(/^\//, "") : rawPayload;

  const computed: Record<string, number> = {
    ...computeLengthFeatures(rawPayload, canonical.path, canonical.query, canonical.body),
    ...computeCompositionFeatures(rawPayload),
    ...computeEncodingFeatures(rawPayload),
    ...computeSqliFeatures(rawPayload),
    ...computeXssFeatures(rawPayload),
    ...computePathTraversalFeatures(pathTraversalPayload),
    ...computeCommandInjectionFeatures(rawPayload),
    ...computeHttpFeatures(canonical),
    ...TEMPORAL_FEATURES,
  };

  const ordered: Record<string, number> = {};
  for (const name of FEATURE_NAMES) {
    ordered[name] = computed[name];
  }
  return ordered;
}

/** Igual que extractFeatures(), pero como vector ordenado (para CSV/parquet/ONNX). */
export function extractFeatureVector(req: Partial<CanonicalRequest>): number[] {
  const features = extractFeatures(req);
  return FEATURE_NAMES.map((name) => features[name]);
}
