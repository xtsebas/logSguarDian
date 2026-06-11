/**
 * Extractor canonico de 72 features para deteccion de SQLi, XSS,
 * Path Traversal y Command Injection.
 *
 * Puerto fiel de extract_features() en
 * data_manager/02_feature_engineering.ipynb (celdas cd_01/cd_03/cd_04).
 * Este es el UNICO lugar donde se calculan las 72 features (R1 del plan
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

export * from "./types";

/** Orden canonico de las 72 columnas (debe coincidir con FEATURE_COLS de cd_01). */
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
  // Grupo 4: SQLi (9)
  "sqli_keyword_count", "sqli_keyword_density", "sqli_comment_count",
  "sqli_operator_count", "quote_count", "semicolon_count", "parenthesis_count",
  "union_present", "select_present",
  // Grupo 5: XSS (9)
  "xss_marker_count", "xss_marker_density", "html_tag_count",
  "script_tag_present", "js_event_handler_count", "javascript_url_count",
  "html_entity_density", "alert_function_present", "inline_style_present",
  // Grupo 6: Path Traversal (7)
  "traversal_sequence_count", "path_separator_count", "absolute_path_indicator",
  "sensitive_file_target", "sensitive_extension_count", "file_extension_suspicious",
  "dotdot_encoded_count",
  // Grupo 7: Command Injection (8)
  "pipe_count", "backtick_count", "shell_command_count",
  "command_separator_count", "redirect_operator_count",
  "dollar_sign_count", "subshell_count", "os_path_indicator",
  // Grupo 8: HTTP request (9)
  "method_is_get", "method_is_post", "ua_present", "ua_length",
  "ua_suspicious", "content_type_encoded", "authorization_length",
  "unusual_headers_count", "status_code",
  // Grupo 9: temporal (5) - siempre 0, requiere estado entre requests
  "req_count_1s", "req_count_5s", "req_count_60s",
  "error_rate_4xx_60s", "endpoint_diversity_60s",
];

if (FEATURE_NAMES.length !== 72) {
  throw new Error(`FEATURE_NAMES debe tener 72 elementos, tiene ${FEATURE_NAMES.length}`);
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
 * longitudes especificas de uri/query/body). Prioridad documentada en
 * CANONICAL_REQUEST_NOTES.md seccion 6: body > query > path.
 */
export function deriveRawPayload(req: CanonicalRequest): string {
  if (req.body.length > 0) return req.body;
  if (req.query.length > 0) return req.query;
  return req.path;
}

/**
 * Extrae las 72 features de una peticion HTTP canonica.
 * Acepta un CanonicalRequest parcial; los campos ausentes se normalizan
 * a sus valores por defecto.
 */
export function extractFeatures(req: Partial<CanonicalRequest>): Record<string, number> {
  const canonical = normalizeCanonicalRequest(req);
  const rawPayload = deriveRawPayload(canonical);

  const computed: Record<string, number> = {
    ...computeLengthFeatures(rawPayload, canonical.path, canonical.query, canonical.body),
    ...computeCompositionFeatures(rawPayload),
    ...computeEncodingFeatures(rawPayload),
    ...computeSqliFeatures(rawPayload),
    ...computeXssFeatures(rawPayload),
    ...computePathTraversalFeatures(rawPayload),
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
