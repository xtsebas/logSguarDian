/**
 * Grupos 4-7 (SQLi, XSS, Path Traversal, Command Injection) del vector de
 * 72 features. Portado desde extract_features() en
 * data_manager/02_feature_engineering.ipynb (celda cd_04).
 */
import { tokenCount } from "./encoding";
import { decodeHtmlEntities, safeDecodeURIComponent } from "./normalizers";
import {
  countMatches,
  SQL_KEYWORDS_COUNT,
  SQLI_COMMENT_COUNT,
  SQLI_OPERATOR_COUNT,
  UNION_PRESENT_TEST,
  SELECT_PRESENT_TEST,
  XSS_MARKER_COUNT,
  HTML_TAG_COUNT,
  SCRIPT_TAG_TEST,
  JS_EVENT_HANDLER_COUNT,
  JAVASCRIPT_URL_COUNT,
  HTML_ENTITY_COUNT,
  ALERT_FUNCTION_TEST,
  INLINE_STYLE_TEST,
  TRAVERSAL_SEQUENCE_COUNT,
  PATH_SEPARATOR_COUNT,
  ABSOLUTE_PATH_TEST,
  SENSITIVE_FILE_TEST,
  SENSITIVE_EXTENSION_COUNT,
  SUSPICIOUS_EXTENSION_COUNT,
  DOTDOT_ENCODED_COUNT,
  SHELL_COMMAND_COUNT,
  COMMAND_SEPARATOR_COUNT,
  REDIRECT_OPERATOR_COUNT,
  SUBSHELL_COUNT,
  OS_PATH_INDICATOR_TEST,
} from "./patterns";

/** Grupo 4: marcadores de SQL Injection (9 features). */
export function computeSqliFeatures(payload: string): Record<string, number> {
  const tokens = Math.max(tokenCount(payload), 1);
  const sqliKeywordCount = countMatches(payload, SQL_KEYWORDS_COUNT);

  return {
    sqli_keyword_count: sqliKeywordCount,
    sqli_keyword_density: sqliKeywordCount / tokens,
    sqli_comment_count: countMatches(payload, SQLI_COMMENT_COUNT),
    sqli_operator_count: countMatches(payload, SQLI_OPERATOR_COUNT),
    quote_count: countMatches(payload, /['"]/g),
    semicolon_count: countMatches(payload, /;/g),
    parenthesis_count: countMatches(payload, /[()]/g),
    union_present: UNION_PRESENT_TEST.test(payload) ? 1 : 0,
    select_present: SELECT_PRESENT_TEST.test(payload) ? 1 : 0,
  };
}

/**
 * Grupo 5: marcadores de Cross-Site Scripting (9 features).
 *
 * Percent-decoding then HTML-entity decoding is applied before matching so
 * that payloads like `%3Cscript%3E` or `&lt;script&gt;` are recognized the
 * same way as `<script>`. This decoding is XSS-specific: SQLi/path-traversal/
 * cmdi features keep reading the raw payload, since decoding has no bearing
 * on those attack classes and could introduce false signals there.
 *
 * `html_entity_density` is the one exception — it measures the presence of
 * *encoded* entities in the raw payload as an obfuscation signal, so it must
 * stay computed on the original (undecoded) string.
 */
export function computeXssFeatures(payload: string): Record<string, number> {
  const decoded = decodeHtmlEntities(safeDecodeURIComponent(payload));
  const pl = Math.max(decoded.length, 1);
  const xssMarkerCount = countMatches(decoded, XSS_MARKER_COUNT);

  return {
    xss_marker_count: xssMarkerCount,
    xss_marker_density: (xssMarkerCount / pl) * 100,
    html_tag_count: countMatches(decoded, HTML_TAG_COUNT),
    script_tag_present: SCRIPT_TAG_TEST.test(decoded) ? 1 : 0,
    js_event_handler_count: countMatches(decoded, JS_EVENT_HANDLER_COUNT),
    javascript_url_count: countMatches(decoded, JAVASCRIPT_URL_COUNT),
    html_entity_density: (countMatches(payload, HTML_ENTITY_COUNT) / Math.max(payload.length, 1)) * 100,
    alert_function_present: ALERT_FUNCTION_TEST.test(decoded) ? 1 : 0,
    inline_style_present: INLINE_STYLE_TEST.test(decoded) ? 1 : 0,
  };
}

/** Grupo 6: marcadores de Path Traversal / LFI (7 features). */
export function computePathTraversalFeatures(payload: string): Record<string, number> {
  return {
    traversal_sequence_count: countMatches(payload, TRAVERSAL_SEQUENCE_COUNT),
    path_separator_count: countMatches(payload, PATH_SEPARATOR_COUNT),
    absolute_path_indicator: ABSOLUTE_PATH_TEST.test(payload) ? 1 : 0,
    sensitive_file_target: SENSITIVE_FILE_TEST.test(payload) ? 1 : 0,
    sensitive_extension_count: countMatches(payload, SENSITIVE_EXTENSION_COUNT),
    file_extension_suspicious: countMatches(payload, SUSPICIOUS_EXTENSION_COUNT),
    dotdot_encoded_count: countMatches(payload, DOTDOT_ENCODED_COUNT),
  };
}

/** Grupo 7: marcadores de Command Injection (8 features). */
export function computeCommandInjectionFeatures(payload: string): Record<string, number> {
  return {
    pipe_count: countMatches(payload, /\|/g),
    backtick_count: countMatches(payload, /`/g),
    shell_command_count: countMatches(payload, SHELL_COMMAND_COUNT),
    command_separator_count: countMatches(payload, COMMAND_SEPARATOR_COUNT),
    redirect_operator_count: countMatches(payload, REDIRECT_OPERATOR_COUNT),
    dollar_sign_count: countMatches(payload, /\$/g),
    subshell_count: countMatches(payload, SUBSHELL_COUNT),
    os_path_indicator: OS_PATH_INDICATOR_TEST.test(payload) ? 1 : 0,
  };
}
