/**
 * Grupo 2 (composicion de caracteres) y Grupo 3 (encoding) del vector de
 * 73 features. Portado desde extract_features() en
 * data_manager/02_feature_engineering.ipynb (celda cd_04).
 */
import { extendedAsciiRatio } from "./entropy";
import {
  countMatches,
  SPECIAL_CHAR_COUNT,
  NUMERIC_CHAR_COUNT,
  UPPERCASE_CHAR_COUNT,
  WHITESPACE_COUNT,
  NEWLINE_CHAR_COUNT,
  NEWLINE_ENCODED_COUNT,
  NULL_BYTE_COUNT,
  NULL_BYTE_ENCODED_COUNT,
  URL_ENCODED_COUNT,
  DOUBLE_ENCODED_COUNT,
  HEX_ESCAPE_COUNT,
  UNICODE_ESCAPE_COUNT,
  HTML_ENTITY_COUNT,
  BASE64_LIKE_COUNT,
} from "./patterns";

/** Conteo de tokens separados por espacios en blanco (como str.split() de Python). */
export function tokenCount(s: string): number {
  const trimmed = s.trim();
  if (trimmed.length === 0) return 0;
  return trimmed.split(/\s+/).length;
}

/** Grupo 2: composicion de caracteres del payload (8 features). */
export function computeCompositionFeatures(payload: string): Record<string, number> {
  const pl = Math.max(payload.length, 1);

  return {
    special_char_ratio: countMatches(payload, SPECIAL_CHAR_COUNT) / pl,
    numeric_char_ratio: countMatches(payload, NUMERIC_CHAR_COUNT) / pl,
    uppercase_ratio: countMatches(payload, UPPERCASE_CHAR_COUNT) / pl,
    whitespace_count: countMatches(payload, WHITESPACE_COUNT),
    newline_char_count:
      countMatches(payload, NEWLINE_CHAR_COUNT) + countMatches(payload, NEWLINE_ENCODED_COUNT),
    null_byte_count:
      countMatches(payload, NULL_BYTE_COUNT) + countMatches(payload, NULL_BYTE_ENCODED_COUNT),
    extended_ascii_ratio: extendedAsciiRatio(payload),
    payload_token_count: tokenCount(payload),
  };
}

/** Grupo 3: indicadores de encoding/ofuscacion (7 features). */
export function computeEncodingFeatures(payload: string): Record<string, number> {
  const pl = Math.max(payload.length, 1);
  const urlEncodedCount = countMatches(payload, URL_ENCODED_COUNT);

  return {
    url_encoded_ratio: urlEncodedCount / pl,
    encoded_char_freq: urlEncodedCount,
    double_encoded_count: countMatches(payload, DOUBLE_ENCODED_COUNT),
    hex_escape_count: countMatches(payload, HEX_ESCAPE_COUNT),
    unicode_escape_count: countMatches(payload, UNICODE_ESCAPE_COUNT),
    html_entity_count: countMatches(payload, HTML_ENTITY_COUNT),
    base64_like_count: countMatches(payload, BASE64_LIKE_COUNT),
  };
}
