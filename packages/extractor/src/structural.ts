/**
 * Grupo 1 (longitudes/estructura URI) y Grupo 8 (HTTP request) del vector
 * de 73 features. Portado desde extract_features() en
 * data_manager/02_feature_engineering.ipynb (celda cd_04).
 */
import { CanonicalRequest, STANDARD_HEADERS } from "./types";
import { shannonEntropy } from "./entropy";
import { countMatches, SCANNER_UA_TEST, CONTENT_TYPE_FORM_TEST } from "./patterns";

/** Grupo 1: longitudes y estructura del payload/URI (10 features). */
export function computeLengthFeatures(
  payload: string,
  path: string,
  query: string,
  body: string,
): Record<string, number> {
  const uri = query.length > 0 ? `${path}?${query}` : path;
  const pathOnly = uri.replace(/\?.*$/, "");

  return {
    payload_length: payload.length,
    payload_entropy: shannonEntropy(payload),
    uri_length: uri.length,
    path_length: pathOnly.length,
    query_string_length: query.length,
    body_length: body.length,
    body_entropy: shannonEntropy(body),
    path_depth: countMatches(pathOnly, /\//g),
    query_param_count: countMatches(query, /&/g) + (query.length > 0 ? 1 : 0),
    fragment_present: uri.includes("#") ? 1 : 0,
  };
}

function lookupHeader(headers: Record<string, string>, name: string): string {
  return headers[name.toLowerCase()] ?? "";
}

function countUnusualHeaders(headers: Record<string, string>): number {
  let count = 0;
  for (const key of Object.keys(headers)) {
    if (!STANDARD_HEADERS.has(key.toLowerCase())) count++;
  }
  return count;
}

/** Grupo 8: metadatos de la peticion HTTP (9 features). */
export function computeHttpFeatures(req: CanonicalRequest): Record<string, number> {
  const methodUpper = req.method.toUpperCase();
  const ua = req.userAgent;
  const authorization = lookupHeader(req.extraHeaders, "authorization");

  return {
    method_is_get: methodUpper === "GET" ? 1 : 0,
    method_is_post: methodUpper === "POST" ? 1 : 0,
    ua_present: ua.length > 0 ? 1 : 0,
    ua_length: ua.length,
    ua_suspicious: ua.length > 0 && SCANNER_UA_TEST.test(ua) ? 1 : 0,
    content_type_encoded: CONTENT_TYPE_FORM_TEST.test(req.contentType) ? 1 : 0,
    authorization_length: authorization.length,
    unusual_headers_count: countUnusualHeaders(req.extraHeaders),
    status_code: req.statusCode ?? 0,
  };
}
