/**
 * CanonicalRequest — esquema unificado al que convergen tanto los datasets
 * de entrenamiento como el objeto `req` de Express en runtime.
 *
 * Ver .claude/CANONICAL_REQUEST_NOTES.md seccion 6 para el diseno completo.
 *
 * rawPayload NO se almacena: se deriva en extractFeatures() como
 *   body || query || path
 * para evitar que datasets y produccion calculen esa derivacion de formas
 * distintas (R1 del plan de ejecucion).
 */
export interface CanonicalRequest {
  /** Verbo HTTP en mayusculas (GET, POST, ...). Default: "" */
  method: string;
  /** Path de la URL, decodificado. Default: "" */
  path: string;
  /** Query string sin el "?" inicial. Default: "" */
  query: string;
  /** Cuerpo de la peticion como string UTF-8. Default: "" */
  body: string;
  /** Header User-Agent. Default: "" */
  userAgent: string;
  /** Header Content-Type. Default: "" */
  contentType: string;
  /** Header Referer. Default: "" */
  referer: string;
  /** Header Cookie. Default: "" */
  cookie: string;
  /** Resto de headers (clave en minusculas -> valor). Default: {} */
  extraHeaders: Record<string, string>;
  /**
   * Codigo de estado de la respuesta. Solo disponible para datasets de
   * entrenamiento construidos a partir de logs (OWASP, RussellMitchell,
   * data_capec). En runtime (middleware) siempre es 0 porque la respuesta
   * aun no existe al momento de la inspeccion (Gap 3 de
   * CANONICAL_REQUEST_NOTES.md). Default: 0
   */
  statusCode?: number;
}

/** Headers HTTP estandar excluidos del conteo de unusual_headers_count. */
export const STANDARD_HEADERS = new Set([
  "host", "user-agent", "accept", "content-type", "content-length",
  "authorization", "cookie", "referer", "connection", "accept-encoding",
  "accept-language", "cache-control",
]);

/**
 * Completa los campos ausentes de un CanonicalRequest parcial con sus
 * valores por defecto. Usado por los adaptadores de dataset y por el
 * middleware Express para normalizar entradas incompletas.
 */
export function normalizeCanonicalRequest(
  req: Partial<CanonicalRequest>,
): CanonicalRequest {
  return {
    method: req.method ?? "",
    path: req.path ?? "",
    query: req.query ?? "",
    body: req.body ?? "",
    userAgent: req.userAgent ?? "",
    contentType: req.contentType ?? "",
    referer: req.referer ?? "",
    cookie: req.cookie ?? "",
    extraHeaders: req.extraHeaders ?? {},
    statusCode: req.statusCode ?? 0,
  };
}
