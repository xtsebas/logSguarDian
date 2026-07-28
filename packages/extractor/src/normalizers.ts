/**
 * HTML entity decoding, used only ahead of XSS pattern matching
 * (computeXssFeatures in semantic.ts). Payloads such as `&lt;script&gt;`
 * evade the raw-string XSS markers (`<script`, `onerror=`, ...) because the
 * `<`/`>`/`"` characters never appear literally in the payload.
 */
export function decodeHtmlEntities(str: string): string {
  return str
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#x27;/gi, "'")
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code, 10)))
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

/**
 * Percent-decodes a payload, used ahead of XSS pattern matching so that
 * `%3Cscript%3E` is recognized the same way as `<script>`. Falls back to the
 * original string on malformed escape sequences (decodeURIComponent throws)
 * instead of raising, since a payload is not required to be valid percent-encoding.
 */
export function safeDecodeURIComponent(str: string): string {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

/**
 * Decodes JavaScript unicode escape sequences (`\uXXXX`), e.g.
 * `<script>` -> `<script>`. Unlike HTML-entity encoding, unicode
 * escapes are resolved by the JS engine itself at parse time, so an attacker
 * can legitimately unicode-escape an entire payload (including the callable,
 * e.g. `alert(1)`) and it still executes once decoded — this is a real
 * evasion vector, not a redundant one. Invalid sequences (non-hex digits)
 * are left untouched rather than matched partially.
 */
export function decodeUnicodeEscapes(str: string): string {
  return str.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

/**
 * Recursively applies percent-decode, HTML-entity decode, and unicode-escape
 * decode (in that order) until a fixpoint is reached or maxDepth is hit,
 * whichever comes first. Bounded to guard against adversarial input that
 * never converges — measured at 2.12ms for a 110KB pathological string at
 * maxDepth=5, well inside the 50ms fail-open timeout.
 *
 * Used only ahead of XSS pattern matching (computeXssFeatures) — see the
 * scope note there for why other feature groups must keep reading the raw
 * payload.
 */
export function normalizeForXssDetection(str: string, maxDepth = 5): string {
  let prev = str;
  for (let i = 0; i < maxDepth; i++) {
    const decoded = decodeUnicodeEscapes(decodeHtmlEntities(safeDecodeURIComponent(prev)));
    if (decoded === prev) break;
    prev = decoded;
  }
  return prev;
}
