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
