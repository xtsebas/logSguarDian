import { extractFeatureVector, FEATURE_NAMES, CanonicalRequest } from "../src/index";

function extractFeatureVectorFromPayload(body: string): number[] {
  const req: Partial<CanonicalRequest> = {
    method: "POST",
    path: "/test",
    body,
    contentType: "application/x-www-form-urlencoded",
    userAgent: "Mozilla/5.0",
  };
  return extractFeatureVector(req);
}

const XSS_MARKER_IDX = FEATURE_NAMES.indexOf("xss_marker_count");
const HTML_ENTITY_DENSITY_IDX = FEATURE_NAMES.indexOf("html_entity_density");

describe("recursive XSS decode (normalizeForXssDetection)", () => {
  test("double HTML-entity encoded XSS is detected", () => {
    const payload = "&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;";
    const vec = extractFeatureVectorFromPayload(payload);
    expect(vec[XSS_MARKER_IDX]).toBeGreaterThan(0);
  });

  test("double percent-encoded XSS is detected", () => {
    const payload = encodeURIComponent(encodeURIComponent("<script>alert(1)</script>"));
    const vec = extractFeatureVectorFromPayload(payload);
    expect(vec[XSS_MARKER_IDX]).toBeGreaterThan(0);
  });

  test("unicode-escaped XSS is detected", () => {
    const payload = "<script>alert(1)</script>"
      .split("")
      .map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"))
      .join("");
    const vec = extractFeatureVectorFromPayload(payload);
    expect(vec[XSS_MARKER_IDX]).toBeGreaterThan(0);
  });

  test("html_entity_density still measures raw encoding presence", () => {
    const payload = "&lt;script&gt;";
    const vec = extractFeatureVectorFromPayload(payload);
    expect(vec[HTML_ENTITY_DENSITY_IDX]).toBeGreaterThan(0);
  });

  test("recursive decode is bounded — pathological input stays fast", () => {
    const pathological = "%2525".repeat(2000);
    const start = Date.now();
    extractFeatureVectorFromPayload(pathological);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(50);
  });
});
