import { decodeHtmlEntities } from "../src/normalizers";
import { extractFeatures, CanonicalRequest } from "../src/index";

describe("decodeHtmlEntities", () => {
  it("decodes HTML-entity-encoded markup back to raw characters", () => {
    const input = "&lt;script&gt;alert(1)&lt;/script&gt;";
    expect(decodeHtmlEntities(input)).toBe("<script>alert(1)</script>");
  });

  it("decodes numeric and hex character references", () => {
    expect(decodeHtmlEntities("&#60;script&#62;")).toBe("<script>");
    expect(decodeHtmlEntities("&#x3c;script&#x3e;")).toBe("<script>");
  });
});

describe("computeXssFeatures via extractFeatures - HTML entity evasion", () => {
  const entityEncodedXss: Partial<CanonicalRequest> = {
    method: "GET",
    path: "/search",
    query: "q=&lt;script&gt;alert(1)&lt;/script&gt;",
    userAgent: "Mozilla/5.0",
  };

  it("recognizes XSS markers after decoding HTML entities", () => {
    const features = extractFeatures(entityEncodedXss);
    expect(features.xss_marker_density).toBeGreaterThan(0);
    expect(features.script_tag_present).toBe(1);
    expect(features.alert_function_present).toBe(1);
  });

  it("still flags the raw entity encoding via html_entity_density", () => {
    const features = extractFeatures(entityEncodedXss);
    expect(features.html_entity_density).toBeGreaterThan(0);
  });

  it("does not decode entities for non-XSS attack classes (sqli unaffected)", () => {
    const sqliWithAmpEntity: Partial<CanonicalRequest> = {
      method: "GET",
      path: "/products",
      query: "id=1&amp;union=select+1",
      userAgent: "Mozilla/5.0",
    };
    const features = extractFeatures(sqliWithAmpEntity);
    // sqli_keyword_count must be computed on the raw (non-decoded) query —
    // "&amp;" must not be turned into "&" before SQLi pattern matching.
    expect(features.union_present).toBe(1);
    expect(features.sqli_keyword_count).toBeGreaterThan(0);
  });
});
