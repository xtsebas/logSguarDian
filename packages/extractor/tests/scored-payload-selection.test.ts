import { extractFeatureVector, FEATURE_NAMES, CanonicalRequest } from "../src/index";

function buildRequest(opts: { query: string; path: string; body: string }): Partial<CanonicalRequest> {
  return {
    method: "GET",
    path: opts.path,
    query: opts.query,
    body: opts.body,
    userAgent: "Mozilla/5.0",
    contentType: opts.body ? "application/x-www-form-urlencoded" : "",
  };
}

const SQLI_KEYWORD_IDX = FEATURE_NAMES.indexOf("sqli_keyword_count");
const XSS_MARKER_IDX = FEATURE_NAMES.indexOf("xss_marker_count");
const ABSOLUTE_PATH_IDX = FEATURE_NAMES.indexOf("absolute_path_indicator");
const TRAVERSAL_IDX = FEATURE_NAMES.indexOf("traversal_sequence_count");

describe("deriveRawPayload — score-based field selection", () => {
  test("capec-style bug case: attack in path, benign query no longer wins", () => {
    const req = buildRequest({
      query: "ver=4.9.5",
      path: "/wp-content/plugins/x/'or(select*from(select(sleep(5)))a)--",
      body: "",
    });
    const vec = extractFeatureVector(req);
    expect(vec[SQLI_KEYWORD_IDX]).toBeGreaterThan(0);
  });

  test("xss in query still wins when path is benign", () => {
    const req = buildRequest({
      query: "<script>alert(1)</script>",
      path: "/search",
      body: "",
    });
    const vec = extractFeatureVector(req);
    expect(vec[XSS_MARKER_IDX]).toBeGreaterThan(0);
  });

  test("nav-only login unaffected (query and body empty)", () => {
    const req = buildRequest({ query: "", path: "/login", body: "" });
    const vec = extractFeatureVector(req);
    expect(vec[ABSOLUTE_PATH_IDX]).toBe(0);
  });

  test("path traversal in query still detected", () => {
    const req = buildRequest({
      query: "../../../etc/passwd",
      path: "/download",
      body: "",
    });
    const vec = extractFeatureVector(req);
    expect(vec[TRAVERSAL_IDX]).toBeGreaterThan(0);
  });

  test("percent-encoded attack in path (real flagship bug case) still wins over benign query", () => {
    // ver=4.9.5 attached to a WordPress-style asset URL, with the real
    // attack (PHP object injection via chr()) hidden behind percent
    // encoding in path — the case that surfaced this whole bug during
    // the MinHash near-dup investigation. sqli_operator_count and
    // sqli_keyword_count don't reflect raw percent-encoded text, so this
    // specifically tests decode-aware scoring (scoreAttackSignalWithDecoding).
    const req = buildRequest({
      query: "ver=4.9.5",
      path:
        "/%22%3Bprint%28chr%28122%29.chr%2897%29.chr%28112%29.chr%2895%29" +
        ".chr%28116%29.chr%28111%29.chr%28107%29.chr%28101%29.chr%28110%29" +
        "%29%3B%24var%3D%22/wp-content/themes/twentyseventeen/style.css",
      body: "",
    });
    const vec = extractFeatureVector(req);
    const lengthIdx = FEATURE_NAMES.indexOf("payload_length");
    // query alone is 9 chars ("ver=4.9.5") — anything longer confirms path won.
    expect(vec[lengthIdx]).toBeGreaterThan(9);
  });

  test("tie (both score 0) falls back to priority order — query over path", () => {
    const req = buildRequest({ query: "page=2", path: "/posts", body: "" });
    const vec = extractFeatureVector(req);
    // query_string_length reflects the winning candidate's length via
    // the query field directly, but the reliable signal is that no
    // path-specific artifact (absolute_path_indicator) leaks in from
    // a path that lost the tie-break.
    expect(vec[ABSOLUTE_PATH_IDX]).toBe(0);
  });
});
