import { parseUrlencodedFields, extractBestPayload } from "../src/body-parser";
import { extractFeatures, CanonicalRequest } from "../src/index";

describe("parseUrlencodedFields / extractBestPayload", () => {
  it("returns null (whole-body fallback) for a single-field body", () => {
    const body = "bio=%3Cscript%3Ealert(1)%3C%2Fscript%3E";
    expect(parseUrlencodedFields(body)).toBeNull();
    expect(extractBestPayload(body)).toBe(body);
  });

  it("isolates the highest-signal field's decoded value from a multi-field body", () => {
    const body = "title=Normal+Post&content=%3Cscript%3Efetch(document.cookie)%3C%2Fscript%3E";
    expect(extractBestPayload(body)).toBe("<script>fetch(document.cookie)</script>");
  });

  it("finds a SQLi payload isolated in the username field", () => {
    const body = "username=%27%20OR%20%271%27%3D%271%27--&password=anything";
    expect(extractBestPayload(body)).toBe("' OR '1'='1'--");
  });

  it("falls back to the first field when all fields score 0 (all benign)", () => {
    const body = "title=Hello+World&content=Normal+content";
    expect(extractBestPayload(body)).toBe("Hello World");
  });
});

describe("computeXssFeatures via extractFeatures - multi-field dilution fix", () => {
  it("produces a higher xss_marker_density for per-field extraction than the whole-string baseline", () => {
    const req: Partial<CanonicalRequest> = {
      method: "POST",
      path: "/posts",
      query: "",
      body: "title=Normal+Post&content=%3Cscript%3Efetch(document.cookie)%3C%2Fscript%3E",
    };
    const features = extractFeatures(req);
    // Whole-string baseline (measured before this fix) was 4.6154.
    expect(features.xss_marker_density).toBeGreaterThan(4.6154);
  });
});

describe("nav path fallback preserved", () => {
  it("absolute_path_indicator is still 0 for GET /login with empty body and query", () => {
    const req: Partial<CanonicalRequest> = { method: "GET", path: "/login", query: "", body: "" };
    expect(extractFeatures(req).absolute_path_indicator).toBe(0);
  });
});
