import { parseUrlencodedFields, extractBestPayload } from "../src/body-parser";
import { extractFeatures, extractFeatureVector, FEATURE_NAMES, CanonicalRequest } from "../src/index";

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

  it("falls back to the whole body when all fields score 0 (all benign) — not the first field", () => {
    // Regression: bestScore previously started at -1, so a field scoring
    // exactly 0 still "won" the comparison and the first field evaluated
    // was returned. That reduced ordinary benign forms (login, new post) to
    // a bare few-character field value, which then scored as sqli for
    // being an unusually short, isolated token with no surrounding
    // structure. bestScore now starts at 0, so nothing beats a genuine 0.
    const body = "title=Hello+World&content=Normal+content";
    expect(extractBestPayload(body)).toBe(body);
  });
});

describe("extractBestPayload tie-break fix — whole-body fallback for benign multi-field forms", () => {
  it("uses the whole body (not the first field) for a legit login", () => {
    const req: Partial<CanonicalRequest> = {
      method: "POST",
      path: "/login",
      query: "",
      body: "username=alice&password=alice123",
    };
    const vec = extractFeatureVector(req);
    const plIdx = FEATURE_NAMES.indexOf("payload_length");
    expect(vec[plIdx]).toBe(req.body!.length);
  });

  it("uses the whole body (not the first field) for a legit post", () => {
    const req: Partial<CanonicalRequest> = {
      method: "POST",
      path: "/posts",
      query: "",
      body: "title=Hello&content=Just a normal note",
    };
    const vec = extractFeatureVector(req);
    const plIdx = FEATURE_NAMES.indexOf("payload_length");
    expect(vec[plIdx]).toBe(req.body!.length);
  });

  it("still isolates the field when one of them DOES carry attack signal", () => {
    const req: Partial<CanonicalRequest> = {
      method: "POST",
      path: "/posts",
      query: "",
      body: "title=Normal+Post&content=<script>alert(1)</script>",
    };
    const vec = extractFeatureVector(req);
    const xssIdx = FEATURE_NAMES.indexOf("xss_marker_count");
    expect(vec[xssIdx]).toBeGreaterThan(0);
    const plIdx = FEATURE_NAMES.indexOf("payload_length");
    expect(vec[plIdx]).toBeLessThan(req.body!.length);
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
