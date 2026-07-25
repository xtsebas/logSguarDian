import { safeDecodeURIComponent } from "../src/normalizers";
import { extractFeatures, CanonicalRequest } from "../src/index";

describe("safeDecodeURIComponent", () => {
  it("percent-decodes a URL-encoded string", () => {
    expect(safeDecodeURIComponent("%3Cscript%3E")).toBe("<script>");
  });

  it("falls back to the original string on malformed escape sequences", () => {
    expect(safeDecodeURIComponent("50% off")).toBe("50% off");
  });
});

describe("computeXssFeatures via extractFeatures - percent-encoding evasion", () => {
  it("recognizes XSS markers after percent-decoding a query payload", () => {
    const req: Partial<CanonicalRequest> = {
      method: "GET",
      path: "/search",
      query: "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
      userAgent: "Mozilla/5.0",
    };
    const features = extractFeatures(req);
    expect(features.script_tag_present).toBe(1);
    expect(features.alert_function_present).toBe(1);
  });

  it("recognizes XSS markers in a body that express.urlencoded() mis-parsed into a single percent-encoded key/value pair", () => {
    // Regression: a raw HTML body like
    //   <object onfocusout=alert(1) tabindex=1 id=x></object><input autofocus>
    // sent without an explicit content-type gets parsed by express.urlencoded()
    // on the stray '=' into { "<object onfocusout": "alert(1) tabindex=1 id=x></object><input autofocus>" }.
    // middleware.ts then re-serializes that object with URLSearchParams
    // (to match how query is encoded, and to avoid JSON.stringify's {, }, :
    // punctuation false-firing on ordinary form POSTs). That percent-encodes
    // the literal <, >, (, ) characters the XSS regexes need to see.
    const req: Partial<CanonicalRequest> = {
      method: "POST",
      path: "/",
      query: "",
      body: "%3Cobject+onfocusout=alert%281%29+tabindex%3D1+id%3Dx%3E%3C%2Fobject%3E%3Cinput+autofocus%3E",
      userAgent: "Mozilla/5.0",
    };
    const features = extractFeatures(req);
    expect(features.js_event_handler_count).toBeGreaterThan(0);
    expect(features.alert_function_present).toBe(1);
    expect(features.html_tag_count).toBeGreaterThan(0);
  });

  it("does not percent-decode for non-XSS attack classes (sqli unaffected)", () => {
    const req: Partial<CanonicalRequest> = {
      method: "GET",
      path: "/products",
      // "union" itself is percent-encoded (%75 = 'u') so the raw text never
      // contains the literal word "union".
      query: "id=1%26%75nion%3Dselect+1",
      userAgent: "Mozilla/5.0",
    };
    const features = extractFeatures(req);
    // union_present must be computed on the raw (non-decoded) query — the
    // encoded "%75nion" must not be turned into "union" before SQLi matching.
    expect(features.union_present).toBe(0);
  });
});
