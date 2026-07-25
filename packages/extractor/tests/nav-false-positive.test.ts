import { extractFeatures, CanonicalRequest } from "../src/index";

describe("absolute_path_indicator - path fallback false positives", () => {
  it("does not fire for GET /login with empty query and body", () => {
    const req: Partial<CanonicalRequest> = { method: "GET", path: "/login", query: "", body: "" };
    expect(extractFeatures(req).absolute_path_indicator).toBe(0);
  });

  it("does not fire for GET /posts/5 with empty query and body", () => {
    const req: Partial<CanonicalRequest> = { method: "GET", path: "/posts/5", query: "", body: "" };
    expect(extractFeatures(req).absolute_path_indicator).toBe(0);
  });

  it("does not fire for GET /admin with empty query and body", () => {
    const req: Partial<CanonicalRequest> = { method: "GET", path: "/admin", query: "", body: "" };
    expect(extractFeatures(req).absolute_path_indicator).toBe(0);
  });

  it("still fires for a traversal payload in the query string", () => {
    const req: Partial<CanonicalRequest> = {
      method: "GET",
      path: "/posts/1/attachment",
      query: "file=../../../etc/passwd",
      body: "",
    };
    const features = extractFeatures(req);
    expect(features.absolute_path_indicator).toBe(0);
    expect(features.traversal_sequence_count).toBeGreaterThan(0);
  });

  it("does not fire for a POST login form with no traversal in body", () => {
    const req: Partial<CanonicalRequest> = {
      method: "POST",
      path: "/login",
      query: "",
      body: "username=alice&password=",
    };
    expect(extractFeatures(req).absolute_path_indicator).toBe(0);
  });

  it("does not fire for a query value without a leading slash, but still flags dotdot traversal", () => {
    const req: Partial<CanonicalRequest> = {
      method: "GET",
      path: "/x",
      query: "q=../../../../etc/passwd",
      body: "",
    };
    const features = extractFeatures(req);
    expect(features.absolute_path_indicator).toBe(0);
    expect(features.traversal_sequence_count).toBeGreaterThan(0);
  });
});
