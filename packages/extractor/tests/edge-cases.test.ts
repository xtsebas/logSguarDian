import { extractFeatureVector, FEATURE_NAMES } from '../src/index';

describe("extractFeatureVector - Edge Cases", () => {
    test("payload vacío: devuelve vector de 73 números sin tirar", () => {
    const vec = extractFeatureVector({ method: "GET", path: "/", query: "", body: "" });
    expect(vec).toHaveLength(73);
    expect(vec.every(v => Number.isFinite(v))).toBe(true);
  });

  test("headers malformados (undefined, string vacío): no tira", () => {
    const vec = extractFeatureVector({
      method: "POST",
      path: "/api",
      query: "",
      body: "",
      userAgent: "",          
      contentType: "",
      cookie: "\x00\xFF",     // bytes no-ASCII
      referer: "not a url",
    });
    expect(vec).toHaveLength(73);
    expect(vec.every(v => Number.isFinite(v))).toBe(true);
  });

  test("URI muy largo (>2000 chars): uri_length y entropía no explotan", () => {
    const longPath = "/" + "a".repeat(2000);
    const vec = extractFeatureVector({ method: "GET", path: longPath, query: "", body: "" });
    expect(vec).toHaveLength(73);
    expect(vec.every(v => Number.isFinite(v))).toBe(true);
    // uri_length debe reflejar el tamaño real
    const idx = FEATURE_NAMES.indexOf("uri_length");
    expect(vec[idx]).toBeGreaterThan(2000);
  });

  test("query string con payload SQLi: no tira y devuelve vector válido", () => {
    const vec = extractFeatureVector({
      method: "GET",
      path: "/products",
      query: "id=1' OR '1'='1' UNION SELECT username,password FROM users--",
      body: "",
    });
    expect(vec).toHaveLength(73);
    expect(vec.every(v => Number.isFinite(v))).toBe(true);
  });
});