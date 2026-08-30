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

const NON_FORM_IDX = FEATURE_NAMES.indexOf("non_form_operator_count");
const OPERATOR_IDX = FEATURE_NAMES.indexOf("sqli_operator_count");

describe("non_form_operator_count", () => {
  test("legit multi-field form scores non_form_operator_count=0", () => {
    const vec = extractFeatureVectorFromPayload("title=Hello&content=Just a normal note");
    expect(vec[NON_FORM_IDX]).toBe(0);
  });

  test("legit login form scores non_form_operator_count=0", () => {
    const vec = extractFeatureVectorFromPayload("username=alice&password=alice123");
    expect(vec[NON_FORM_IDX]).toBe(0);
  });

  test("SQLi embedded in a field scores non_form_operator_count>0", () => {
    const vec = extractFeatureVectorFromPayload("username=' OR 1=1--&password=x");
    expect(vec[NON_FORM_IDX]).toBeGreaterThan(0);
  });

  test("classic SQLi (no form syntax) scores non_form_operator_count>0", () => {
    const vec = extractFeatureVectorFromPayload("' OR 1=1 --");
    expect(vec[NON_FORM_IDX]).toBeGreaterThan(0);
  });

  test("sqli_operator_count is unchanged (not replaced)", () => {
    const vec = extractFeatureVectorFromPayload("' OR 1=1 --");
    expect(vec[OPERATOR_IDX]).toBe(1);
  });
});
