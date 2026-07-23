import * as fs from "fs";
import * as path from "path";
import request from "supertest";
import { createTestApp } from "./test-app";

const FIXTURES_PATH = path.join(__dirname, "fixtures/test_payloads.jsonl");
const DETECTION_THRESHOLD = 0.8; // OBJ. 3 criterion
const FP_THRESHOLD = 0.2;
const ATTACK_CLASSES = ["sqli", "xss", "path_traversal", "cmdi"];

interface FixtureRecord {
  method: string;
  path: string;
  query: string;
  body: string | null;
  userAgent: string;
  contentType: string;
  referer: string;
  cookie: string;
  extraHeaders: Record<string, string>;
  _expected_class: string;
}

function loadFixtures(): FixtureRecord[] {
  return fs
    .readFileSync(FIXTURES_PATH, "utf-8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

async function sendPayload(
  app: import("express").Express,
  rec: FixtureRecord
): Promise<{ status: number; blocked: boolean }> {
  const hasBody = typeof rec.body === "string" && rec.body.length > 0;
  const rawMethod = (rec.method || (hasBody ? "POST" : "GET")).toLowerCase();
  const SUPPORTED_METHODS = ["get", "post", "put", "delete", "patch"] as const;
  const method = (SUPPORTED_METHODS as readonly string[]).includes(rawMethod)
    ? (rawMethod as (typeof SUPPORTED_METHODS)[number])
    : "get";
  // Some dataset records store the raw payload directly in `path` without a
  // leading slash (e.g. a bare "<script>..." string) rather than a real URL
  // path, which produces an invalid request URL if sent as-is.
  const urlPath = rec.path ? (rec.path.startsWith("/") ? rec.path : `/${rec.path}`) : "/";
  const fullPath = rec.query ? `${urlPath}?${rec.query}` : urlPath;

  const buildRequest = (target: string) => {
    let req = request(app)[method](target);
    if (rec.userAgent) req = req.set("User-Agent", rec.userAgent);
    if (rec.contentType) req = req.set("Content-Type", rec.contentType);
    if (rec.cookie) req = req.set("Cookie", rec.cookie);
    if (rec.referer) req = req.set("Referer", rec.referer);
    if (hasBody) req = req.send(rec.body as string);
    return req;
  };

  try {
    const res = await buildRequest(fullPath);
    return { status: res.status, blocked: res.status === 403 };
  } catch {
    // Some raw dataset payloads (e.g. literal "<script>") are not percent-encoded,
    // which produces an invalid request URL. Real attacker traffic must be valid
    // HTTP, so re-encode the unsafe characters and retry once.
    const res = await buildRequest(encodeURI(fullPath));
    return { status: res.status, blocked: res.status === 403 };
  }
}

describe("E2E Detection Suite (PLAN.md F5.7 GATE)", () => {
  let app: import("express").Express;

  beforeAll(async () => {
    app = createTestApp();
    // Give the worker_thread time to load rf.onnx + if.onnx before the first request.
    await new Promise((r) => setTimeout(r, 6000));
  }, 15000);

  for (const attackClass of ATTACK_CLASSES) {
    test(`${attackClass}: blocks >= 80% of representative payloads`, async () => {
      const fixtures = loadFixtures().filter((r) => r._expected_class === attackClass);
      expect(fixtures.length).toBeGreaterThan(0);

      let blocked = 0;
      for (const rec of fixtures) {
        const result = await sendPayload(app, rec);
        if (result.blocked) blocked++;
      }

      const detectionRate = blocked / fixtures.length;
      // eslint-disable-next-line no-console
      console.log(`${attackClass}: ${blocked}/${fixtures.length} blocked (${(detectionRate * 100).toFixed(1)}%)`);

      expect(detectionRate).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    }, 60000);
  }

  test("benign: false positive rate <= 20%", async () => {
    const fixtures = loadFixtures().filter((r) => r._expected_class === "benign");

    let blocked = 0;
    for (const rec of fixtures) {
      const result = await sendPayload(app, rec);
      if (result.blocked) blocked++;
    }

    const fpRate = blocked / fixtures.length;
    // eslint-disable-next-line no-console
    console.log(`benign: ${blocked}/${fixtures.length} incorrectly blocked (FP rate: ${(fpRate * 100).toFixed(1)}%)`);

    expect(fpRate).toBeLessThanOrEqual(FP_THRESHOLD);
  }, 60000);

  test("GATE: detection rate summary", async () => {
    const fixtures = loadFixtures();
    const results: Record<string, { total: number; blocked: number }> = {};

    for (const rec of fixtures) {
      const cls = rec._expected_class;
      if (!results[cls]) results[cls] = { total: 0, blocked: 0 };
      results[cls].total++;
      const { blocked } = await sendPayload(app, rec);
      if (blocked) results[cls].blocked++;
    }

    // eslint-disable-next-line no-console
    console.log("\n=== E2E Detection Rate Summary (OBJ. 3) ===");
    // eslint-disable-next-line no-console
    console.log("Class           | Detected | Total | Rate    | Gate");
    // eslint-disable-next-line no-console
    console.log("-".repeat(55));

    let allPass = true;
    for (const cls of [...ATTACK_CLASSES, "benign"]) {
      const r = results[cls];
      if (!r) continue;
      const rate = r.blocked / r.total;
      const pass = cls === "benign" ? rate <= FP_THRESHOLD : rate >= DETECTION_THRESHOLD;
      if (!pass) allPass = false;
      const label = cls === "benign" ? "<=20% FP" : ">=80% DR";
      // eslint-disable-next-line no-console
      console.log(
        `${cls.padEnd(16)}| ${String(r.blocked).padEnd(9)}| ${String(r.total).padEnd(6)}| ${(rate * 100)
          .toFixed(1)
          .padEnd(8)}| ${pass ? "PASS" : "FAIL"} ${label}`
      );
    }

    // eslint-disable-next-line no-console
    console.log("-".repeat(55));
    // eslint-disable-next-line no-console
    console.log(`Overall GATE: ${allPass ? "PASS" : "FAIL"}`);

    expect(allPass).toBe(true);
  }, 120000);
});
