/**
 * Unit tests for the webhook dispatcher (A16/A23).
 *
 * Uses a real local HTTP server (no mocks) to verify the payload is delivered
 * correctly. No ONNX models required — tests sendWebhook() directly.
 */
import * as http from "http";
import { sendWebhook } from "../src/webhook";
import type { DetectionEvent } from "../src/types";

const BLOCK_EVENT: DetectionEvent = {
  timestamp: 1700000000000,
  method: "GET",
  path: "/api/users",
  query_string: "id=1' OR '1'='1' UNION SELECT username,password FROM users--",
  user_agent: "Mozilla/5.0 (test)",
  verdict: "block",
  predicted_class: "sqli",
  confidence: 0.98,
  if_score: 0.02,
  is_anomaly: false,
  webhook_sent: true,
  elapsed_ms: 12,
};

const ANOMALY_EVENT: DetectionEvent = {
  ...BLOCK_EVENT,
  verdict: "pass_anomaly",
  predicted_class: "benign",
  confidence: 0.30,
  if_score: 0.03,
  is_anomaly: true,
};

function startMockServer(): Promise<{ server: http.Server; url: string; getBody: () => string }> {
  return new Promise((resolve) => {
    let lastBody = "";
    const server = http.createServer((req, res) => {
      let data = "";
      req.on("data", (chunk) => { data += chunk; });
      req.on("end", () => {
        lastBody = data;
        res.writeHead(200);
        res.end();
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      resolve({
        server,
        url: `http://127.0.0.1:${port}/webhook`,
        getBody: () => lastBody,
      });
    });
  });
}

describe("sendWebhook — delivery", () => {
  let server: http.Server;
  let url: string;
  let getBody: () => string;

  beforeEach(async () => {
    ({ server, url, getBody } = await startMockServer());
  });

  afterEach(() => new Promise<void>((resolve) => server.close(() => resolve())));

  test("sends POST with JSON body to the webhook URL", (done) => {
    sendWebhook(url, BLOCK_EVENT);
    setTimeout(() => {
      const parsed = JSON.parse(getBody()) as DetectionEvent;
      expect(parsed.verdict).toBe("block");
      expect(parsed.predicted_class).toBe("sqli");
      expect(parsed.confidence).toBe(0.98);
      expect(parsed.query_string).toContain("UNION SELECT");
      done();
    }, 300);
  });

  test("payload includes all DetectionEvent fields", (done) => {
    sendWebhook(url, BLOCK_EVENT);
    setTimeout(() => {
      const parsed = JSON.parse(getBody()) as Record<string, unknown>;
      expect(parsed).toHaveProperty("timestamp");
      expect(parsed).toHaveProperty("method");
      expect(parsed).toHaveProperty("path");
      expect(parsed).toHaveProperty("query_string");
      expect(parsed).toHaveProperty("user_agent");
      expect(parsed).toHaveProperty("verdict");
      expect(parsed).toHaveProperty("predicted_class");
      expect(parsed).toHaveProperty("confidence");
      expect(parsed).toHaveProperty("if_score");
      expect(parsed).toHaveProperty("is_anomaly");
      expect(parsed).toHaveProperty("webhook_sent");
      expect(parsed).toHaveProperty("elapsed_ms");
      done();
    }, 300);
  });

  test("fires on pass_anomaly verdict too", (done) => {
    sendWebhook(url, ANOMALY_EVENT);
    setTimeout(() => {
      const parsed = JSON.parse(getBody()) as DetectionEvent;
      expect(parsed.verdict).toBe("pass_anomaly");
      expect(parsed.is_anomaly).toBe(true);
      done();
    }, 300);
  });
});

describe("sendWebhook — fail-open", () => {
  test("does not throw when the server is unreachable", () => {
    expect(() => sendWebhook("http://127.0.0.1:1/no-server", BLOCK_EVENT)).not.toThrow();
  });

  test("does not throw on a malformed URL", () => {
    expect(() => sendWebhook("not-a-url", BLOCK_EVENT)).not.toThrow();
  });

  test("does not throw on an empty URL", () => {
    expect(() => sendWebhook("", BLOCK_EVENT)).not.toThrow();
  });
});
