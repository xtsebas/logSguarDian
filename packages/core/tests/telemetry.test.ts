/**
 * Unit tests for the MLOps telemetry dispatcher (CT/CI/CD pipeline, Fase 1).
 *
 * Uses a real local HTTP server (no mocks) to verify the payload is delivered
 * correctly. No ONNX models required — tests sendTelemetry() directly.
 */
import * as http from "http";
import { sendTelemetry } from "../src/telemetry";
import type { TelemetryEvent } from "../src/types";

const EVENT: TelemetryEvent = {
  vector: Array.from({ length: 73 }, (_, i) => i * 0.1),
  predicted_class: "sqli",
  confidence: 0.92,
  timestamp: 1700000000000,
  source_id: "host-a",
};

function startMockServer(): Promise<{ server: http.Server; url: string; getBody: () => string }> {
  return new Promise((resolve) => {
    let lastBody = "";
    const server = http.createServer((req, res) => {
      let data = "";
      req.on("data", (chunk) => { data += chunk; });
      req.on("end", () => {
        lastBody = data;
        // See webhook.test.ts's identical fix — prevents a keep-alive client
        // socket from outliving this test and corrupting other chdir-based
        // test files sharing this Jest worker process.
        res.setHeader("Connection", "close");
        res.writeHead(201);
        res.end();
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      resolve({
        server,
        url: `http://127.0.0.1:${port}/telemetry`,
        getBody: () => lastBody,
      });
    });
  });
}

describe("sendTelemetry — delivery", () => {
  let server: http.Server;
  let url: string;
  let getBody: () => string;

  beforeEach(async () => {
    ({ server, url, getBody } = await startMockServer());
  });

  afterEach(() => new Promise<void>((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  }));

  test("sends POST with JSON body to the collector URL", (done) => {
    sendTelemetry(url, EVENT);
    setTimeout(() => {
      const parsed = JSON.parse(getBody()) as TelemetryEvent;
      expect(parsed.predicted_class).toBe("sqli");
      expect(parsed.confidence).toBeCloseTo(0.92);
      expect(parsed.source_id).toBe("host-a");
      expect(parsed.vector).toHaveLength(73);
      done();
    }, 300);
  });

  test("payload includes all TelemetryEvent fields", (done) => {
    sendTelemetry(url, EVENT);
    setTimeout(() => {
      const parsed = JSON.parse(getBody()) as Record<string, unknown>;
      expect(parsed).toHaveProperty("vector");
      expect(parsed).toHaveProperty("predicted_class");
      expect(parsed).toHaveProperty("confidence");
      expect(parsed).toHaveProperty("timestamp");
      expect(parsed).toHaveProperty("source_id");
      done();
    }, 300);
  });
});

describe("sendTelemetry — fail-open", () => {
  test("does not throw when the collector is unreachable", () => {
    expect(() => sendTelemetry("http://127.0.0.1:1/no-server", EVENT)).not.toThrow();
  });

  test("does not throw on a malformed URL", () => {
    expect(() => sendTelemetry("not-a-url", EVENT)).not.toThrow();
  });

  test("does not throw on an empty URL", () => {
    expect(() => sendTelemetry("", EVENT)).not.toThrow();
  });
});
