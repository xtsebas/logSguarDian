import * as fs from "fs";
import * as http from "http";
import * as os from "os";
import * as path from "path";
import { runConfigInit } from "../src/cli/config-init";
import { runWebhooksTest } from "../src/cli/webhooks-test";
import { WebhookStore } from "../src/webhook-store";
import type { DetectionEvent } from "../src/types";

/** Registers a webhook directly via WebhookStore — bypasses the CLI's HTTPS-only
 *  validation in webhooks-add.ts, needed since the local mock server is plain HTTP. */
function seedWebhook(dir: string, url: string): void {
  const store = new WebhookStore(path.join(dir, "logsguardian.db"));
  store.add(url);
  store.close();
}

function withTempDir(fn: (dir: string) => Promise<void> | void): Promise<void> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-webhooks-test-"));
  const origCwd = process.cwd();
  process.chdir(dir);
  return Promise.resolve(fn(dir)).finally(() => {
    process.chdir(origCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });
}

function mockExit(): jest.SpyInstance {
  return jest.spyOn(process, "exit").mockImplementation((code) => {
    throw new Error(`process.exit(${code})`);
  });
}

/**
 * Real local HTTP server that always responds with the given status code.
 *
 * Sends `Connection: close` and forcibly closes all sockets on teardown
 * (closeServer) — without this, sendWebhook()'s client socket can be kept
 * alive by Node's default HTTP agent (each test hits a distinct ephemeral
 * port, so the pooled socket is never reused, just left open) past the end
 * of the test that created it. That's exactly the kind of leaked handle
 * Jest's "worker process failed to exit gracefully... Active timers can
 * also cause this" warning describes, and it was the confirmed root cause
 * of this file corrupting other tests' process.cwd() when run in the same
 * suite: a handle from test N staying alive let test N's continuation (or
 * Node's own socket teardown) run interleaved with test N+1's chdir'd
 * region, since nothing here actually waits for full socket teardown
 * before resolving.
 */
function startMockServer(statusCode: number): Promise<{ server: http.Server; url: string; getBody: () => string }> {
  return new Promise((resolve) => {
    let lastBody = "";
    const server = http.createServer((req, res) => {
      let data = "";
      req.on("data", (chunk) => {
        data += chunk;
      });
      req.on("end", () => {
        lastBody = data;
        res.setHeader("Connection", "close");
        res.writeHead(statusCode);
        res.end();
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      resolve({ server, url: `http://127.0.0.1:${port}/webhook`, getBody: () => lastBody });
    });
  });
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });
}

describe("webhooks test", () => {
  test("exits with code 1 when no id argument is given", async () => {
    await withTempDir(async () => {
      runConfigInit();
      const spy = mockExit();
      const errSpy = jest.spyOn(console, "error").mockImplementation(() => {});
      await expect(runWebhooksTest([])).rejects.toThrow("process.exit(1)");
      expect(errSpy.mock.calls.join(" ")).toContain("Usage: logsguardian webhooks test <id>");
      errSpy.mockRestore();
      spy.mockRestore();
    });
  });

  test("exits with code 1 on an invalid id ('abc', '1.5', '01')", async () => {
    await withTempDir(async () => {
      runConfigInit();
      const spy = mockExit();
      await expect(runWebhooksTest(["abc"])).rejects.toThrow("process.exit(1)");
      await expect(runWebhooksTest(["1.5"])).rejects.toThrow("process.exit(1)");
      await expect(runWebhooksTest(["01"])).rejects.toThrow("process.exit(1)");
      spy.mockRestore();
    });
  });

  test("exits with code 1 when the id is not in the store", async () => {
    await withTempDir(async () => {
      runConfigInit();
      const spy = mockExit();
      const errSpy = jest.spyOn(console, "error").mockImplementation(() => {});
      await expect(runWebhooksTest(["999"])).rejects.toThrow("process.exit(1)");
      expect(errSpy.mock.calls.join(" ")).toContain("webhook #999 not found");
      errSpy.mockRestore();
      spy.mockRestore();
    });
  });

  test("valid id, server returns 200: output contains HTTP 200 and success message", async () => {
    const { server, url } = await startMockServer(200);
    await withTempDir(async (dir) => {
      runConfigInit();
      const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      seedWebhook(dir, url);

      await runWebhooksTest(["1"]);
      const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
      logSpy.mockRestore();

      expect(output).toContain("HTTP 200");
      expect(output).toContain("Webhook delivered successfully.");
    });
    await closeServer(server);
  });

  test("valid id, server returns 500: output contains HTTP 500, does not crash", async () => {
    const { server, url } = await startMockServer(500);
    await withTempDir(async (dir) => {
      runConfigInit();
      const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      seedWebhook(dir, url);

      await expect(runWebhooksTest(["1"])).resolves.toBeUndefined();
      const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
      logSpy.mockRestore();

      expect(output).toContain("HTTP 500");
      expect(output).toContain("non-2xx status");
    });
    await closeServer(server);
  });

  test("server unreachable: exits 1 with 'No response received'", async () => {
    await withTempDir(async (dir) => {
      runConfigInit();
      seedWebhook(dir, "http://127.0.0.1:1/unreachable");

      const spy = mockExit();
      const output2Spy = jest.spyOn(console, "log").mockImplementation(() => {});
      await expect(runWebhooksTest(["1"])).rejects.toThrow("process.exit(1)");
      const output = output2Spy.mock.calls.map((c) => c.join(" ")).join("\n");
      output2Spy.mockRestore();
      spy.mockRestore();

      expect(output).toContain("No response received");
    });
  });

  test("payload shape: server receives JSON body with all DetectionEvent fields", async () => {
    const { server, url, getBody } = await startMockServer(200);
    await withTempDir(async (dir) => {
      runConfigInit();
      const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      seedWebhook(dir, url);

      await runWebhooksTest(["1"]);
      logSpy.mockRestore();

      const parsed = JSON.parse(getBody()) as DetectionEvent;
      expect(typeof parsed.timestamp).toBe("number");
      expect(parsed).toHaveProperty("method");
      expect(parsed).toHaveProperty("path");
      expect(parsed).toHaveProperty("query_string");
      expect(parsed).toHaveProperty("user_agent");
      expect(parsed).toHaveProperty("client_ip");
      expect(parsed).toHaveProperty("verdict");
      expect(parsed).toHaveProperty("predicted_class");
      expect(parsed).toHaveProperty("confidence");
      expect(parsed).toHaveProperty("if_score");
      expect(parsed).toHaveProperty("is_anomaly");
      expect(parsed).toHaveProperty("webhook_sent");
      expect(parsed).toHaveProperty("elapsed_ms");
    });
    await closeServer(server);
  });
});
