/**
 * Unit tests for middleware.ts (A14/A18, A16/A23).
 *
 * worker_threads is mocked — no ONNX models required.
 * The MockWorker is an EventEmitter; each test configures postMessage
 * to emit a synthetic WorkerResponse so applyPolicy() can be exercised.
 *
 * RF_CLASSES order: ["benign", "cmdi", "path_traversal", "sqli", "xss"]
 * IF_THRESHOLD = 0.02901575  (below → anomaly)
 */
import * as http from "http";
import * as net from "net";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import Database from "better-sqlite3";
import express from "express";
import type { Application } from "express";
import type { WorkerRequest, WorkerResponse } from "../src/types";

// ─── Worker mock ─────────────────────────────────────────────────────────────
// Variable starts with "mock" so babel-jest allows it inside jest.mock factory.
interface MockWorkerLike {
  emit(event: string, ...args: unknown[]): boolean;
  postMessage(msg: unknown): void;
}
// eslint-disable-next-line prefer-const
let mockWorkerRef: MockWorkerLike | null = null;

jest.mock("worker_threads", () => {
  const { EventEmitter } = require("events");
  class MockWorker extends EventEmitter {
    constructor(_scriptPath: unknown, _opts: unknown) {
      super();
      mockWorkerRef = this as unknown as MockWorkerLike;
    }
    postMessage(_msg: unknown): void { /* no-op → middleware times out */ }
    terminate(): void {}
  }
  return {
    Worker: MockWorker,
    workerData: undefined,
    isMainThread: true,
    parentPort: null,
  };
});

// Import AFTER mock registration so middleware.ts receives the fake Worker.
import { logsguardian } from "../src/middleware";

// ─── Helpers ──────────────────────────────────────────────────────────────────
const tmpDbs: string[] = [];

function tmpDb(): string {
  const p = path.join(
    os.tmpdir(),
    `lg-mw-${Date.now()}-${Math.random().toString(36).slice(2)}.db`
  );
  tmpDbs.push(p);
  return p;
}

afterAll(() => {
  for (const p of tmpDbs) { try { fs.unlinkSync(p); } catch { /* already removed */ } }
});

function makeApp(opts: Parameters<typeof logsguardian>[0] = {}): Application {
  const app = express();
  app.use(logsguardian({ dbPath: tmpDb(), ...opts }));
  app.get("/", (_req, res) => res.json({ ok: true }));
  return app;
}

function httpGet(app: Application, url: string): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const { port } = server.address() as net.AddressInfo;
      http.get(`http://127.0.0.1:${port}${url}`, (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          server.close(() => {
            let body: unknown;
            try { body = JSON.parse(data); } catch { body = data; }
            resolve({ status: res.statusCode!, body });
          });
        });
      }).on("error", (err) => { server.close(); reject(err); });
    });
  });
}

/** Overrides postMessage on the current mock worker to emit a synthetic response. */
function mockResponse(rfProbs: number[], ifScore: number): void {
  const w = mockWorkerRef!;
  w.postMessage = (msg: unknown) => {
    const { id } = msg as WorkerRequest;
    setImmediate(() => w.emit("message", { id, rfProbs, ifScore } as WorkerResponse));
  };
}

// ─── Probe vectors ────────────────────────────────────────────────────────────
// RF_CLASSES = ["benign","cmdi","path_traversal","sqli","xss"]
const SQLI_HIGH   = [0.05, 0.05, 0.05, 0.80, 0.05]; // sqli at 0.80
const SQLI_LOW    = [0.10, 0.10, 0.10, 0.50, 0.20]; // sqli at 0.50
const BENIGN_HIGH = [0.90, 0.03, 0.03, 0.02, 0.02]; // benign at 0.90
const IF_NORMAL   = 0.10;                             // above threshold → not anomaly
const IF_ANOMALY  = 0.01;                             // below threshold → anomaly

// ─── Tests ───────────────────────────────────────────────────────────────────
describe("logsguardian — fail-open", () => {
  test("passes request when worker does not respond within timeoutMs", async () => {
    const app = makeApp({ timeoutMs: 60 });
    // mockWorkerRef.postMessage is no-op → timeout → fail-open pass
    const { status } = await httpGet(app, "/");
    expect(status).toBe(200);
  });
});

describe("logsguardian — block mode", () => {
  test("returns 403 when RF predicts attack with confidence >= threshold", async () => {
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500 });
    mockResponse(SQLI_HIGH, IF_NORMAL);

    const { status, body } = await httpGet(app, "/?id=1 OR 1=1");
    expect(status).toBe(403);
    expect((body as { class: string }).class).toBe("sqli");
  });

  test("passes request when attack confidence is below threshold", async () => {
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500 });
    mockResponse(SQLI_LOW, IF_NORMAL); // 0.50 < 0.70

    const { status } = await httpGet(app, "/?id=1 OR 1=1");
    expect(status).toBe(200);
  });

  test("passes benign request", async () => {
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500 });
    mockResponse(BENIGN_HIGH, IF_NORMAL);

    const { status } = await httpGet(app, "/");
    expect(status).toBe(200);
  });
});

describe("logsguardian — monitor mode", () => {
  test("does not return 403 even for high-confidence attack", async () => {
    const app = makeApp({ mode: "monitor", threshold: 0.70, timeoutMs: 500 });
    mockResponse(SQLI_HIGH, IF_NORMAL); // would block in block mode

    const { status } = await httpGet(app, "/?id=1 OR 1=1");
    expect(status).toBe(200);
  });
});

describe("logsguardian — custom threshold", () => {
  test("blocks when confidence >= custom threshold", async () => {
    const app = makeApp({ mode: "block", threshold: 0.45, timeoutMs: 500 });
    mockResponse(SQLI_LOW, IF_NORMAL); // 0.50 >= 0.45 → block

    const { status } = await httpGet(app, "/");
    expect(status).toBe(403);
  });

  test("passes when confidence < custom threshold", async () => {
    const app = makeApp({ mode: "block", threshold: 0.60, timeoutMs: 500 });
    mockResponse(SQLI_LOW, IF_NORMAL); // 0.50 < 0.60 → pass

    const { status } = await httpGet(app, "/");
    expect(status).toBe(200);
  });
});

describe("logsguardian — client_ip capture", () => {
  test("persists the requester's IP on the logged DetectionEvent", async () => {
    const dbPath = tmpDb();
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500, dbPath });
    mockResponse(SQLI_HIGH, IF_NORMAL);

    await httpGet(app, "/?id=1 OR 1=1");
    await new Promise((r) => setTimeout(r, 100)); // allow async store.log() to flush

    const db = new Database(dbPath, { readonly: true });
    const row = db.prepare("SELECT client_ip FROM detection_events WHERE id = 1").get() as
      | { client_ip: string }
      | undefined;
    db.close();

    expect(row?.client_ip).toBeTruthy();
    expect(row?.client_ip).toMatch(/127\.0\.0\.1|::1|::ffff:127\.0\.0\.1/);
  });
});

describe("logsguardian — webhook", () => {
  function startReceiver(): Promise<{ server: http.Server; url: string; waitForBody: () => Promise<string> }> {
    return new Promise((resolve) => {
      let received = "";
      let notify: ((s: string) => void) | null = null;

      const server = http.createServer((req, res) => {
        let data = "";
        req.on("data", (c) => (data += c));
        req.on("end", () => {
          received = data;
          res.writeHead(200);
          res.end();
          if (notify) { notify(data); notify = null; }
        });
      });

      server.listen(0, "127.0.0.1", () => {
        const { port } = server.address() as { port: number };
        resolve({
          server,
          url: `http://127.0.0.1:${port}/hook`,
          waitForBody: () =>
            new Promise((res2) => {
              if (received) { res2(received); return; }
              notify = res2;
              setTimeout(() => res2(received), 500); // fallback
            }),
        });
      });
    });
  }

  test("fires webhook on block verdict", async () => {
    const { server, url, waitForBody } = await startReceiver();
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500, webhookUrl: url });
    mockResponse(SQLI_HIGH, IF_NORMAL);

    await httpGet(app, "/?id=1 OR 1=1");
    const body = JSON.parse(await waitForBody());
    await new Promise<void>((r) => server.close(() => r()));

    expect(body.verdict).toBe("block");
    expect(body.predicted_class).toBe("sqli");
    expect(body.webhook_sent).toBe(true);
  });

  test("fires webhook on pass_anomaly verdict", async () => {
    const { server, url, waitForBody } = await startReceiver();
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500, webhookUrl: url });
    mockResponse(BENIGN_HIGH, IF_ANOMALY); // benign class but anomalous IF score

    await httpGet(app, "/");
    const body = JSON.parse(await waitForBody());
    await new Promise<void>((r) => server.close(() => r()));

    expect(body.verdict).toBe("pass_anomaly");
    expect(body.is_anomaly).toBe(true);
  });

  test("does not fire webhook on clean pass verdict", async () => {
    let fired = false;
    const server = http.createServer((_req, res) => { fired = true; res.end(); });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as { port: number };

    const app = makeApp({
      mode: "block",
      threshold: 0.70,
      timeoutMs: 500,
      webhookUrl: `http://127.0.0.1:${port}/hook`,
    });
    mockResponse(BENIGN_HIGH, IF_NORMAL); // fully benign → verdict 'pass'

    await httpGet(app, "/");
    await new Promise((r) => setTimeout(r, 300)); // allow webhook to fire if it would

    await new Promise<void>((r) => server.close(() => r()));
    expect(fired).toBe(false);
  });
});
