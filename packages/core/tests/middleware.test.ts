/**
 * Unit tests for middleware.ts (A14/A18, A16/A23, revised for the RF/IF worker-pool split).
 *
 * worker_threads is mocked — no ONNX models required.
 * Each MockWorker instance remembers its own role (from workerData.role) so
 * the shared mock helpers can respond as the RF worker, the IF pool workers,
 * or both — mirroring the real architecture: middleware.ts spawns 1 RF
 * worker + IF_POOL_SIZE (2) IF workers, dispatches to both per request, and
 * resolves as soon as RF answers (IF only enriches, never blocks/delays).
 *
 * RF_CLASSES order: ["benign", "cmdi", "path_traversal", "sqli", "xss"]
 * IF_THRESHOLD = 0.002486040118540811  (below → anomaly)
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
  role: "rf" | "if";
  emit(event: string, ...args: unknown[]): boolean;
  postMessage(msg: unknown): void;
}
// eslint-disable-next-line prefer-const
let mockWorkersByRole: { rf: MockWorkerLike | null; if: MockWorkerLike[] } = { rf: null, if: [] };

jest.mock("worker_threads", () => {
  const { EventEmitter } = require("events");
  class MockWorker extends EventEmitter {
    role: "rf" | "if";
    constructor(_scriptPath: unknown, opts: { workerData: { role: "rf" | "if" } }) {
      super();
      this.role = opts.workerData.role;
      if (this.role === "rf") {
        mockWorkersByRole.rf = this as unknown as MockWorkerLike;
      } else {
        mockWorkersByRole.if.push(this as unknown as MockWorkerLike);
      }
      // Real workers signal readiness once their ONNX session loads; mocks have
      // no loading to do, so signal immediately (after listeners are attached).
      setImmediate(() => this.emit("message", { ready: true, role: this.role }));
    }
    postMessage(_msg: unknown): void { /* no-op → hop times out */ }
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
  // Reset the mock registry so this app's RF/IF worker construction is captured cleanly.
  mockWorkersByRole = { rf: null, if: [] };
  const app = express();
  app.use(logsguardian({ dbPath: tmpDb(), ...opts }));
  app.get("/", (_req, res) => res.json({ ok: true }));
  return app;
}

function httpGet(app: Application, url: string): Promise<{ status: number; body: unknown; elapsedMs: number }> {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const { port } = server.address() as net.AddressInfo;
      const t0 = Date.now();
      http.get(`http://127.0.0.1:${port}${url}`, (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          const elapsedMs = Date.now() - t0;
          server.close(() => {
            let body: unknown;
            try { body = JSON.parse(data); } catch { body = data; }
            resolve({ status: res.statusCode!, body, elapsedMs });
          });
        });
      }).on("error", (err) => { server.close(); reject(err); });
    });
  });
}

/** Wires the RF mock worker to reply immediately with the given probs. */
function mockRfResponse(rfProbs: number[]): void {
  const rf = mockWorkersByRole.rf!;
  rf.postMessage = (msg: unknown) => {
    const { id } = msg as WorkerRequest;
    setImmediate(() => rf.emit("message", { id, role: "rf", rfProbs } as WorkerResponse));
  };
}

/** Wires every IF pool mock worker to reply immediately with the given score. */
function mockIfResponse(ifScore: number): void {
  for (const ifw of mockWorkersByRole.if) {
    ifw.postMessage = (msg: unknown) => {
      const { id } = msg as WorkerRequest;
      setImmediate(() => ifw.emit("message", { id, role: "if", ifScore } as WorkerResponse));
    };
  }
}

/** Wires every IF pool mock worker to reply after delayMs — a REAL setTimeout, not setImmediate,
 *  to test IF_GRACE_MS's boundary (arrival within vs. past the grace window). */
function mockIfResponseDelayed(ifScore: number, delayMs: number): void {
  for (const ifw of mockWorkersByRole.if) {
    ifw.postMessage = (msg: unknown) => {
      const { id } = msg as WorkerRequest;
      setTimeout(() => ifw.emit("message", { id, role: "if", ifScore } as WorkerResponse), delayMs);
    };
  }
}

/** Wires both hops to reply immediately — the common case for existing tests. */
function mockResponse(rfProbs: number[], ifScore: number): void {
  mockRfResponse(rfProbs);
  mockIfResponse(ifScore);
}

// ─── Probe vectors ────────────────────────────────────────────────────────────
// RF_CLASSES = ["benign","cmdi","path_traversal","sqli","xss"]
const SQLI_HIGH   = [0.05, 0.05, 0.05, 0.80, 0.05]; // sqli at 0.80
const SQLI_LOW    = [0.10, 0.10, 0.10, 0.50, 0.20]; // sqli at 0.50
const BENIGN_HIGH = [0.90, 0.03, 0.03, 0.02, 0.02]; // benign at 0.90
const IF_NORMAL   = 0.10;                             // above threshold → not anomaly
const IF_ANOMALY  = 0.001;                            // below threshold → anomaly

// ─── Tests ───────────────────────────────────────────────────────────────────
describe("logsguardian — fail-open", () => {
  test("passes request when neither RF nor IF worker responds within timeoutMs", async () => {
    const app = makeApp({ timeoutMs: 60 });
    // Both mock workers default to no-op postMessage → both hops time out → fail-open pass
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

describe("logsguardian — RF/IF pool partial-failure handling", () => {
  test("resolves from RF alone when IF times out — verdict correct, if_score=0, no response delay", async () => {
    // IF's timeoutMs is long (2000ms); if the response were waiting on IF, this test
    // would take >2s. It should resolve as soon as RF answers instead.
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 2000 });
    mockRfResponse(SQLI_HIGH); // IF worker(s) left as no-op → IF hop times out

    const { status, body, elapsedMs } = await httpGet(app, "/?id=1 OR 1=1");
    expect(status).toBe(403);
    expect((body as { class: string }).class).toBe("sqli");
    // Must not have waited anywhere near IF's 2000ms timeout.
    expect(elapsedMs).toBeLessThan(500);
  });

  test("fails open when RF times out, even though IF replied — IF's data is discarded", async () => {
    const dbPath = tmpDb();
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 150, dbPath });
    mockIfResponse(IF_ANOMALY); // RF worker left as no-op → RF hop times out

    const { status } = await httpGet(app, "/");
    expect(status).toBe(200); // fail-open: RF is sole blocking authority

    await new Promise((r) => setTimeout(r, 100)); // allow async store.log() to flush
    const db = new Database(dbPath, { readonly: true });
    const row = db.prepare("SELECT verdict, if_score, is_anomaly FROM detection_events WHERE id = 1").get() as
      | { verdict: string; if_score: number; is_anomaly: number }
      | undefined;
    db.close();

    expect(row?.verdict).toBe("timeout");
    // IF's anomaly score must not leak into the logged event once RF has already timed out.
    expect(row?.if_score).toBe(0);
    expect(row?.is_anomaly).toBe(0);
  });

  test("IF within the grace window is included in the verdict (pass_anomaly)", async () => {
    // IF replies via setImmediate (effectively ~0ms), well inside IF_GRACE_MS (5ms).
    // This is the case that failed before the grace window existed (RF always won the
    // race against IF's mock reply, resolving before ifScore was ever attached).
    const dbPath = tmpDb();
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500, dbPath });
    mockRfResponse(BENIGN_HIGH);
    mockIfResponse(IF_ANOMALY);

    const { status } = await httpGet(app, "/");
    expect(status).toBe(200);

    await new Promise((r) => setTimeout(r, 100)); // allow async store.log() to flush
    const db = new Database(dbPath, { readonly: true });
    const row = db.prepare("SELECT verdict, if_score, is_anomaly FROM detection_events WHERE id = 1").get() as
      | { verdict: string; if_score: number; is_anomaly: number }
      | undefined;
    db.close();

    expect(row?.verdict).toBe("pass_anomaly");
    expect(row?.is_anomaly).toBe(1);
  });

  test("IF arriving AFTER the grace window expires is NOT included — verdict resolves as plain pass", async () => {
    // IF_GRACE_MS is 5ms; delay the IF mock reply to 40ms, well past the window,
    // to prove the window actually expires rather than waiting indefinitely for IF.
    const dbPath = tmpDb();
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500, dbPath });
    mockRfResponse(BENIGN_HIGH);
    mockIfResponseDelayed(IF_ANOMALY, 40);

    const { status, elapsedMs } = await httpGet(app, "/");
    expect(status).toBe(200);
    // Resolved via the grace window (~5ms), not by waiting the full 40ms for IF.
    expect(elapsedMs).toBeLessThan(40);

    await new Promise((r) => setTimeout(r, 100)); // allow async store.log() to flush
    const db = new Database(dbPath, { readonly: true });
    const row = db.prepare("SELECT verdict, if_score, is_anomaly FROM detection_events WHERE id = 1").get() as
      | { verdict: string; if_score: number; is_anomaly: number }
      | undefined;
    db.close();

    // IF's anomalous score arrived too late to be folded in — verdict is plain pass, not pass_anomaly.
    expect(row?.verdict).toBe("pass");
    expect(row?.if_score).toBe(0);
    expect(row?.is_anomaly).toBe(0);
  });

  test("both RF and IF timing out still fails open (unchanged from single-worker behavior)", async () => {
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 60 });
    // Both mock workers default to no-op — neither hop responds.
    const { status } = await httpGet(app, "/?id=1 OR 1=1");
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
