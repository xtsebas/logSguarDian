/**
 * Unit tests for middleware.ts (A14/A18, A16/A23, revised for the RF/IF worker-pool
 * split, then again for the async log-patch replacing the grace window).
 *
 * worker_threads is mocked — no ONNX models required.
 * Each MockWorker instance remembers its own role (from workerData.role) so
 * the shared mock helpers can respond as the RF worker, the IF pool workers,
 * or both — mirroring the real architecture: middleware.ts spawns 1 RF
 * worker + IF_POOL_SIZE (2) IF workers, dispatches to both per request, and
 * resolves the INSTANT RF answers — never waits for IF. A late IF reply
 * patches the already-logged DetectionEvent row asynchronously instead.
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
import { WebhookStore } from "../src/webhook-store";

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

// Every makeApp() call opens its own real EventStore/WebhookStore SQLite
// connection (Worker is mocked here, but the stores are not) — closed via
// logsguardian()'s close() (Fase 6/7 addition) at file teardown, same
// leaked-handle-corrupts-other-files' process.cwd() concern as smoke.test.ts.
const middlewareInstances: import("../src/types").LogsguardianHandler[] = [];

afterAll(() => {
  for (const mw of middlewareInstances) mw.close?.();
  for (const p of tmpDbs) { try { fs.unlinkSync(p); } catch { /* already removed */ } }
});

function makeApp(opts: Parameters<typeof logsguardian>[0] = {}): Application {
  // Reset the mock registry so this app's RF/IF worker construction is captured cleanly.
  mockWorkersByRole = { rf: null, if: [] };
  const app = express();
  const mw = logsguardian({ dbPath: tmpDb(), ...opts });
  middlewareInstances.push(mw);
  app.use(mw);
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

/** Wires every IF pool mock worker to reply after delayMs — a REAL setTimeout, not
 *  setImmediate, to simulate IF genuinely arriving after the response already
 *  resolved (the normal case now) and test the async log-patch path. */
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

  test("RF resolves immediately — response does not wait for IF at all", async () => {
    // IF replies after 200ms, far slower than any real inference. If the response
    // waited for it even briefly, elapsedMs would be close to 200ms.
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500 });
    mockRfResponse(BENIGN_HIGH);
    mockIfResponseDelayed(IF_NORMAL, 200);

    const { status, elapsedMs } = await httpGet(app, "/");
    expect(status).toBe(200);
    expect(elapsedMs).toBeLessThan(100);
  });

  test("IF's late reply patches the log asynchronously — verdict flips pass -> pass_anomaly", async () => {
    const dbPath = tmpDb();
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500, dbPath });
    mockRfResponse(BENIGN_HIGH);
    mockIfResponseDelayed(IF_ANOMALY, 20); // arrives well after the response is sent

    const { status } = await httpGet(app, "/");
    expect(status).toBe(200);

    // Immediately after the response: IF hasn't replied yet, so the row is logged
    // as a plain pass with no anomaly data — this is the log-patch design's tradeoff.
    await new Promise((r) => setTimeout(r, 5));
    const dbEarly = new Database(dbPath, { readonly: true });
    const earlyRow = dbEarly.prepare("SELECT verdict, if_score FROM detection_events WHERE id = 1").get() as
      | { verdict: string; if_score: number }
      | undefined;
    dbEarly.close();
    expect(earlyRow?.verdict).toBe("pass");
    expect(earlyRow?.if_score).toBe(0);

    // After IF's delayed reply (20ms) has had time to patch the row:
    await new Promise((r) => setTimeout(r, 60));
    const db = new Database(dbPath, { readonly: true });
    const row = db.prepare("SELECT verdict, if_score, is_anomaly FROM detection_events WHERE id = 1").get() as
      | { verdict: string; if_score: number; is_anomaly: number }
      | undefined;
    db.close();

    expect(row?.verdict).toBe("pass_anomaly");
    expect(row?.if_score).toBe(IF_ANOMALY);
    expect(row?.is_anomaly).toBe(1);
  });

  test("IF's late reply with anomaly=true fires a webhook for the retroactive pass_anomaly", async () => {
    let receivedBody: string | null = null;
    const server = http.createServer((req, res) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => { receivedBody = data; res.end(); });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as { port: number };

    const app = makeApp({
      mode: "block", threshold: 0.70, timeoutMs: 500,
      webhookUrl: `http://127.0.0.1:${port}/hook`,
    });
    mockRfResponse(BENIGN_HIGH);
    mockIfResponseDelayed(IF_ANOMALY, 20);

    const { status } = await httpGet(app, "/");
    expect(status).toBe(200);
    expect(receivedBody).toBeNull(); // no webhook yet — IF hasn't replied

    await new Promise((r) => setTimeout(r, 80)); // let the delayed IF reply patch + fire
    await new Promise<void>((r) => server.close(() => r()));

    expect(receivedBody).not.toBeNull();
    const body = JSON.parse(receivedBody!);
    expect(body.verdict).toBe("pass_anomaly");
    expect(body.is_anomaly).toBe(true);
  });

  test("IF never arrives — log keeps if_score=0, and a very late reply after the timer expires is NOT patched", async () => {
    // timeoutMs (60) is also the ifTimer's cleanup budget for the late-patch map.
    // Delay IF's reply well past that, so by the time it arrives, cleanup has
    // already removed the tracked row — the patch attempt should be a no-op.
    const dbPath = tmpDb();
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 60, dbPath });
    mockRfResponse(BENIGN_HIGH);
    mockIfResponseDelayed(IF_ANOMALY, 150);

    const { status, elapsedMs } = await httpGet(app, "/");
    expect(status).toBe(200);
    expect(elapsedMs).toBeLessThan(60);

    await new Promise((r) => setTimeout(r, 200)); // past both the 60ms cleanup and the 150ms IF reply
    const db = new Database(dbPath, { readonly: true });
    const row = db.prepare("SELECT verdict, if_score, is_anomaly FROM detection_events WHERE id = 1").get() as
      | { verdict: string; if_score: number; is_anomaly: number }
      | undefined;
    db.close();

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

  test("fires webhook to a destination registered via WebhookStore (webhooks add), no webhookUrl configured", async () => {
    const { server, url, waitForBody } = await startReceiver();
    const dbPath = tmpDb();
    const store = new WebhookStore(dbPath);
    store.add(url);
    store.close();

    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500, dbPath }); // no webhookUrl
    mockResponse(SQLI_HIGH, IF_NORMAL);

    await httpGet(app, "/?id=1 OR 1=1");
    const body = JSON.parse(await waitForBody());
    await new Promise<void>((r) => server.close(() => r()));

    expect(body.verdict).toBe("block");
    expect(body.webhook_sent).toBe(true);
  });

  test("does not notify a webhook removed from WebhookStore, even without restarting the process", async () => {
    let fired = false;
    const server = http.createServer((_req, res) => { fired = true; res.end(); });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as { port: number };
    const url = `http://127.0.0.1:${port}/hook`;

    const dbPath = tmpDb();
    const store = new WebhookStore(dbPath);
    const id = store.add(url);
    store.remove(id);
    store.close();

    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500, dbPath });
    mockResponse(SQLI_HIGH, IF_NORMAL);

    await httpGet(app, "/?id=1 OR 1=1");
    await new Promise((r) => setTimeout(r, 300)); // allow webhook to fire if it would

    await new Promise<void>((r) => server.close(() => r()));
    expect(fired).toBe(false);
  });

  test("fires to both webhookUrl and a registered WebhookStore destination on the same detection", async () => {
    const staticReceiver = await startReceiver();
    const registeredReceiver = await startReceiver();
    const dbPath = tmpDb();
    const store = new WebhookStore(dbPath);
    store.add(registeredReceiver.url);
    store.close();

    const app = makeApp({
      mode: "block",
      threshold: 0.70,
      timeoutMs: 500,
      dbPath,
      webhookUrl: staticReceiver.url,
    });
    mockResponse(SQLI_HIGH, IF_NORMAL);

    await httpGet(app, "/?id=1 OR 1=1");
    const [staticBody, registeredBody] = await Promise.all([
      staticReceiver.waitForBody(),
      registeredReceiver.waitForBody(),
    ]);
    await Promise.all([
      new Promise<void>((r) => staticReceiver.server.close(() => r())),
      new Promise<void>((r) => registeredReceiver.server.close(() => r())),
    ]);

    expect(JSON.parse(staticBody).verdict).toBe("block");
    expect(JSON.parse(registeredBody).verdict).toBe("block");
  });

  test("no webhookUrl and no registered webhooks: block verdict is still logged, nothing thrown, webhook_sent=false", async () => {
    const dbPath = tmpDb();
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500, dbPath }); // no webhookUrl, empty webhooks table
    mockResponse(SQLI_HIGH, IF_NORMAL);

    const { status } = await httpGet(app, "/?id=1 OR 1=1");
    expect(status).toBe(403);

    await new Promise((r) => setTimeout(r, 100)); // allow async store.log() to flush
    const db = new Database(dbPath, { readonly: true });
    const row = db.prepare("SELECT verdict, webhook_sent FROM detection_events WHERE id = 1").get() as
      | { verdict: string; webhook_sent: number }
      | undefined;
    db.close();

    expect(row?.verdict).toBe("block");
    expect(row?.webhook_sent).toBe(0);
  });

  test("mutating the registry between two requests on the SAME running middleware instance takes effect immediately (no restart)", async () => {
    const dbPath = tmpDb();
    let received = "";
    const server = http.createServer((req, res) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => { received = data; res.writeHead(200); res.end(); });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as { port: number };
    const url = `http://127.0.0.1:${port}/hook`;

    // App is constructed with an empty webhooks table. This single instance
    // (one middleware closure, one set of workers) is reused for all 3 requests
    // below — no new makeApp() call happens after this point. That's the point:
    // if webhookStore.list() were read once and cached at middleware-init time
    // instead of queried fresh per request, requests 2 and 3 would still behave
    // like request 1, since nothing about the app instance itself ever changes.
    const app = makeApp({ mode: "block", threshold: 0.70, timeoutMs: 500, dbPath });
    mockResponse(SQLI_HIGH, IF_NORMAL);

    // Request 1: registry is empty — must not fire.
    await httpGet(app, "/?id=1 OR 1=1");
    await new Promise((r) => setTimeout(r, 200));
    expect(received).toBe("");

    // Mutate the registry via a SEPARATE WebhookStore handle to the same dbPath —
    // the app instance above is never touched or reconstructed.
    const store = new WebhookStore(dbPath);
    const id = store.add(url);
    store.close();

    // Request 2: same app instance — must now fire, proving the addition was
    // picked up live.
    await httpGet(app, "/?id=1 OR 1=1");
    await new Promise((r) => setTimeout(r, 200));
    expect(received).not.toBe("");
    expect(JSON.parse(received).verdict).toBe("block");

    // Remove it again via a separate handle, still without touching the app instance.
    received = "";
    const store2 = new WebhookStore(dbPath);
    store2.remove(id);
    store2.close();

    // Request 3: same app instance — must stop firing again, proving removal is
    // also picked up live, not just addition.
    await httpGet(app, "/?id=1 OR 1=1");
    await new Promise((r) => setTimeout(r, 200));

    await new Promise<void>((r) => server.close(() => r()));
    expect(received).toBe("");
  });
});
