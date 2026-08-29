/**
 * Smoke test for packages/core middleware (F5.3).
 *
 * Does NOT require ONNX models to be present. Tests that:
 *   1. logsguardian() returns an Express-compatible RequestHandler.
 *   2. When the worker is unavailable (dist/worker.js not compiled or models
 *      missing), the middleware fails open — next() is always called.
 *   3. In 'monitor' mode, next() is called even when a verdict would be 'block'.
 */
import * as path from "path";
import type { Request, Response, NextFunction } from "express";
import { logsguardian } from "../dist/index";

function makeReq(overrides: Partial<Request> = {}): Request {
  return {
    method: "GET",
    path: "/api/users",
    query: {},
    body: {},
    headers: { "user-agent": "jest-smoke-test" },
    ...overrides,
  } as unknown as Request;
}

function makeRes(): Response {
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  };
  return res as unknown as Response;
}

describe("logsguardian middleware — smoke tests", () => {
  // Every logsguardian() call spawns real worker_threads (1 RF + 2 IF) — even
  // with a short timeoutMs, since the middleware's timeout only governs how
  // long IT waits, not whether the workers themselves spawn and start loading
  // real ONNX models from the default modelDir (packages/core/models/,
  // populated by the postbuild script). Left unterminated, these outlive the
  // test and were confirmed (during the Fase 6/7 test-suite flakiness
  // investigation) to be the dominant source of cross-file process.cwd()
  // corruption in other chdir-based test files sharing this Jest worker
  // process — closing every instance here fixes that at the source instead
  // of chasing it file-by-file.
  const instances: import("../src/types").LogsguardianHandler[] = [];
  function trackedLogsguardian(...args: Parameters<typeof logsguardian>): ReturnType<typeof logsguardian> {
    const mw = logsguardian(...args);
    instances.push(mw);
    return mw;
  }
  // afterAll rather than afterEach: fewer terminate() calls overall (the
  // worker-thread crash race is triggered by terminate() itself, so calling
  // it less often — once at file teardown instead of after every test —
  // reduces exposure), and all that actually matters is that no worker from
  // this file survives into the NEXT file Jest schedules onto this worker
  // process.
  afterAll(() => {
    for (const mw of instances) mw.close?.();
    instances.length = 0;
  });

  test("factory returns a RequestHandler function", () => {
    const mw = trackedLogsguardian({ mode: "monitor", dbPath: ":memory:" });
    expect(typeof mw).toBe("function");
    expect(mw.length).toBe(3);
  });

  test("fail-open: next() is called when worker is unavailable (short timeout)", async () => {
    // timeoutMs=2 ensures we exercise the fail-open path without waiting for real inference.
    const mw = trackedLogsguardian({ mode: "block", timeoutMs: 2, dbPath: ":memory:" });
    const next = jest.fn() as unknown as NextFunction;
    const res = makeRes();
    await mw(makeReq(), res, next);
    expect(next).toHaveBeenCalledTimes(1);
  });

  test("monitor mode: next() is called regardless of verdict", async () => {
    const sqliReq = makeReq({
      method: "GET",
      path: "/products",
      query: { id: "1' OR '1'='1' UNION SELECT username,password FROM users--" } as unknown as Request["query"],
    });
    const mw = trackedLogsguardian({ mode: "monitor", timeoutMs: 2, dbPath: ":memory:" });
    const next = jest.fn() as unknown as NextFunction;
    const res = makeRes();
    await mw(sqliReq, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });

  test("with real models: block mode sends 403 on SQLi GET query param", async () => {
    const modelDir = path.join(__dirname, "../../../training/models");
    const workerPath = path.join(__dirname, "../dist/worker.js");

    const fs = await import("fs");
    const modelsExist =
      fs.existsSync(path.join(modelDir, "rf.onnx")) &&
      fs.existsSync(path.join(modelDir, "if.onnx")) &&
      fs.existsSync(workerPath);

    if (!modelsExist) {
      console.log("Skipping: models or compiled worker not present.");
      return;
    }

    const mw = trackedLogsguardian({ mode: "block", timeoutMs: 5000, dbPath: ":memory:", modelDir });
    // Give the worker time to load the models before sending real traffic.
    await new Promise((r) => setTimeout(r, 3000));

    // GET request: attack payload is in the query string, req.body is {} (default Express).
    // This is the canonical delivery vector for SQLi/XSS/PT/CMDi — the body bug would
    // make the middleware serialize {} to "{}" and shadow the query string entirely.
    const sqliReq = makeReq({
      method: "GET",
      path: "/products",
      query: { id: "1' OR '1'='1' UNION SELECT username,password FROM users--" } as unknown as Request["query"],
      body: {}, // default Express body — must NOT shadow the query
    });

    const next = jest.fn() as unknown as NextFunction;
    const res = makeRes();
    await mw(sqliReq, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  }, 15000);
});
