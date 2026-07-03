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
  test("factory returns a RequestHandler function", () => {
    const mw = logsguardian({ mode: "monitor", dbPath: ":memory:" });
    expect(typeof mw).toBe("function");
    expect(mw.length).toBe(3);
  });

  test("fail-open: next() is called when worker is unavailable (short timeout)", async () => {
    // timeoutMs=2 ensures we exercise the fail-open path without waiting for real inference.
    const mw = logsguardian({ mode: "block", timeoutMs: 2, dbPath: ":memory:" });
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
    const mw = logsguardian({ mode: "monitor", timeoutMs: 2, dbPath: ":memory:" });
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

    const mw = logsguardian({ mode: "block", timeoutMs: 5000, dbPath: ":memory:", modelDir });
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
