/**
 * Fase 1 acceptance test: a real vector sent over HTTP arrives and is stored.
 */
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import request from "supertest";
import { createCollectorApp } from "../src/collector/server";
import type { Collector } from "../src/collector/server";

const VALID_VECTOR = Array.from({ length: 73 }, (_, i) => i * 0.01);

function tmpDb(): string {
  return path.join(os.tmpdir(), `lg-mlops-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
}

describe("POST /telemetry", () => {
  let collector: Collector;
  let dbPath: string;

  beforeEach(() => {
    dbPath = tmpDb();
    collector = createCollectorApp({ dbPath });
  });

  afterEach(() => {
    collector.store.close();
    try { fs.unlinkSync(dbPath); } catch { /* already removed */ }
  });

  test("accepts a valid vector and stores it", async () => {
    const res = await request(collector.app)
      .post("/telemetry")
      .send({
        vector: VALID_VECTOR,
        predicted_class: "sqli",
        confidence: 0.91,
        timestamp: Date.now(),
        source_id: "host-a",
      });

    expect(res.status).toBe(201);
    expect(collector.store.count()).toBe(1);

    const [stored] = collector.store.list();
    expect(stored.source_id).toBe("host-a");
    expect(stored.predicted_class).toBe("sqli");
    expect(stored.confidence).toBeCloseTo(0.91);
    expect(stored.vector).toHaveLength(73);
    expect(stored.vector[5]).toBeCloseTo(0.05);
  });

  test("accumulates vectors from multiple sources", async () => {
    const base = { vector: VALID_VECTOR, predicted_class: "benign", confidence: 0.99, timestamp: Date.now() };
    await request(collector.app).post("/telemetry").send({ ...base, source_id: "host-a" });
    await request(collector.app).post("/telemetry").send({ ...base, source_id: "host-b" });
    await request(collector.app).post("/telemetry").send({ ...base, source_id: "host-a" });

    expect(collector.store.count()).toBe(3);
    expect(collector.store.sources().sort()).toEqual(["host-a", "host-b"]);
  });

  test("rejects a vector with the wrong length", async () => {
    const res = await request(collector.app)
      .post("/telemetry")
      .send({ vector: [1, 2, 3], predicted_class: "benign", confidence: 0.5, timestamp: Date.now(), source_id: "host-a" });

    expect(res.status).toBe(400);
    expect(collector.store.count()).toBe(0);
  });

  test("rejects an unknown predicted_class", async () => {
    const res = await request(collector.app)
      .post("/telemetry")
      .send({ vector: VALID_VECTOR, predicted_class: "not-a-class", confidence: 0.5, timestamp: Date.now(), source_id: "host-a" });

    expect(res.status).toBe(400);
  });

  test("rejects confidence outside [0, 1]", async () => {
    const res = await request(collector.app)
      .post("/telemetry")
      .send({ vector: VALID_VECTOR, predicted_class: "benign", confidence: 1.5, timestamp: Date.now(), source_id: "host-a" });

    expect(res.status).toBe(400);
  });

  test("rejects a missing source_id", async () => {
    const res = await request(collector.app)
      .post("/telemetry")
      .send({ vector: VALID_VECTOR, predicted_class: "benign", confidence: 0.5, timestamp: Date.now() });

    expect(res.status).toBe(400);
  });
});

describe("GET /health", () => {
  test("reports event and source counts", async () => {
    const dbPath = tmpDb();
    const collector = createCollectorApp({ dbPath });

    await request(collector.app)
      .post("/telemetry")
      .send({ vector: VALID_VECTOR, predicted_class: "benign", confidence: 0.5, timestamp: Date.now(), source_id: "host-a" });

    const res = await request(collector.app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok", events: 1, sources: 1 });

    collector.store.close();
    try { fs.unlinkSync(dbPath); } catch { /* already removed */ }
  });
});
