import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import Database from "better-sqlite3";
import { EventStore } from "../src/store";
import type { DetectionEvent } from "../src/types";

const SAMPLE: DetectionEvent = {
  timestamp: 1_700_000_000_000,
  method: "GET",
  path: "/api/users",
  query_string: "id=1' OR '1'='1'--",
  user_agent: "Mozilla/5.0 (test)",
  verdict: "block",
  predicted_class: "sqli",
  confidence: 0.95,
  if_score: 0.02,
  is_anomaly: false,
  webhook_sent: true,
  elapsed_ms: 12.5,
};

function tmpDb(): string {
  return path.join(
    os.tmpdir(),
    `lg-store-${Date.now()}-${Math.random().toString(36).slice(2)}.db`
  );
}

describe("EventStore", () => {
  let dbPath: string;

  beforeEach(() => { dbPath = tmpDb(); });
  afterEach(() => { try { fs.unlinkSync(dbPath); } catch { /* already removed */ } });

  test("persists all DetectionEvent fields on log()", () => {
    const store = new EventStore(dbPath);
    store.log(SAMPLE);
    store.close();

    const db = new Database(dbPath, { readonly: true });
    const row = db
      .prepare("SELECT * FROM detection_events WHERE id = 1")
      .get() as Record<string, unknown>;
    db.close();

    expect(row.method).toBe("GET");
    expect(row.path).toBe("/api/users");
    expect(row.query_string).toBe("id=1' OR '1'='1'--");
    expect(row.user_agent).toBe("Mozilla/5.0 (test)");
    expect(row.verdict).toBe("block");
    expect(row.predicted_class).toBe("sqli");
    expect(row.confidence).toBeCloseTo(0.95);
    expect(row.if_score).toBeCloseTo(0.02);
    expect(row.elapsed_ms).toBeCloseTo(12.5);
  });

  test("is_anomaly=false stores as 0 in SQLite", () => {
    const store = new EventStore(dbPath);
    store.log({ ...SAMPLE, is_anomaly: false });
    store.close();

    const db = new Database(dbPath, { readonly: true });
    const row = db
      .prepare("SELECT is_anomaly FROM detection_events WHERE id = 1")
      .get() as { is_anomaly: number };
    db.close();
    expect(row.is_anomaly).toBe(0);
  });

  test("is_anomaly=true stores as 1 in SQLite", () => {
    const store = new EventStore(dbPath);
    store.log({ ...SAMPLE, is_anomaly: true, verdict: "pass_anomaly" });
    store.close();

    const db = new Database(dbPath, { readonly: true });
    const row = db
      .prepare("SELECT is_anomaly FROM detection_events WHERE id = 1")
      .get() as { is_anomaly: number };
    db.close();
    expect(row.is_anomaly).toBe(1);
  });

  test("webhook_sent booleans store as 1 and 0 in SQLite", () => {
    const store = new EventStore(dbPath);
    store.log({ ...SAMPLE, webhook_sent: true });
    store.log({ ...SAMPLE, webhook_sent: false });
    store.close();

    const db = new Database(dbPath, { readonly: true });
    const rows = db
      .prepare("SELECT webhook_sent FROM detection_events ORDER BY id ASC")
      .all() as Array<{ webhook_sent: number }>;
    db.close();
    expect(rows[0].webhook_sent).toBe(1);
    expect(rows[1].webhook_sent).toBe(0);
  });

  test("migration adds new columns to a legacy DB schema without error", () => {
    const legacyDb = new Database(dbPath);
    legacyDb.exec(`
      CREATE TABLE detection_events (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       INTEGER NOT NULL,
        method          TEXT    NOT NULL,
        path            TEXT    NOT NULL,
        verdict         TEXT    NOT NULL,
        predicted_class TEXT    NOT NULL,
        confidence      REAL    NOT NULL,
        if_score        REAL    NOT NULL,
        elapsed_ms      REAL    NOT NULL
      )
    `);
    legacyDb.close();

    const store = new EventStore(dbPath);
    expect(() => store.log(SAMPLE)).not.toThrow();
    store.close();

    const db = new Database(dbPath, { readonly: true });
    const row = db
      .prepare(
        "SELECT query_string, user_agent, is_anomaly, webhook_sent FROM detection_events WHERE id = 1"
      )
      .get() as Record<string, unknown>;
    db.close();
    expect(row.query_string).toBe("id=1' OR '1'='1'--");
    expect(row.user_agent).toBe("Mozilla/5.0 (test)");
    expect(row.is_anomaly).toBe(0);
    expect(row.webhook_sent).toBe(1);
  });
});
