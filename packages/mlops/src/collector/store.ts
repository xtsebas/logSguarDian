/**
 * SQLite store for accumulated telemetry vectors (Fase 1/2 of the CT/CI/CD
 * pipeline). Same better-sqlite3 pattern as packages/core's EventStore /
 * WebhookStore: CREATE TABLE IF NOT EXISTS + a flat MIGRATIONS array of
 * idempotent-by-catching-the-error ALTER TABLE statements.
 */
import Database from "better-sqlite3";
import * as path from "path";
import type { TelemetryPayload } from "./schema";

const DEFAULT_DB_PATH = path.join(process.cwd(), "mlops-telemetry.db");

const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS telemetry_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at     INTEGER NOT NULL,
    timestamp       INTEGER NOT NULL,
    source_id       TEXT    NOT NULL,
    predicted_class TEXT    NOT NULL,
    confidence      REAL    NOT NULL,
    vector          TEXT    NOT NULL
  )
`;

const MIGRATIONS: string[] = [];

export interface TelemetryRecord {
  id: number;
  received_at: number;
  timestamp: number;
  source_id: string;
  predicted_class: string;
  confidence: number;
  vector: number[];
}

export class TelemetryStore {
  private db: Database.Database;
  private insert: Database.Statement;

  constructor(dbPath: string = DEFAULT_DB_PATH) {
    this.db = new Database(dbPath);
    this.db.exec(CREATE_TABLE_SQL);
    for (const sql of MIGRATIONS) {
      try { this.db.exec(sql); } catch { /* column already exists — safe to ignore */ }
    }
    this.insert = this.db.prepare(`
      INSERT INTO telemetry_events
        (received_at, timestamp, source_id, predicted_class, confidence, vector)
      VALUES
        (@received_at, @timestamp, @source_id, @predicted_class, @confidence, @vector)
    `);
  }

  /** Inserts a telemetry event and returns its generated id. */
  add(payload: TelemetryPayload): number {
    const result = this.insert.run({
      received_at: Date.now(),
      timestamp: payload.timestamp,
      source_id: payload.source_id,
      predicted_class: payload.predicted_class,
      confidence: payload.confidence,
      vector: JSON.stringify(payload.vector),
    });
    return Number(result.lastInsertRowid);
  }

  /** Returns accumulated telemetry events, oldest first, up to `limit`. */
  list(limit = 10000): TelemetryRecord[] {
    const rows = this.db
      .prepare(`SELECT * FROM telemetry_events ORDER BY id ASC LIMIT ?`)
      .all(limit) as Array<Omit<TelemetryRecord, "vector"> & { vector: string }>;
    return rows.map((r) => ({ ...r, vector: JSON.parse(r.vector) as number[] }));
  }

  /** Total number of accumulated events, across all sources. */
  count(): number {
    const row = this.db.prepare(`SELECT COUNT(*) as c FROM telemetry_events`).get() as { c: number };
    return row.c;
  }

  /** Distinct source_id values seen so far — used to confirm multi-source accumulation (Fase 2). */
  sources(): string[] {
    const rows = this.db
      .prepare(`SELECT DISTINCT source_id FROM telemetry_events ORDER BY source_id ASC`)
      .all() as Array<{ source_id: string }>;
    return rows.map((r) => r.source_id);
  }

  close(): void {
    this.db.close();
  }
}
