/**
 * SQLite event log (F5.5).
 *
 * Writes DetectionEvents synchronously via better-sqlite3. The call is cheap
 * (~0.1 ms per INSERT on a local DB) and happens after next() is called, so
 * it does not block the request critical path.
 */
import Database from "better-sqlite3";
import * as path from "path";
import type { DetectionEvent } from "./types";

const DEFAULT_DB_PATH = path.join(process.cwd(), "logsguardian.db");

const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS detection_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       INTEGER NOT NULL,
    method          TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    query_string    TEXT    NOT NULL DEFAULT '',
    user_agent      TEXT    NOT NULL DEFAULT '',
    verdict         TEXT    NOT NULL,
    predicted_class TEXT    NOT NULL,
    confidence      REAL    NOT NULL,
    if_score        REAL    NOT NULL,
    is_anomaly      INTEGER NOT NULL DEFAULT 0,
    webhook_sent    INTEGER NOT NULL DEFAULT 0,
    elapsed_ms      REAL    NOT NULL
  )
`;

/** Columns added after v0.1.0 — applied once on startup for existing databases. */
const MIGRATIONS: string[] = [
  `ALTER TABLE detection_events ADD COLUMN query_string TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE detection_events ADD COLUMN user_agent   TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE detection_events ADD COLUMN is_anomaly   INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE detection_events ADD COLUMN webhook_sent INTEGER NOT NULL DEFAULT 0`,
];

export class EventStore {
  private db: Database.Database;
  private insert: Database.Statement;

  constructor(dbPath: string = DEFAULT_DB_PATH) {
    this.db = new Database(dbPath);
    this.db.exec(CREATE_TABLE_SQL);
    for (const sql of MIGRATIONS) {
      try { this.db.exec(sql); } catch { /* column already exists — safe to ignore */ }
    }
    this.insert = this.db.prepare(`
      INSERT INTO detection_events
        (timestamp, method, path, query_string, user_agent,
         verdict, predicted_class, confidence, if_score,
         is_anomaly, webhook_sent, elapsed_ms)
      VALUES
        (@timestamp, @method, @path, @query_string, @user_agent,
         @verdict, @predicted_class, @confidence, @if_score,
         @is_anomaly, @webhook_sent, @elapsed_ms)
    `);
  }

  log(event: DetectionEvent): void {
    this.insert.run({
      ...event,
      is_anomaly: event.is_anomaly ? 1 : 0,
      webhook_sent: event.webhook_sent ? 1 : 0,
    });
  }

  close(): void {
    this.db.close();
  }
}
