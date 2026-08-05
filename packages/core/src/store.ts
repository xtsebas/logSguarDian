/**
 * SQLite event log (F5.5).
 *
 * Writes DetectionEvents synchronously via better-sqlite3. The call is cheap
 * (~0.1 ms per INSERT on a local DB) and happens after next() is called, so
 * it does not block the request critical path.
 *
 * IF's inference (~1ms) is no longer waited for before logging (see
 * middleware.ts's async log-patch design) — most rows are written with
 * if_score=0 and get patched moments later via patchIfScore() once IF's
 * worker actually replies. A late anomalous score retroactively flips a
 * 'pass' verdict to 'pass_anomaly' (and webhook_sent, if a webhook fires
 * for it) — never a 'block' or 'timeout' verdict, which are unaffected.
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
    client_ip       TEXT    NOT NULL DEFAULT '',
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
  `ALTER TABLE detection_events ADD COLUMN client_ip    TEXT NOT NULL DEFAULT ''`,
];

export class EventStore {
  private db: Database.Database;
  private insert: Database.Statement;
  private patchIf: Database.Statement;

  constructor(dbPath: string = DEFAULT_DB_PATH) {
    this.db = new Database(dbPath);
    this.db.exec(CREATE_TABLE_SQL);
    for (const sql of MIGRATIONS) {
      try { this.db.exec(sql); } catch { /* column already exists — safe to ignore */ }
    }
    this.insert = this.db.prepare(`
      INSERT INTO detection_events
        (timestamp, method, path, query_string, user_agent, client_ip,
         verdict, predicted_class, confidence, if_score,
         is_anomaly, webhook_sent, elapsed_ms)
      VALUES
        (@timestamp, @method, @path, @query_string, @user_agent, @client_ip,
         @verdict, @predicted_class, @confidence, @if_score,
         @is_anomaly, @webhook_sent, @elapsed_ms)
    `);
    // verdict only ever flips 'pass' -> 'pass_anomaly' here; 'block'/'timeout' rows
    // are untouched regardless of IF's late score, IF has no blocking authority.
    // webhook_sent only flips if the caller actually sent one (@webhook_fired) —
    // is_anomaly alone doesn't imply a webhook was configured/dispatched.
    this.patchIf = this.db.prepare(`
      UPDATE detection_events
      SET if_score = @if_score,
          is_anomaly = @is_anomaly,
          verdict = CASE WHEN verdict = 'pass' AND @is_anomaly = 1
                         THEN 'pass_anomaly' ELSE verdict END,
          webhook_sent = CASE WHEN @webhook_fired = 1 THEN 1 ELSE webhook_sent END
      WHERE id = @id
    `);
  }

  /** Returns the inserted row's id, needed by patchIfScore() for late-arriving IF scores. */
  log(event: DetectionEvent): number {
    const info = this.insert.run({
      ...event,
      is_anomaly: event.is_anomaly ? 1 : 0,
      webhook_sent: event.webhook_sent ? 1 : 0,
    });
    return Number(info.lastInsertRowid);
  }

  /**
   * Patches a previously-logged row with IF's late-arriving score. Only
   * flips verdict/webhook_sent from 'pass' to 'pass_anomaly' — 'block' and
   * 'timeout' rows keep their original verdict, IF never has blocking
   * authority (decision-policy.md §3).
   */
  patchIfScore(eventId: number, ifScore: number, isAnomaly: boolean, webhookFired: boolean): void {
    this.patchIf.run({
      id: eventId,
      if_score: ifScore,
      is_anomaly: isAnomaly ? 1 : 0,
      webhook_fired: webhookFired ? 1 : 0,
    });
  }

  close(): void {
    this.db.close();
  }
}
