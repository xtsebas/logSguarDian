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
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,
    method      TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    verdict     TEXT    NOT NULL,
    predicted_class TEXT NOT NULL,
    confidence  REAL    NOT NULL,
    if_score    REAL    NOT NULL,
    elapsed_ms  REAL    NOT NULL
  )
`;

export class EventStore {
  private db: Database.Database;
  private insert: Database.Statement;

  constructor(dbPath: string = DEFAULT_DB_PATH) {
    this.db = new Database(dbPath);
    this.db.exec(CREATE_TABLE_SQL);
    this.insert = this.db.prepare(`
      INSERT INTO detection_events
        (timestamp, method, path, verdict, predicted_class, confidence, if_score, elapsed_ms)
      VALUES
        (@timestamp, @method, @path, @verdict, @predicted_class, @confidence, @if_score, @elapsed_ms)
    `);
  }

  log(event: DetectionEvent): void {
    this.insert.run(event);
  }

  close(): void {
    this.db.close();
  }
}
