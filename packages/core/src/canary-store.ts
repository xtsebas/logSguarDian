/**
 * SQLite log of canary/candidate-model shadow comparisons (Fase 7).
 *
 * Distinct from store.ts (production detection log) — this module only
 * manages the `canary_comparisons` table, written after the real response
 * has already been sent (middleware.ts's handleCanaryMessage, mirroring
 * handleIfMessage's async log-patch pattern exactly). Lives in the same
 * database file as EventStore/WebhookStore — one `logsguardian.db` per
 * project, same convention as webhook-store.ts.
 */
import Database from "better-sqlite3";
import * as path from "path";
import type { CanaryComparison } from "./types";

const DEFAULT_DB_PATH = path.join(process.cwd(), "logsguardian.db");

const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS canary_comparisons (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id                  INTEGER NOT NULL,
    timestamp                   INTEGER NOT NULL,
    production_verdict          TEXT    NOT NULL,
    production_predicted_class  TEXT    NOT NULL,
    production_confidence       REAL    NOT NULL,
    canary_verdict              TEXT    NOT NULL,
    canary_predicted_class      TEXT    NOT NULL,
    canary_confidence           REAL    NOT NULL,
    verdict_match                INTEGER NOT NULL,
    class_match                  INTEGER NOT NULL,
    confidence_delta             REAL    NOT NULL
  )
`;

export interface CanaryComparisonRecord extends CanaryComparison {
  id: number;
}

export class CanaryStore {
  private db: Database.Database;
  private insert: Database.Statement;

  constructor(dbPath: string = DEFAULT_DB_PATH) {
    this.db = new Database(dbPath);
    this.db.exec(CREATE_TABLE_SQL);
    this.insert = this.db.prepare(`
      INSERT INTO canary_comparisons
        (request_id, timestamp, production_verdict, production_predicted_class,
         production_confidence, canary_verdict, canary_predicted_class,
         canary_confidence, verdict_match, class_match, confidence_delta)
      VALUES
        (@request_id, @timestamp, @production_verdict, @production_predicted_class,
         @production_confidence, @canary_verdict, @canary_predicted_class,
         @canary_confidence, @verdict_match, @class_match, @confidence_delta)
    `);
  }

  /** Returns the inserted row's id. */
  log(comparison: CanaryComparison): number {
    const info = this.insert.run({
      ...comparison,
      verdict_match: comparison.verdict_match ? 1 : 0,
      class_match: comparison.class_match ? 1 : 0,
    });
    return Number(info.lastInsertRowid);
  }

  /** Returns all comparisons, oldest first — used by the corpus-replay report. */
  list(): CanaryComparisonRecord[] {
    return this.db
      .prepare(`SELECT * FROM canary_comparisons ORDER BY id ASC`)
      .all() as CanaryComparisonRecord[];
  }

  close(): void {
    this.db.close();
  }
}
