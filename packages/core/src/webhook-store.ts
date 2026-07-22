/**
 * SQLite registry of webhook destinations (F5, `webhooks` command group).
 *
 * Distinct from webhook.ts, which sends the HTTP POST at detection time.
 * This module only manages the `webhooks` table: registering, listing,
 * and (in a future task) testing/removing destinations. Lives in the same
 * database file as EventStore (store.ts) — one `logsguardian.db` per project.
 */
import Database from "better-sqlite3";
import * as path from "path";

const DEFAULT_DB_PATH = path.join(process.cwd(), "logsguardian.db");

export type WebhookStatus = "active" | "disabled";

export interface WebhookRecord {
  id: number;
  url: string;
  created_at: number;
  status: WebhookStatus;
}

const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS webhooks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'active'
  )
`;

export class WebhookStore {
  private db: Database.Database;

  constructor(dbPath: string = DEFAULT_DB_PATH) {
    this.db = new Database(dbPath);
    this.db.exec(CREATE_TABLE_SQL);
  }

  /** Inserts a new webhook destination and returns its generated id. */
  add(url: string): number {
    const result = this.db
      .prepare(`INSERT INTO webhooks (url, created_at, status) VALUES (@url, @created_at, 'active')`)
      .run({ url, created_at: Date.now() });
    return Number(result.lastInsertRowid);
  }

  /** Deletes a webhook by id. Returns true if a row was removed, false if the id did not exist. */
  remove(id: number): boolean {
    const result = this.db.prepare(`DELETE FROM webhooks WHERE id = @id`).run({ id });
    return result.changes > 0;
  }

  /** Fetches a single webhook by id, or undefined if it doesn't exist. */
  getById(id: number): WebhookRecord | undefined {
    return this.db.prepare(`SELECT id, url, created_at, status FROM webhooks WHERE id = ?`).get(id) as
      | WebhookRecord
      | undefined;
    
  /** Returns all registered webhooks, ordered by id ascending. */
  list(): WebhookRecord[] {
    return this.db.prepare(`SELECT id, url, created_at, status FROM webhooks ORDER BY id ASC`).all() as WebhookRecord[];
  }

  close(): void {
    this.db.close();
  }
}
