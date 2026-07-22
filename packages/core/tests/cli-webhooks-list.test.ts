import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import Database from "better-sqlite3";
import { runConfigInit } from "../src/cli/config-init";
import { runWebhooksAdd } from "../src/cli/webhooks-add";
import { runWebhooksList } from "../src/cli/webhooks-list";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-webhooks-list-"));
  const origCwd = process.cwd();
  try {
    process.chdir(dir);
    fn(dir);
  } finally {
    process.chdir(origCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Seeds a row directly via better-sqlite3, bypassing WebhookStore.add(). */
function insertDirect(dbPath: string, row: { url: string; created_at: number; status: string }): void {
  const db = new Database(dbPath);
  db.exec(
    `CREATE TABLE IF NOT EXISTS webhooks (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      url        TEXT    NOT NULL,
      created_at INTEGER NOT NULL,
      status     TEXT    NOT NULL DEFAULT 'active'
    )`
  );
  db.prepare(`INSERT INTO webhooks (url, created_at, status) VALUES (@url, @created_at, @status)`).run(row);
  db.close();
}

describe("webhooks list", () => {
  test("no database file: auto-creates it, shows empty message, exit 0", () => {
    withTempDir((dir) => {
      runConfigInit();
      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      expect(() => runWebhooksList([])).not.toThrow();
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("No webhooks registered.");
      expect(fs.existsSync(path.join(dir, "logsguardian.db"))).toBe(true);
    });
  });

  test("database exists but webhooks table is empty: shows message, exit 0", () => {
    withTempDir((dir) => {
      runConfigInit();
      // touch the db file with an unrelated table, so it exists but has no webhooks rows yet
      const db = new Database(path.join(dir, "logsguardian.db"));
      db.close();

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksList([]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("No webhooks registered.");
    });
  });

  test("single webhook: table shows id, url, created_at, status", () => {
    withTempDir(() => {
      runConfigInit();
      const addSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksAdd(["https://example.com/hook"]);
      addSpy.mockRestore();

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksList([]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("1");
      expect(output).toContain("active");
      expect(output).toContain("https://example.com/hook");
      expect(output).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
    });
  });

  test("multiple webhooks: all rows shown, ordered by id ascending", () => {
    withTempDir(() => {
      runConfigInit();
      const addSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksAdd(["https://a.example.com/hook"]);
      runWebhooksAdd(["https://b.example.com/hook"]);
      runWebhooksAdd(["https://c.example.com/hook"]);
      addSpy.mockRestore();

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksList([]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      const idxA = output.indexOf("a.example.com");
      const idxB = output.indexOf("b.example.com");
      const idxC = output.indexOf("c.example.com");
      expect(idxA).toBeGreaterThan(-1);
      expect(idxB).toBeGreaterThan(idxA);
      expect(idxC).toBeGreaterThan(idxB);
    });
  });

  test("--format json: valid array with id/url/created_at(ISO)/status fields", () => {
    withTempDir(() => {
      runConfigInit();
      const addSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksAdd(["https://example.com/hook"]);
      addSpy.mockRestore();

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksList(["--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed).toHaveLength(1);
      expect(parsed[0]).toEqual({
        id: 1,
        url: "https://example.com/hook",
        created_at: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
        status: "active",
      });
    });
  });

  test("--format json with no webhooks: outputs an empty array, exit 0", () => {
    withTempDir(() => {
      runConfigInit();
      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      expect(() => runWebhooksList(["--format", "json"])).not.toThrow();
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed).toEqual([]);
    });
  });

  test("reflects the store exactly: a row inserted directly via better-sqlite3 shows up as-is", () => {
    withTempDir((dir) => {
      runConfigInit();
      const dbPath = path.join(dir, "logsguardian.db");
      const createdAt = Date.UTC(2026, 5, 1, 12, 30, 0);
      insertDirect(dbPath, { url: "https://direct-insert.example.com/hook", created_at: createdAt, status: "active" });

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksList(["--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed).toEqual([
        {
          id: 1,
          url: "https://direct-insert.example.com/hook",
          created_at: new Date(createdAt).toISOString(),
          status: "active",
        },
      ]);
    });
  });
});
