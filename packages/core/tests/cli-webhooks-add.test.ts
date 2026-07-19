import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import Database from "better-sqlite3";
import { runConfigInit } from "../src/cli/config-init";
import { runWebhooksAdd } from "../src/cli/webhooks-add";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-webhooks-add-"));
  const origCwd = process.cwd();
  try {
    process.chdir(dir);
    fn(dir);
  } finally {
    process.chdir(origCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("webhooks add", () => {
  test("exits with code 1 when no URL argument is given", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runWebhooksAdd([])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("exits with code 1 on a syntactically invalid URL", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runWebhooksAdd(["not-a-url"])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("exits with code 1 when the URL is not HTTPS", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runWebhooksAdd(["http://example.com/hook"])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("rejects non-HTTP(S) schemes too (ftp, file, etc.)", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runWebhooksAdd(["ftp://example.com/hook"])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("a valid HTTPS URL persists in the SQLite store with a generated id and created_at", () => {
    withTempDir((dir) => {
      runConfigInit();
      const t0 = Date.now();

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksAdd(["https://hooks.slack.com/services/T00/B00/XXX"]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("https://hooks.slack.com/services/T00/B00/XXX");

      const db = new Database(path.join(dir, "logsguardian.db"), { readonly: true });
      const row = db.prepare("SELECT * FROM webhooks WHERE id = 1").get() as Record<string, unknown>;
      db.close();

      expect(row.url).toBe("https://hooks.slack.com/services/T00/B00/XXX");
      expect(row.status).toBe("active");
      expect(row.created_at as number).toBeGreaterThanOrEqual(t0);
      expect(row.created_at as number).toBeLessThanOrEqual(Date.now());
    });
  });

  test("prints the assigned id in the confirmation output", () => {
    withTempDir(() => {
      runConfigInit();
      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksAdd(["https://example.com/hook"]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toMatch(/#1\b/);
    });
  });

  test("successive calls assign incrementing ids", () => {
    withTempDir((dir) => {
      runConfigInit();
      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksAdd(["https://example.com/hook-a"]);
      runWebhooksAdd(["https://example.com/hook-b"]);
      spy.mockRestore();

      const db = new Database(path.join(dir, "logsguardian.db"), { readonly: true });
      const rows = db.prepare("SELECT id, url FROM webhooks ORDER BY id ASC").all() as Array<{
        id: number;
        url: string;
      }>;
      db.close();

      expect(rows).toEqual([
        { id: 1, url: "https://example.com/hook-a" },
        { id: 2, url: "https://example.com/hook-b" },
      ]);
    });
  });

  test("creates the database file if it does not exist yet", () => {
    withTempDir((dir) => {
      runConfigInit();
      expect(fs.existsSync(path.join(dir, "logsguardian.db"))).toBe(false);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksAdd(["https://example.com/hook"]);
      spy.mockRestore();

      expect(fs.existsSync(path.join(dir, "logsguardian.db"))).toBe(true);
    });
  });
});
