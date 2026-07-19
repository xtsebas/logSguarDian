import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import Database from "better-sqlite3";
import { runConfigInit } from "../src/cli/config-init";
import { runWebhooksAdd } from "../src/cli/webhooks-add";
import { runWebhooksRemove } from "../src/cli/webhooks-remove";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-webhooks-remove-"));
  const origCwd = process.cwd();
  try {
    process.chdir(dir);
    fn(dir);
  } finally {
    process.chdir(origCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function rowIds(dir: string): number[] {
  const db = new Database(path.join(dir, "logsguardian.db"), { readonly: true });
  const rows = db.prepare("SELECT id FROM webhooks ORDER BY id ASC").all() as Array<{ id: number }>;
  db.close();
  return rows.map((r) => r.id);
}

describe("webhooks remove", () => {
  test("exits with code 1 when no id argument is given", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runWebhooksRemove([])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("exits with code 1 on a non-integer id", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runWebhooksRemove(["abc"])).toThrow("process.exit(1)");
      expect(() => runWebhooksRemove(["1.5"])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("exits with code 1 with a clear error when the id does not exist", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      const errSpy = jest.spyOn(console, "error").mockImplementation(() => {});
      expect(() => runWebhooksRemove(["1"])).toThrow("process.exit(1)");
      expect(errSpy.mock.calls.join(" ")).toContain("webhook #1 not found");
      errSpy.mockRestore();
      mockExit.mockRestore();
    });
  });

  test("the record disappears from the store after removal", () => {
    withTempDir((dir) => {
      runConfigInit();
      const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksAdd(["https://example.com/hook"]);
      expect(rowIds(dir)).toEqual([1]);

      runWebhooksRemove(["1"]);
      logSpy.mockRestore();

      expect(rowIds(dir)).toEqual([]);
    });
  });

  test("removing one webhook does not affect the others", () => {
    withTempDir((dir) => {
      runConfigInit();
      const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksAdd(["https://example.com/hook-a"]);
      runWebhooksAdd(["https://example.com/hook-b"]);
      runWebhooksAdd(["https://example.com/hook-c"]);
      expect(rowIds(dir)).toEqual([1, 2, 3]);

      runWebhooksRemove(["2"]);
      logSpy.mockRestore();

      expect(rowIds(dir)).toEqual([1, 3]);
    });
  });

  test("prints a confirmation naming the removed id", () => {
    withTempDir(() => {
      runConfigInit();
      const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksAdd(["https://example.com/hook"]);
      runWebhooksRemove(["1"]);
      const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
      logSpy.mockRestore();

      expect(output).toContain("Removed webhook #1");
    });
  });

  test("removing an already-removed id fails with 'not found', not a crash", () => {
    withTempDir(() => {
      runConfigInit();
      const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      runWebhooksAdd(["https://example.com/hook"]);
      runWebhooksRemove(["1"]);
      logSpy.mockRestore();

      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runWebhooksRemove(["1"])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });
});
