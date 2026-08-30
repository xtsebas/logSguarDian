import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runConfigShow } from "../src/cli/config-show";
import { CONFIG_FILENAME } from "../src/cli/guard";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-test-"));
  const origCwd = process.cwd();
  try {
    process.chdir(dir);
    fn(dir);
  } finally {
    process.chdir(origCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function writeConfig(dir: string, body: string): void {
  fs.writeFileSync(path.join(dir, CONFIG_FILENAME), body, "utf-8");
}

describe("config show", () => {
  test("exits with code 1 when no config file exists", () => {
    withTempDir(() => {
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runConfigShow([])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("table format: prints all config keys", () => {
    withTempDir((dir) => {
      writeConfig(dir, `module.exports = { mode: 'block', timeoutMs: 50, dbPath: './lg.db' };`);
      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runConfigShow([]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      expect(output).toContain("mode");
      expect(output).toContain("block");
      expect(output).toContain("timeoutMs");
      expect(output).toContain("50");
      spy.mockRestore();
    });
  });

  test("--format json: outputs valid JSON matching config", () => {
    withTempDir((dir) => {
      writeConfig(dir, `module.exports = { mode: 'block', timeoutMs: 50, dbPath: './lg.db' };`);
      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runConfigShow(["--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      expect(parsed.mode).toBe("block");
      expect(parsed.timeoutMs).toBe(50);
      spy.mockRestore();
    });
  });

  test("--format json: reflects config file content exactly", () => {
    withTempDir((dir) => {
      writeConfig(dir, `module.exports = { mode: 'log', timeoutMs: 100, dbPath: './custom.db' };`);
      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runConfigShow(["--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      expect(parsed.mode).toBe("log");
      expect(parsed.timeoutMs).toBe(100);
      spy.mockRestore();
    });
  });

  test("table output: no module internals leaked", () => {
    withTempDir((dir) => {
      writeConfig(dir, `module.exports = { mode: 'block', timeoutMs: 50, dbPath: './lg.db' };`);
      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runConfigShow([]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      expect(output).not.toContain("module.exports");
      expect(output).not.toContain("[Function");
      expect(output).not.toContain("undefined");
      spy.mockRestore();
    });
  });
});
