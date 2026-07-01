/**
 * Acceptance test for `logsguardian config init` (A14).
 *
 * Criteria:
 *   1. Generated file exists on disk.
 *   2. File is valid JS — require() does not throw.
 *   3. Required object has the expected keys with correct types.
 *   4. Running init a second time exits with code 1 (no overwrite).
 *   5. requireConfig() exits with code 1 when config is absent.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runConfigInit } from "../src/cli/config-init";
import { requireConfig, CONFIG_FILENAME } from "../src/cli/guard";

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

describe("config init", () => {
  test("creates logsguardian.config.js in cwd", () => {
    withTempDir((dir) => {
      runConfigInit();
      expect(fs.existsSync(path.join(dir, CONFIG_FILENAME))).toBe(true);
    });
  });

  test("generated file is valid JS and loadable via require()", () => {
    withTempDir((dir) => {
      runConfigInit();
      const configPath = path.join(dir, CONFIG_FILENAME);
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const config = require(configPath) as Record<string, unknown>;
      expect(typeof config).toBe("object");
      expect(config).not.toBeNull();
    });
  });

  test("generated config has required keys with correct types", () => {
    withTempDir((dir) => {
      runConfigInit();
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const config = require(path.join(dir, CONFIG_FILENAME)) as Record<string, unknown>;
      expect(typeof config.mode).toBe("string");
      expect(["block", "monitor"]).toContain(config.mode);
      expect(typeof config.timeoutMs).toBe("number");
      expect(config.timeoutMs).toBeGreaterThan(0);
      expect(typeof config.dbPath).toBe("string");
    });
  });

  test("exits with code 1 if config already exists", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runConfigInit()).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });
});

describe("requireConfig guard", () => {
  test("exits with code 1 when config is absent", () => {
    withTempDir(() => {
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => requireConfig()).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("returns the config object when file exists", () => {
    withTempDir((dir) => {
      runConfigInit();
      // Clear require cache so the module is loaded fresh.
      const configPath = path.join(dir, CONFIG_FILENAME);
      delete require.cache[configPath];
      const config = requireConfig();
      expect(config).toHaveProperty("mode");
      expect(config).toHaveProperty("timeoutMs");
      expect(config).toHaveProperty("dbPath");
    });
  });
});
