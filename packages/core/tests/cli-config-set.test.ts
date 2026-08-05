/**
 * Acceptance tests for `logsguardian config set <key> <value>` (A14).
 *
 * Criteria:
 *   1. Valid key+value updates the config file on disk.
 *   2. Updated value is loadable via require() with the correct type.
 *   3. Other keys are preserved after a set operation.
 *   4. Invalid key exits with code 1.
 *   5. Invalid value exits with code 1.
 *   6. Missing key or value exits with code 1.
 *   7. threshold=0 and threshold=1 are accepted (boundary).
 *   8. threshold outside [0,1] is rejected.
 *   9. mode='log' is accepted as an input alias for 'monitor' (persisted as 'monitor').
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runConfigInit } from "../src/cli/config-init";
import { runConfigSet } from "../src/cli/config-set";
import { CONFIG_FILENAME } from "../src/cli/guard";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-set-"));
  const origCwd = process.cwd();
  try {
    process.chdir(dir);
    fn(dir);
  } finally {
    process.chdir(origCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function loadConfig(dir: string): Record<string, unknown> {
  // Jest has its own module registry separate from Node's require.cache.
  // resetModules() ensures the next require() reloads from disk.
  jest.resetModules();
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require(path.join(dir, CONFIG_FILENAME)) as Record<string, unknown>;
}

describe("config set — valid updates", () => {
  test("sets threshold to a float value", () => {
    withTempDir((dir) => {
      runConfigInit();
      runConfigSet(["threshold", "0.85"]);
      const config = loadConfig(dir);
      expect(config.threshold).toBe(0.85);
      expect(typeof config.threshold).toBe("number");
    });
  });

  test("sets mode to 'monitor'", () => {
    withTempDir((dir) => {
      runConfigInit();
      runConfigSet(["mode", "monitor"]);
      const config = loadConfig(dir);
      expect(config.mode).toBe("monitor");
    });
  });

  test("sets mode back to 'block'", () => {
    withTempDir((dir) => {
      runConfigInit();
      runConfigSet(["mode", "monitor"]);
      runConfigSet(["mode", "block"]);
      const config = loadConfig(dir);
      expect(config.mode).toBe("block");
    });
  });

  test("sets mode to 'log' — persisted as 'monitor' (input-only alias)", () => {
    withTempDir((dir) => {
      runConfigInit();
      runConfigSet(["mode", "log"]);
      const config = loadConfig(dir);
      expect(config.mode).toBe("monitor");
    });
  });

  test("sets model to 'rf'", () => {
    withTempDir((dir) => {
      runConfigInit();
      runConfigSet(["model", "rf"]);
      const config = loadConfig(dir);
      expect(config.model).toBe("rf");
    });
  });

  test("sets model to 'if'", () => {
    withTempDir((dir) => {
      runConfigInit();
      runConfigSet(["model", "if"]);
      const config = loadConfig(dir);
      expect(config.model).toBe("if");
    });
  });

  test("sets model to 'hybrid'", () => {
    withTempDir((dir) => {
      runConfigInit();
      runConfigSet(["model", "hybrid"]);
      const config = loadConfig(dir);
      expect(config.model).toBe("hybrid");
    });
  });

  test("other keys are preserved after setting threshold", () => {
    withTempDir((dir) => {
      runConfigInit();
      runConfigSet(["threshold", "0.60"]);
      const config = loadConfig(dir);
      expect(config.threshold).toBe(0.6);
      expect(config.mode).toBeDefined();
      expect(config.timeoutMs).toBeDefined();
      expect(config.dbPath).toBeDefined();
    });
  });

  test("threshold boundary: 0 is accepted", () => {
    withTempDir((dir) => {
      runConfigInit();
      runConfigSet(["threshold", "0"]);
      const config = loadConfig(dir);
      expect(config.threshold).toBe(0);
    });
  });

  test("threshold boundary: 1 is accepted", () => {
    withTempDir((dir) => {
      runConfigInit();
      runConfigSet(["threshold", "1"]);
      const config = loadConfig(dir);
      expect(config.threshold).toBe(1);
    });
  });
});

describe("config set — invalid input", () => {
  function expectExit1(fn: () => void): void {
    const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
      throw new Error(`process.exit(${code})`);
    });
    try {
      expect(fn).toThrow("process.exit(1)");
    } finally {
      mockExit.mockRestore();
    }
  }

  test("exits 1 for unknown key", () => {
    withTempDir(() => {
      runConfigInit();
      expectExit1(() => runConfigSet(["unknownKey", "value"]));
    });
  });

  test("exits 1 for an unrecognized mode value, error lists block/monitor/log", () => {
    withTempDir(() => {
      runConfigInit();
      const errSpy = jest.spyOn(console, "error").mockImplementation(() => {});
      expectExit1(() => runConfigSet(["mode", "foo"]));
      const output = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
      errSpy.mockRestore();
      expect(output).toContain("'block', 'monitor', or 'log'");
    });
  });

  test("exits 1 for threshold > 1", () => {
    withTempDir(() => {
      runConfigInit();
      expectExit1(() => runConfigSet(["threshold", "1.5"]));
    });
  });

  test("exits 1 for threshold < 0", () => {
    withTempDir(() => {
      runConfigInit();
      expectExit1(() => runConfigSet(["threshold", "-0.1"]));
    });
  });

  test("exits 1 for non-numeric threshold", () => {
    withTempDir(() => {
      runConfigInit();
      expectExit1(() => runConfigSet(["threshold", "high"]));
    });
  });

  test("exits 1 for model='bert' (not a supported model)", () => {
    withTempDir(() => {
      runConfigInit();
      expectExit1(() => runConfigSet(["model", "bert"]));
    });
  });

  test("exits 1 when key is missing", () => {
    withTempDir(() => {
      runConfigInit();
      expectExit1(() => runConfigSet([]));
    });
  });

  test("exits 1 when value is missing", () => {
    withTempDir(() => {
      runConfigInit();
      expectExit1(() => runConfigSet(["threshold"]));
    });
  });
});
