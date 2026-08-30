/**
 * Acceptance tests for `logsguardian config validate` (A14).
 *
 * Criteria:
 *   1. A freshly-initialised config passes validation.
 *   2. Corrupted mode value is reported as an error.
 *   3. threshold out of range is reported as an error.
 *   4. Invalid model selection is reported as an error.
 *   5. Non-positive timeoutMs is reported as an error.
 *   6. Non-existent modelDir is reported as an error.
 *   7. Existing modelDir with missing rf.onnx is reported as an error.
 *   8. Multiple errors are all reported (not short-circuited after first).
 *   9. modelDir with required model files passes validation.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runConfigInit } from "../src/cli/config-init";
import { runConfigSet } from "../src/cli/config-set";
import { runConfigValidate } from "../src/cli/config-validate";
import { CONFIG_FILENAME } from "../src/cli/guard";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-validate-"));
  const origCwd = process.cwd();
  try {
    process.chdir(dir);
    fn(dir);
  } finally {
    process.chdir(origCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function writeRawConfig(dir: string, content: string): void {
  const configPath = path.join(dir, CONFIG_FILENAME);
  fs.writeFileSync(configPath, content, "utf-8");
}

function expectValidateExits1(_dir: string): void {
  // Ensure Jest's module registry loads the latest file from disk.
  jest.resetModules();
  const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
    throw new Error(`process.exit(${code})`);
  });
  try {
    expect(() => runConfigValidate()).toThrow("process.exit(1)");
  } finally {
    mockExit.mockRestore();
  }
}

describe("config validate — valid config", () => {
  test("freshly-initialised config passes validation", () => {
    withTempDir(() => {
      runConfigInit();
      jest.resetModules();
      expect(() => runConfigValidate()).not.toThrow();
    });
  });

  test("valid mode='monitor' passes", () => {
    withTempDir(() => {
      runConfigInit();
      runConfigSet(["mode", "monitor"]);
      jest.resetModules();
      expect(() => runConfigValidate()).not.toThrow();
    });
  });

  test("valid threshold=0.5 passes", () => {
    withTempDir(() => {
      runConfigInit();
      runConfigSet(["threshold", "0.5"]);
      jest.resetModules();
      expect(() => runConfigValidate()).not.toThrow();
    });
  });
});

describe("config validate — invalid config", () => {
  test("invalid mode value fails", () => {
    withTempDir((dir) => {
      writeRawConfig(
        dir,
        `module.exports = { mode: 'log', threshold: 0.7, model: 'hybrid', timeoutMs: 50, dbPath: './logsguardian.db' };`
      );
      expectValidateExits1(dir);
    });
  });

  test("threshold > 1 fails", () => {
    withTempDir((dir) => {
      writeRawConfig(
        dir,
        `module.exports = { mode: 'block', threshold: 1.5, model: 'hybrid', timeoutMs: 50, dbPath: './logsguardian.db' };`
      );
      expectValidateExits1(dir);
    });
  });

  test("threshold < 0 fails", () => {
    withTempDir((dir) => {
      writeRawConfig(
        dir,
        `module.exports = { mode: 'block', threshold: -0.1, model: 'hybrid', timeoutMs: 50, dbPath: './logsguardian.db' };`
      );
      expectValidateExits1(dir);
    });
  });

  test("invalid model selection fails", () => {
    withTempDir((dir) => {
      writeRawConfig(
        dir,
        `module.exports = { mode: 'block', threshold: 0.7, model: 'bert', timeoutMs: 50, dbPath: './logsguardian.db' };`
      );
      expectValidateExits1(dir);
    });
  });

  test("timeoutMs=0 fails", () => {
    withTempDir((dir) => {
      writeRawConfig(
        dir,
        `module.exports = { mode: 'block', threshold: 0.7, model: 'hybrid', timeoutMs: 0, dbPath: './logsguardian.db' };`
      );
      expectValidateExits1(dir);
    });
  });

  test("non-existent modelDir fails", () => {
    withTempDir((dir) => {
      writeRawConfig(
        dir,
        `module.exports = { mode: 'block', threshold: 0.7, model: 'hybrid', timeoutMs: 50, dbPath: './logsguardian.db', modelDir: '/does/not/exist' };`
      );
      expectValidateExits1(dir);
    });
  });

  test("modelDir without rf.onnx fails when model requires RF", () => {
    withTempDir((dir) => {
      const modelDir = path.join(dir, "models");
      fs.mkdirSync(modelDir);
      // Create if.onnx but NOT rf.onnx; model='hybrid' needs both.
      fs.writeFileSync(path.join(modelDir, "if.onnx"), "stub");
      writeRawConfig(
        dir,
        `module.exports = { mode: 'block', threshold: 0.7, model: 'hybrid', timeoutMs: 50, dbPath: './logsguardian.db', modelDir: '${modelDir.replace(/\\/g, "\\\\")}' };`
      );
      expectValidateExits1(dir);
    });
  });

  test("modelDir with both onnx files passes when model='hybrid'", () => {
    withTempDir((dir) => {
      const modelDir = path.join(dir, "models");
      fs.mkdirSync(modelDir);
      fs.writeFileSync(path.join(modelDir, "rf.onnx"), "stub");
      fs.writeFileSync(path.join(modelDir, "if.onnx"), "stub");
      writeRawConfig(
        dir,
        `module.exports = { mode: 'block', threshold: 0.7, model: 'hybrid', timeoutMs: 50, dbPath: './logsguardian.db', modelDir: '${modelDir.replace(/\\/g, "\\\\")}' };`
      );
      jest.resetModules();
      expect(() => runConfigValidate()).not.toThrow();
    });
  });

  test("model='rf' only checks rf.onnx existence", () => {
    withTempDir((dir) => {
      const modelDir = path.join(dir, "models");
      fs.mkdirSync(modelDir);
      fs.writeFileSync(path.join(modelDir, "rf.onnx"), "stub");
      // No if.onnx — but model='rf' should not need it.
      writeRawConfig(
        dir,
        `module.exports = { mode: 'block', threshold: 0.7, model: 'rf', timeoutMs: 50, dbPath: './logsguardian.db', modelDir: '${modelDir.replace(/\\/g, "\\\\")}' };`
      );
      jest.resetModules();
      expect(() => runConfigValidate()).not.toThrow();
    });
  });

  test("multiple invalid fields are all reported (not short-circuited)", () => {
    withTempDir((dir) => {
      // mode invalid + threshold out of range — both should appear in output.
      writeRawConfig(
        dir,
        `module.exports = { mode: 'log', threshold: 2.0, model: 'hybrid', timeoutMs: 50, dbPath: './logsguardian.db' };`
      );
      const consoleSpy = jest.spyOn(console, "error").mockImplementation(() => undefined);
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      try {
        expect(() => runConfigValidate()).toThrow("process.exit(1)");
        const output = consoleSpy.mock.calls.map((c) => c.join(" ")).join("\n");
        expect(output).toMatch(/mode/);
        expect(output).toMatch(/threshold/);
      } finally {
        consoleSpy.mockRestore();
        mockExit.mockRestore();
      }
    });
  });
});
