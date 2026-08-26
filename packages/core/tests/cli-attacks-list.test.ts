import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runConfigInit } from "../src/cli/config-init";
import { runAttacksList } from "../src/cli/attacks-list";
import { EventStore } from "../src/store";
import type { DetectionEvent } from "../src/types";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-attacks-list-"));
  const origCwd = process.cwd();
  try {
    process.chdir(dir);
    fn(dir);
  } finally {
    process.chdir(origCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const BASE: DetectionEvent = {
  timestamp: 1_700_000_000_000,
  method: "GET",
  path: "/api/users",
  query_string: "",
  user_agent: "test-agent",
  client_ip: "203.0.113.5",
  verdict: "block",
  predicted_class: "sqli",
  confidence: 0.9,
  if_score: 0.02,
  is_anomaly: false,
  webhook_sent: false,
  elapsed_ms: 1.0,
};

/** Seeds a fresh EventStore at dbPath with the given events — stands in for a "store mock". */
function seed(dbPath: string, events: DetectionEvent[]): void {
  const store = new EventStore(dbPath);
  for (const e of events) store.log(e);
  store.close();
}

describe("attacks list", () => {
  test("exits with code 1 when no database file exists", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runAttacksList([])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("--format json: total_count and last_detected are correct per attack type", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, predicted_class: "sqli", timestamp: 1_000 },
        { ...BASE, predicted_class: "sqli", timestamp: 3_000 },
        { ...BASE, predicted_class: "sqli", timestamp: 2_000 },
        { ...BASE, predicted_class: "xss", timestamp: 5_000 },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksList(["--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed).toEqual(
        expect.arrayContaining([
          { predicted_class: "sqli", total_count: 3, last_detected: 3_000 },
          { predicted_class: "xss", total_count: 1, last_detected: 5_000 },
        ])
      );
      expect(parsed).toHaveLength(2);
    });
  });

  test("excludes 'benign' — it is not an attack type", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, predicted_class: "benign", verdict: "pass" },
        { ...BASE, predicted_class: "benign", verdict: "pass_anomaly", is_anomaly: true },
        { ...BASE, predicted_class: "cmdi" },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksList(["--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed).toEqual([{ predicted_class: "cmdi", total_count: 1, last_detected: BASE.timestamp }]);
    });
  });

  test("includes low-confidence classifications that were never blocked (catalogs by predicted_class, not verdict)", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        // RF classified as sqli but confidence was below threshold -> verdict 'pass', still an attack type seen.
        { ...BASE, predicted_class: "sqli", verdict: "pass", confidence: 0.4 },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksList(["--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed).toEqual([{ predicted_class: "sqli", total_count: 1, last_detected: BASE.timestamp }]);
    });
  });

  test("table output: sorted by total_count descending, ISO timestamp shown", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, predicted_class: "xss", timestamp: 1_700_000_000_000 },
        { ...BASE, predicted_class: "sqli", timestamp: 1_700_000_001_000 },
        { ...BASE, predicted_class: "sqli", timestamp: 1_700_000_002_000 },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksList([]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      const sqliIdx = output.indexOf("sqli");
      const xssIdx = output.indexOf("xss");
      expect(sqliIdx).toBeGreaterThan(-1);
      expect(xssIdx).toBeGreaterThan(-1);
      expect(sqliIdx).toBeLessThan(xssIdx);
      expect(output).toContain(new Date(1_700_000_002_000).toISOString());
    });
  });

  test("table output: shows a friendly message when no attack types have been classified", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [{ ...BASE, predicted_class: "benign", verdict: "pass" }]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksList([]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("No attack types classified yet.");
      // The dbPath-mismatch hint (guard.ts's dbPathMismatchHint()) — added after
      // this exact failure mode cost real debugging time against a live app
      // whose dbPath diverged from logsguardian.config.js's. Must name the
      // actual resolved dbPath, not just a generic "check your config" message.
      expect(output).toContain(path.join(dir, "logsguardian.db"));
      expect(output).toContain("logsguardian(options)");
    });
  });
});
