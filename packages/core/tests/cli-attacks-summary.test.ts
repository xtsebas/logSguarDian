import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runConfigInit } from "../src/cli/config-init";
import { runAttacksSummary } from "../src/cli/attacks-summary";
import { EventStore } from "../src/store";
import type { DetectionEvent } from "../src/types";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-attacks-summary-"));
  const origCwd = process.cwd();
  try {
    process.chdir(dir);
    fn(dir);
  } finally {
    process.chdir(origCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** 2026-07-<day>T00:00:00Z, in ms. */
function onDay(day: number): number {
  return Date.UTC(2026, 6, day, 0, 0, 0);
}

const BASE: DetectionEvent = {
  timestamp: onDay(10),
  method: "POST",
  path: "/api/login",
  query_string: "",
  user_agent: "test-agent",
  verdict: "block",
  predicted_class: "sqli",
  confidence: 0.9,
  if_score: 0.02,
  is_anomaly: false,
  webhook_sent: false,
  elapsed_ms: 1.0,
};

function seed(dbPath: string, events: DetectionEvent[]): void {
  const store = new EventStore(dbPath);
  for (const e of events) store.log(e);
  store.close();
}

describe("attacks summary", () => {
  test("exits with code 1 when no database file exists", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runAttacksSummary([])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("exits with code 1 on an invalid --from date", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [BASE]);
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runAttacksSummary(["--from", "not-a-date"])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("exits with code 1 when --from is after --to", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [BASE]);
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runAttacksSummary(["--from", "2026-07-20", "--to", "2026-07-01"])).toThrow(
        "process.exit(1)"
      );
      mockExit.mockRestore();
    });
  });

  test("--format json: severity maps from verdict (block=high, pass_anomaly=medium, pass=low)", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, verdict: "block", predicted_class: "sqli" },
        { ...BASE, verdict: "block", predicted_class: "sqli" },
        { ...BASE, verdict: "pass_anomaly", predicted_class: "xss", is_anomaly: true },
        { ...BASE, verdict: "pass", predicted_class: "cmdi", confidence: 0.3 },
        // benign is never an attack type, regardless of verdict.
        { ...BASE, verdict: "pass_anomaly", predicted_class: "benign", is_anomaly: true },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksSummary(["--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed).toEqual(
        expect.arrayContaining([
          { path: "/api/login", method: "POST", severity: "high", predicted_class: "sqli", count: 2 },
          { path: "/api/login", method: "POST", severity: "medium", predicted_class: "xss", count: 1 },
          { path: "/api/login", method: "POST", severity: "low", predicted_class: "cmdi", count: 1 },
        ])
      );
      expect(parsed).toHaveLength(3);
    });
  });

  test("--from/--to filters by date range, inclusive of both boundaries", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, timestamp: onDay(5), predicted_class: "sqli" }, // before range
        { ...BASE, timestamp: onDay(10), predicted_class: "xss" }, // on --from boundary
        { ...BASE, timestamp: onDay(15), predicted_class: "cmdi" }, // inside range
        { ...BASE, timestamp: onDay(31) + 999, predicted_class: "path_traversal" }, // on --to boundary (end of day)
        { ...BASE, timestamp: Date.UTC(2026, 7, 1, 0, 0, 1), predicted_class: "sqli" }, // after range
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksSummary(["--from", "2026-07-10", "--to", "2026-07-31", "--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      const classes = parsed.map((r: { predicted_class: string }) => r.predicted_class).sort();
      expect(classes).toEqual(["cmdi", "path_traversal", "xss"]);
    });
  });

  test("--endpoint filters to a single route", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, path: "/api/login", predicted_class: "sqli" },
        { ...BASE, path: "/api/users", method: "GET", predicted_class: "xss" },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksSummary(["--endpoint", "/api/login", "--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed).toHaveLength(1);
      expect(parsed[0].path).toBe("/api/login");
    });
  });

  test("table output: grouped by endpoint, severity ordered high > medium > low", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, path: "/api/login", verdict: "pass", predicted_class: "cmdi", confidence: 0.3 },
        { ...BASE, path: "/api/login", verdict: "block", predicted_class: "sqli" },
        { ...BASE, path: "/api/users", method: "GET", verdict: "pass_anomaly", predicted_class: "xss", is_anomaly: true },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksSummary([]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("/api/login (POST)");
      expect(output).toContain("/api/users (GET)");
      const highIdx = output.indexOf("HIGH");
      const lowIdx = output.indexOf("LOW");
      expect(highIdx).toBeGreaterThan(-1);
      expect(lowIdx).toBeGreaterThan(-1);
      expect(highIdx).toBeLessThan(lowIdx);
    });
  });

  test("table output: shows a friendly message when nothing matches the filters", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [{ ...BASE, verdict: "pass", predicted_class: "benign" }]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksSummary([]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("No attack types classified in this range.");
    });
  });
});
