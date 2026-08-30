import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runConfigInit } from "../src/cli/config-init";
import { runEndpointsTop } from "../src/cli/endpoints-top";
import { CONFIG_FILENAME } from "../src/cli/guard";
import { EventStore } from "../src/store";
import type { DetectionEvent } from "../src/types";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-endpoints-top-"));
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

/** Seeds a fresh EventStore at dbPath with the given events, then closes it. */
function seed(dbPath: string, events: DetectionEvent[]): void {
  const store = new EventStore(dbPath);
  for (const e of events) store.log(e);
  store.close();
}

describe("endpoints top", () => {
  test("exits with code 1 when no database file exists", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runEndpointsTop([])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("table output: ranks routes by incident_count descending", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, path: "/api/login", method: "POST", confidence: 0.95 },
        { ...BASE, path: "/api/login", method: "POST", confidence: 0.95 },
        { ...BASE, path: "/api/login", method: "POST", confidence: 0.95 },
        { ...BASE, path: "/api/users", method: "GET", confidence: 0.8 },
        { ...BASE, path: "/api/users", method: "GET", confidence: 0.8 },
        { ...BASE, path: "/health", method: "GET", verdict: "pass", confidence: 0.1 },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsTop([]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      const loginIdx = output.indexOf("/api/login");
      const usersIdx = output.indexOf("/api/users");
      expect(loginIdx).toBeGreaterThan(-1);
      expect(usersIdx).toBeGreaterThan(-1);
      expect(loginIdx).toBeLessThan(usersIdx);
      // 'pass' verdict is not an incident — /health must not appear.
      expect(output).not.toContain("/health");
      expect(output).toContain("POST");
      expect(output).toContain("3");
    });
  });

  test("--format json: risk_score = incident_count * avg_confidence, rounded to 2 decimals", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, path: "/api/login", method: "POST", confidence: 0.9 },
        { ...BASE, path: "/api/login", method: "POST", confidence: 0.8 },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsTop(["--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed).toHaveLength(1);
      expect(parsed[0].path).toBe("/api/login");
      expect(parsed[0].method).toBe("POST");
      expect(parsed[0].incident_count).toBe(2);
      // avg_confidence = (0.9 + 0.8) / 2 = 0.85; risk_score = 2 * 0.85 = 1.7
      expect(parsed[0].risk_score).toBeCloseTo(1.7);
    });
  });

  test("pass_anomaly verdicts count as incidents alongside block", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, path: "/api/upload", method: "POST", verdict: "block", confidence: 0.9 },
        { ...BASE, path: "/api/upload", method: "POST", verdict: "pass_anomaly", confidence: 0.3, is_anomaly: true },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsTop(["--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed[0].incident_count).toBe(2);
    });
  });

  test("--limit caps the number of rows returned", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, path: "/a", method: "GET" },
        { ...BASE, path: "/b", method: "GET" },
        { ...BASE, path: "/c", method: "GET" },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsTop(["--format", "json", "--limit", "2"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed).toHaveLength(2);
    });
  });

  test("table output: shows a friendly message when there are no incidents", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, verdict: "pass" },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsTop([]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("No detection events found.");
    });
  });
});
