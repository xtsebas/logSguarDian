import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runConfigInit } from "../src/cli/config-init";
import { runEndpointsProfile } from "../src/cli/endpoints-profile";
import { EventStore } from "../src/store";
import type { DetectionEvent } from "../src/types";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-endpoints-profile-"));
  const origCwd = process.cwd();
  try {
    process.chdir(dir);
    fn(dir);
  } finally {
    process.chdir(origCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** 2024-01-01T00:00:00Z plus `hour` hours, in ms. */
function atHour(hour: number): number {
  return Date.UTC(2024, 0, 1, hour, 0, 0);
}

const BASE: DetectionEvent = {
  timestamp: atHour(0),
  method: "GET",
  path: "/api/login",
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

function seed(dbPath: string, events: DetectionEvent[]): void {
  const store = new EventStore(dbPath);
  for (const e of events) store.log(e);
  store.close();
}

describe("endpoints profile", () => {
  test("exits with code 1 when no route argument is given", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runEndpointsProfile([])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("exits with code 1 when no database file exists", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runEndpointsProfile(["/api/login"])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("--format json: aggregates attack types, hourly distribution, and IPs for the given route only", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, predicted_class: "sqli", client_ip: "203.0.113.5", timestamp: atHour(3) },
        { ...BASE, predicted_class: "sqli", client_ip: "203.0.113.5", timestamp: atHour(3) },
        { ...BASE, predicted_class: "xss", client_ip: "198.51.100.20", timestamp: atHour(14) },
        {
          ...BASE,
          verdict: "pass_anomaly",
          predicted_class: "benign",
          is_anomaly: true,
          client_ip: "198.51.100.21",
          timestamp: atHour(14),
        },
        // Different route — must not leak into /api/login's profile.
        { ...BASE, path: "/api/users", client_ip: "9.9.9.9" },
        // 'pass' verdict — not an incident, must be excluded.
        { ...BASE, verdict: "pass", predicted_class: "benign", timestamp: atHour(3) },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsProfile(["/api/login", "--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed.path).toBe("/api/login");
      expect(parsed.total_incidents).toBe(4);
      expect(parsed.block_count).toBe(3);
      expect(parsed.pass_anomaly_count).toBe(1);

      expect(parsed.attack_types).toEqual(
        expect.arrayContaining([
          { predicted_class: "sqli", count: 2 },
          { predicted_class: "xss", count: 1 },
          { predicted_class: "benign", count: 1 },
        ])
      );

      expect(parsed.hourly_distribution).toEqual(
        expect.arrayContaining([
          { hour: 3, count: 2 },
          { hour: 14, count: 2 },
        ])
      );

      expect(parsed.top_source_ips).toEqual(
        expect.arrayContaining([
          { client_ip: "203.0.113.5", count: 2 },
          { client_ip: "198.51.100.20", count: 1 },
          { client_ip: "198.51.100.21", count: 1 },
        ])
      );

      // 198.51.100.20 and .21 share the /24 -> combined count 2.
      expect(parsed.source_ranges).toEqual(
        expect.arrayContaining([
          { client_ip: "203.0.113.0/24", count: 2 },
          { client_ip: "198.51.100.0/24", count: 2 },
        ])
      );
    });
  });

  test("--method filters the profile to a single HTTP method", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, method: "GET" },
        { ...BASE, method: "POST" },
        { ...BASE, method: "POST" },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsProfile(["/api/login", "--method", "post", "--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed.total_incidents).toBe(2);
      expect(parsed.methods).toEqual([{ method: "POST", count: 2 }]);
    });
  });

  test("table output: shows a friendly message when the route has no incidents", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [{ ...BASE, verdict: "pass" }]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsProfile(["/api/login"]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("No detection events found for this route.");
    });
  });

  test("table output: prints attack types and source IPs", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, predicted_class: "sqli", client_ip: "203.0.113.5" },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsProfile(["/api/login"]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("/api/login");
      expect(output).toContain("sqli");
      expect(output).toContain("203.0.113.5");
      expect(output).toContain("203.0.113.0/24");
    });
  });
});
