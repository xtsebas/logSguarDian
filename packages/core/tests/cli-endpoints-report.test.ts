import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runConfigInit } from "../src/cli/config-init";
import { runEndpointsReport } from "../src/cli/endpoints-report";
import { EventStore } from "../src/store";
import type { DetectionEvent } from "../src/types";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-endpoints-report-"));
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

function seed(dbPath: string, events: DetectionEvent[]): void {
  const store = new EventStore(dbPath);
  for (const e of events) store.log(e);
  store.close();
}

describe("endpoints report", () => {
  test("exits with code 1 when no database file exists", () => {
    withTempDir(() => {
      runConfigInit();
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runEndpointsReport([])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("exits with code 1 on an unsupported --format value", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [BASE]);
      const mockExit = jest.spyOn(process, "exit").mockImplementation((code) => {
        throw new Error(`process.exit(${code})`);
      });
      expect(() => runEndpointsReport(["--format", "xml"])).toThrow("process.exit(1)");
      mockExit.mockRestore();
    });
  });

  test("--format json: output is valid, parseable JSON covering all routes", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, path: "/api/login", method: "POST", predicted_class: "sqli", client_ip: "203.0.113.5" },
        { ...BASE, path: "/api/login", method: "POST", predicted_class: "sqli", client_ip: "203.0.113.5" },
        { ...BASE, path: "/api/login", method: "POST", predicted_class: "xss", client_ip: "198.51.100.20" },
        { ...BASE, path: "/api/users", method: "GET", predicted_class: "cmdi", client_ip: "9.9.9.9" },
        // 'pass' verdict — not an incident, must be excluded entirely.
        { ...BASE, path: "/health", method: "GET", verdict: "pass", predicted_class: "benign" },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsReport(["--format", "json"]);
      const raw = spy.mock.calls[0][0] as string;
      spy.mockRestore();

      expect(() => JSON.parse(raw)).not.toThrow();
      const parsed = JSON.parse(raw);

      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed).toHaveLength(2);

      const login = parsed.find((r: { path: string }) => r.path === "/api/login");
      expect(login.method).toBe("POST");
      expect(login.incident_count).toBe(3);
      expect(login.block_count).toBe(3);
      expect(login.pass_anomaly_count).toBe(0);
      expect(login.top_attack_class).toBe("sqli");
      expect(login.attack_types).toEqual(
        expect.arrayContaining([
          { predicted_class: "sqli", count: 2 },
          { predicted_class: "xss", count: 1 },
        ])
      );
      expect(login.top_source_ip).toBe("203.0.113.5");

      expect(parsed.some((r: { path: string }) => r.path === "/health")).toBe(false);
    });
  });

  test("--format csv: correct headers and one row per route+method", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, path: "/api/login", method: "POST", predicted_class: "sqli", client_ip: "203.0.113.5" },
        { ...BASE, path: "/api/login", method: "POST", predicted_class: "xss", client_ip: "203.0.113.5" },
        { ...BASE, path: "/api/users", method: "GET", predicted_class: "cmdi", client_ip: "9.9.9.9" },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsReport(["--format", "csv"]);
      const output = spy.mock.calls[0][0] as string;
      spy.mockRestore();

      const lines = output.trim().split("\n");
      expect(lines[0]).toBe(
        "path,method,incident_count,block_count,pass_anomaly_count,risk_score,top_attack_class,attack_types,top_source_ip"
      );
      expect(lines).toHaveLength(3); // header + 2 routes

      const loginRow = lines.find((l) => l.startsWith("/api/login"));
      expect(loginRow).toContain("POST,2,2,0");
      // Tied counts (sqli:1, xss:1) — SQLite doesn't guarantee tie-break order.
      expect(loginRow).toMatch(/(sqli:1;xss:1|xss:1;sqli:1)/);
      expect(loginRow).toContain("203.0.113.5");
    });
  });

  test("default format (no --format flag) is JSON", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [BASE]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsReport([]);
      const raw = spy.mock.calls[0][0] as string;
      spy.mockRestore();

      expect(() => JSON.parse(raw)).not.toThrow();
    });
  });

  test("--output <path>: writes the report to a file instead of stdout", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [BASE]);

      const outFile = path.join(dir, "report.csv");
      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsReport(["--format", "csv", "--output", outFile]);
      const loggedLines = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(fs.existsSync(outFile)).toBe(true);
      const written = fs.readFileSync(outFile, "utf-8");
      expect(written.split("\n")[0]).toContain("path,method,incident_count");
      // stdout should confirm the write, not dump the full CSV body.
      expect(loggedLines).toContain("Wrote 1 route(s)");
      expect(loggedLines).not.toContain("api/users");
    });
  });

  test("empty store (no incidents): JSON is an empty array, CSV is header-only", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [{ ...BASE, verdict: "pass" }]);

      const spyJson = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsReport(["--format", "json"]);
      const jsonOut = spyJson.mock.calls[0][0] as string;
      spyJson.mockRestore();
      expect(JSON.parse(jsonOut)).toEqual([]);

      const spyCsv = jest.spyOn(console, "log").mockImplementation(() => {});
      runEndpointsReport(["--format", "csv"]);
      const csvOut = spyCsv.mock.calls[0][0] as string;
      spyCsv.mockRestore();
      expect(csvOut.trim().split("\n")).toHaveLength(1);
    });
  });
});
