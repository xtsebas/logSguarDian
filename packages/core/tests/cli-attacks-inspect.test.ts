import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runConfigInit } from "../src/cli/config-init";
import { runAttacksInspect } from "../src/cli/attacks-inspect";
import { EventStore } from "../src/store";
import type { DetectionEvent } from "../src/types";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "logsguardian-attacks-inspect-"));
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
  timestamp: Date.UTC(2026, 6, 10, 0, 0, 0),
  method: "POST",
  path: "/api/login",
  query_string: "id=1' OR '1'='1",
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

function mockExit(): jest.SpyInstance {
  return jest.spyOn(process, "exit").mockImplementation((code) => {
    throw new Error(`process.exit(${code})`);
  });
}

describe("attacks inspect", () => {
  test("exits with code 1 when no type argument is given", () => {
    withTempDir(() => {
      runConfigInit();
      const spy = mockExit();
      expect(() => runAttacksInspect([])).toThrow("process.exit(1)");
      spy.mockRestore();
    });
  });

  test("exits with code 1 on an invalid attack type", () => {
    withTempDir(() => {
      runConfigInit();
      const spy = mockExit();
      expect(() => runAttacksInspect(["ddos"])).toThrow("process.exit(1)");
      spy.mockRestore();
    });
  });

  test("valid type with no database: shows detection rate, no crash, no examples message", () => {
    withTempDir(() => {
      runConfigInit();
      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      expect(() => runAttacksInspect(["sqli"])).not.toThrow();
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("F1 Score");
      expect(output).toContain("No examples in store yet");
    });
  });

  test("valid type with database events: shows payload examples from the store", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [
        { ...BASE, query_string: "id=1' OR '1'='1", predicted_class: "sqli", verdict: "block" },
      ]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksInspect(["sqli"]);
      const output = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      spy.mockRestore();

      expect(output).toContain("id=1' OR '1'='1");
    });
  });

  test("--format json: outputs valid JSON with the expected shape", () => {
    withTempDir((dir) => {
      runConfigInit();
      seed(path.join(dir, "logsguardian.db"), [BASE]);

      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksInspect(["sqli", "--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed).toHaveProperty("attack_type", "sqli");
      expect(parsed).toHaveProperty("detection_rate");
      expect(parsed).toHaveProperty("top_features");
      expect(parsed).toHaveProperty("payload_examples");
      expect(Array.isArray(parsed.top_features)).toBe(true);
      expect(Array.isArray(parsed.payload_examples)).toBe(true);
    });
  });

  test("--format json for cmdi: f1 value is 0.8865 (test-set, docs/decision-policy.md §2.1)", () => {
    withTempDir(() => {
      runConfigInit();
      const spy = jest.spyOn(console, "log").mockImplementation(() => {});
      runAttacksInspect(["cmdi", "--format", "json"]);
      const parsed = JSON.parse(spy.mock.calls[0][0] as string);
      spy.mockRestore();

      expect(parsed.detection_rate.f1).toBe(0.8865);
      expect(parsed.detection_rate.eval_set).toBe("test");
    });
  });
});
