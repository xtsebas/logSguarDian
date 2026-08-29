/**
 * Fase 4 acceptance test: one real label/discard curation cycle produces a
 * curated JSONL file with the expected feature-space schema.
 */
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { PassThrough } from "stream";
import Database from "better-sqlite3";
import { runReviewClusters } from "../src/cli/review-clusters";
import { FEATURE_NAMES } from "@logsguardian/extractor";

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "lg-review-clusters-"));
}

function makeVector(seed: number): number[] {
  return Array.from({ length: 73 }, (_, i) => seed + i * 0.01);
}

function writeTelemetryDb(dbPath: string, events: Array<{ id: number; vector: number[] }>): void {
  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE telemetry_events (
      id INTEGER PRIMARY KEY,
      received_at INTEGER NOT NULL,
      timestamp INTEGER NOT NULL,
      source_id TEXT NOT NULL,
      predicted_class TEXT NOT NULL,
      confidence REAL NOT NULL,
      vector TEXT NOT NULL
    )
  `);
  const insert = db.prepare(`INSERT INTO telemetry_events (id, received_at, timestamp, source_id, predicted_class, confidence, vector) VALUES (@id, 0, 0, 'sim-host-1', 'xss', 0.9, @vector)`);
  for (const e of events) insert.run({ id: e.id, vector: JSON.stringify(e.vector) });
  db.close();
}

function sendLines(stream: PassThrough, lines: string[]): void {
  for (const line of lines) stream.write(line + "\n");
  stream.end();
}

describe("runReviewClusters", () => {
  let dir: string;
  let dbPath: string;
  let reportPath: string;
  let outDir: string;

  beforeEach(() => {
    dir = tmpDir();
    dbPath = path.join(dir, "telemetry.db");
    reportPath = path.join(dir, "cluster_report.json");
    outDir = path.join(dir, "curated");

    writeTelemetryDb(dbPath, [
      { id: 1, vector: makeVector(1) },
      { id: 2, vector: makeVector(2) },
      { id: 3, vector: makeVector(3) },
    ]);

    fs.writeFileSync(reportPath, JSON.stringify({
      total_events: 3,
      anomalous_events: 3,
      eps: 2.5,
      min_samples: 3,
      clusters: [
        {
          cluster_id: 0,
          size: 2,
          avg_if_score: -0.1,
          sources: { "sim-host-1": 2 },
          predicted_classes: { xss: 2 },
          representative_vector: makeVector(1),
          member_event_ids: [1, 2],
        },
        {
          cluster_id: "noise",
          size: 1,
          avg_if_score: -0.05,
          sources: { "sim-host-1": 1 },
          predicted_classes: { xss: 1 },
          representative_vector: makeVector(3),
          member_event_ids: [3],
        },
      ],
    }));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test("labeling a cluster writes its member vectors with the assigned label", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    output.on("data", () => { /* drain */ });

    const run = runReviewClusters(["--report", reportPath, "--db", dbPath, "--out-dir", outDir], { input, output });
    sendLines(input, ["label 0 xss", "discard noise", "done"]);
    await run;

    const files = fs.readdirSync(outDir);
    expect(files).toHaveLength(1);
    const rows = fs.readFileSync(path.join(outDir, files[0]), "utf-8").trim().split("\n").map((l) => JSON.parse(l));

    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.label).toBe("xss");
      expect(row._source).toBe("mlops_telemetry_curated");
      expect(typeof row._row_hash).toBe("string");
      for (const name of FEATURE_NAMES) expect(typeof row[name]).toBe("number");
    }
  });

  test("discarding every cluster writes nothing", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    output.on("data", () => { /* drain */ });

    const run = runReviewClusters(["--report", reportPath, "--db", dbPath, "--out-dir", outDir], { input, output });
    sendLines(input, ["discard 0", "discard noise", "done"]);
    await run;

    expect(fs.existsSync(outDir)).toBe(false);
  });

  test("rejects an invalid category and leaves the cluster pending", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    output.on("data", () => { /* drain */ });
    const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});

    const run = runReviewClusters(["--report", reportPath, "--db", dbPath, "--out-dir", outDir], { input, output });
    sendLines(input, ["label 0 not-a-class", "label 0 xss", "discard noise", "done"]);
    await run;
    const logged = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    logSpy.mockRestore();

    expect(logged).toContain("invalid category");
    const files = fs.readdirSync(outDir);
    const rows = fs.readFileSync(path.join(outDir, files[0]), "utf-8").trim().split("\n").map((l) => JSON.parse(l));
    expect(rows).toHaveLength(2);
  });
});
