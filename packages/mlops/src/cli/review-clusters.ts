/**
 * Fase 4 — `mlops review-clusters`: interactive curation of anomaly clusters
 * produced by scripts/cluster_anomalies.py (Fase 3).
 *
 * Output schema note: telemetry events never carry the raw request text (by
 * Fase 1 design — only the 73-feature vector is ever sent to the collector),
 * so the curated file this writes is feature-space, not the raw-request
 * canonical JSONL that unify.py normally consumes. It matches the columns
 * training/split.py reads from features.parquet directly (FEATURE_NAMES +
 * label + _source + _row_hash), so Fase 5's orchestrator merges this file in
 * *after* the extractor CLI step rather than before it — there is no raw
 * text for the extractor to re-derive features from.
 */
import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";
import * as crypto from "crypto";
import Database from "better-sqlite3";
import { FEATURE_NAMES } from "@logsguardian/extractor";

const DATA_DIR = path.resolve(__dirname, "..", "..", "data");
const DEFAULT_DB_PATH = path.join(DATA_DIR, "mlops-telemetry.db");
const CURATED_DIR = path.resolve(__dirname, "..", "..", "..", "..", "training", "data_clean");
const VALID_LABELS = new Set(["sqli", "xss", "path_traversal", "cmdi", "benign"]);

interface ClusterEntry {
  cluster_id: number | "noise";
  size: number;
  avg_if_score: number;
  sources: Record<string, number>;
  predicted_classes: Record<string, number>;
  representative_vector: number[];
  member_event_ids: number[];
}

interface ClusterReport {
  total_events: number;
  anomalous_events: number;
  eps: number;
  min_samples: number;
  clusters: ClusterEntry[];
}

function findLatestReport(): string {
  const files = fs.existsSync(DATA_DIR)
    ? fs.readdirSync(DATA_DIR).filter((f) => f.startsWith("cluster_report_") && f.endsWith(".json"))
    : [];
  if (files.length === 0) {
    throw new Error(`no cluster_report_*.json found in ${DATA_DIR} — run scripts/cluster_anomalies.py first`);
  }
  files.sort();
  return path.join(DATA_DIR, files[files.length - 1]);
}

function loadVectorsByEventId(dbPath: string, eventIds: number[]): Map<number, number[]> {
  const db = new Database(dbPath, { readonly: true });
  const placeholders = eventIds.map(() => "?").join(",");
  const rows = db
    .prepare(`SELECT id, vector FROM telemetry_events WHERE id IN (${placeholders})`)
    .all(...eventIds) as Array<{ id: number; vector: string }>;
  db.close();
  return new Map(rows.map((r) => [r.id, JSON.parse(r.vector) as number[]]));
}

function summarizeCluster(c: ClusterEntry): string {
  const sources = Object.entries(c.sources).map(([k, v]) => `${k}:${v}`).join(", ");
  const classes = Object.entries(c.predicted_classes).map(([k, v]) => `${k}:${v}`).join(", ");
  return (
    `cluster ${c.cluster_id}  (size=${c.size}, avg_if_score=${c.avg_if_score.toFixed(6)})\n` +
    `  sources:            ${sources}\n` +
    `  RF predicted_class: ${classes}`
  );
}

function rowHash(vector: number[], label: string): string {
  return crypto.createHash("sha256").update(vector.join(",") + "|" + label).digest("hex");
}

export interface ReviewClustersIO {
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
}

export async function runReviewClusters(args: string[], io: ReviewClustersIO = {}): Promise<void> {
  const reportPath = args.includes("--report")
    ? args[args.indexOf("--report") + 1]
    : findLatestReport();
  const dbPath = args.includes("--db") ? args[args.indexOf("--db") + 1] : DEFAULT_DB_PATH;

  const report: ClusterReport = JSON.parse(fs.readFileSync(reportPath, "utf-8"));
  if (report.clusters.length === 0) {
    console.log("No clusters to review.");
    return;
  }

  const allEventIds = report.clusters.flatMap((c) => c.member_event_ids);
  const vectorsByEventId = loadVectorsByEventId(dbPath, allEventIds);

  const decisions = new Map<string, { action: "label"; category: string } | { action: "discard" }>();
  const pending = new Map(report.clusters.map((c) => [String(c.cluster_id), c]));

  console.log(`Loaded ${report.clusters.length} clusters from ${reportPath}\n`);
  for (const c of report.clusters) console.log(summarizeCluster(c) + "\n");

  console.log("Commands: label <cluster_id> <category>  |  discard <cluster_id>  |  list  |  done");
  console.log(`Categories: ${[...VALID_LABELS].join(", ")}\n`);

  // A sequential await-based question() loop silently drops lines when stdin
  // is a fully-buffered pipe/file (all "line" events can fire before the
  // second question() call re-attaches its listener) — a persistent "line"
  // listener processes every line regardless of how fast stdin delivers them.
  const rl = readline.createInterface({ input: io.input ?? process.stdin, output: io.output ?? process.stdout });
  rl.setPrompt("review-clusters> ");

  await new Promise<void>((resolveSession) => {
    rl.prompt();
    rl.on("line", (raw) => {
      const line = raw.trim();
      if (!line) { rl.prompt(); return; }
      const [cmd, ...rest] = line.split(/\s+/);

      if (cmd === "done" || cmd === "exit") { rl.close(); return; }

      if (cmd === "list") {
        for (const c of pending.values()) console.log(summarizeCluster(c) + "\n");
        rl.prompt();
        return;
      }

      if (cmd === "discard") {
        const [clusterId] = rest;
        if (!pending.has(clusterId)) { console.log(`unknown cluster '${clusterId}'`); rl.prompt(); return; }
        decisions.set(clusterId, { action: "discard" });
        pending.delete(clusterId);
        console.log(`discarded cluster ${clusterId}`);
        rl.prompt();
        return;
      }

      if (cmd === "label") {
        const [clusterId, category] = rest;
        if (!pending.has(clusterId)) { console.log(`unknown cluster '${clusterId}'`); rl.prompt(); return; }
        if (!VALID_LABELS.has(category)) { console.log(`invalid category '${category}' — must be one of ${[...VALID_LABELS].join(", ")}`); rl.prompt(); return; }
        decisions.set(clusterId, { action: "label", category });
        pending.delete(clusterId);
        console.log(`labeled cluster ${clusterId} as '${category}'`);
        rl.prompt();
        return;
      }

      console.log(`unrecognized command '${cmd}'`);
      rl.prompt();
    });
    rl.on("close", () => resolveSession());
  });

  const labeledRows: Record<string, unknown>[] = [];
  for (const c of report.clusters) {
    const decision = decisions.get(String(c.cluster_id));
    if (!decision || decision.action !== "label") continue;
    for (const eventId of c.member_event_ids) {
      const vector = vectorsByEventId.get(eventId);
      if (!vector) continue;
      const row: Record<string, unknown> = {};
      FEATURE_NAMES.forEach((name, i) => { row[name] = vector[i]; });
      row.label = decision.category;
      row._source = "mlops_telemetry_curated";
      row._row_hash = rowHash(vector, decision.category);
      labeledRows.push(row);
    }
  }

  if (labeledRows.length === 0) {
    console.log("\nNo clusters were labeled — nothing written.");
    return;
  }

  const outDir = args.includes("--out-dir") ? args[args.indexOf("--out-dir") + 1] : CURATED_DIR;
  fs.mkdirSync(outDir, { recursive: true });
  const dateStr = new Date().toISOString().slice(0, 10);
  const outPath = path.join(outDir, `telemetry_curated_${dateStr}.jsonl`);
  const content = labeledRows.map((r) => JSON.stringify(r)).join("\n") + "\n";
  fs.writeFileSync(outPath, content);

  console.log(`\nWrote ${labeledRows.length} curated rows to ${outPath}`);
}
