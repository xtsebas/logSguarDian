#!/usr/bin/env node
/**
 * Fase 7 — secondary, optional live-traffic shadow mode. Explicitly
 * time-boxed (--duration), never a background daemon: the real memory
 * margin measured for an active canary worker (benchmarks/onnx-memory-
 * pool-canary.bench.js — ~28-54MB vs the ~120MB+ baseline-only margin) means
 * this should only run for a deliberate window, not indefinitely.
 *
 * IMPORTANT CAVEAT: this mode has no ground truth. It can only report "the
 * candidate disagreed with production on X% of live traffic" — it cannot
 * tell you which one was right. Treat disagreement as a signal to
 * investigate, not a promotion decision by itself. canary-replay.ts (corpus
 * replay against e2e/fixtures/test_payloads.jsonl's known _expected_class
 * labels) is the mechanism with an actual pass/fail gate; this one only
 * produces descriptive stats.
 *
 * Usage:
 *   pnpm --filter @logsguardian/mlops run canary-shadow -- \
 *     --duration 10 [--candidate path/to/rf_candidate.onnx] [--port 4791]
 */
import * as fs from "fs";
import * as path from "path";
import express from "express";
import Database from "better-sqlite3";
import { logsguardian } from "logsguardian";
import type { LogsguardianHandler } from "logsguardian";

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const MODEL_DIR = path.join(REPO_ROOT, "training", "models");
const DEFAULT_CANDIDATE_PATH = path.join(MODEL_DIR, "rf_candidate.onnx");
const DB_PATH = path.join(REPO_ROOT, "packages", "mlops", "data", "canary-shadow.db");
const DEFAULT_PORT = 4791;
const WARMUP_MS = 3000;

function parseArgs(argv: string[]): { durationMin: number; candidatePath: string; port: number } {
  const durationIdx = argv.indexOf("--duration");
  const candidateIdx = argv.indexOf("--candidate");
  const portIdx = argv.indexOf("--port");

  const durationMin = durationIdx >= 0 ? Number(argv[durationIdx + 1]) : NaN;
  if (!Number.isFinite(durationMin) || durationMin <= 0) {
    console.error("Usage: canary-shadow --duration <minutes> [--candidate <path>] [--port <n>]");
    console.error("--duration is required — this mode never runs unbounded.");
    process.exit(1);
  }

  return {
    durationMin,
    candidatePath: candidateIdx >= 0 ? argv[candidateIdx + 1] : DEFAULT_CANDIDATE_PATH,
    port: portIdx >= 0 ? Number(argv[portIdx + 1]) : DEFAULT_PORT,
  };
}

async function main(): Promise<void> {
  const { durationMin, candidatePath, port } = parseArgs(process.argv.slice(2));

  if (!fs.existsSync(candidatePath)) {
    console.error(`canary-shadow: candidate model not found at ${candidatePath}`);
    process.exit(1);
  }

  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  try { fs.unlinkSync(DB_PATH); } catch { /* first run */ }

  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  const mw = logsguardian({ mode: "block", modelDir: MODEL_DIR, dbPath: DB_PATH }) as LogsguardianHandler;
  app.use(mw);
  app.all(/.*/, (_req, res) => res.json({ status: "ok" }));

  console.log(`Warming up production workers (${WARMUP_MS}ms)...`);
  await new Promise((r) => setTimeout(r, WARMUP_MS));

  console.log(`Spawning canary worker: ${candidatePath}`);
  await mw.spawnCanaryWorker!(candidatePath);

  const server = app.listen(port, () => {
    console.log(`\nlogsguardian + canary shadow listening on :${port}`);
    console.log(`Running for ${durationMin} minute(s) — this is a hard stop, not a suggestion.`);
    console.log(`No ground truth in this mode: disagreement is a signal to investigate, not a verdict.\n`);
  });

  await new Promise((r) => setTimeout(r, durationMin * 60_000));

  console.log("\nDuration elapsed — tearing down.");
  server.close();
  mw.closeCanaryWorker!();
  mw.close!();

  const db = new Database(DB_PATH, { readonly: true });
  const row = db.prepare(`
    SELECT COUNT(*) as total, SUM(verdict_match) as matched
    FROM canary_comparisons
  `).get() as { total: number; matched: number | null };
  db.close();

  const total = row.total;
  const matched = row.matched ?? 0;
  const agreementRate = total > 0 ? matched / total : null;

  console.log("\n=== Live shadow summary (descriptive only — no ground truth, no gate) ===");
  console.log(`Compared requests: ${total}`);
  console.log(`Verdict agreement: ${agreementRate !== null ? (agreementRate * 100).toFixed(2) + "%" : "n/a (no traffic)"}`);
  console.log(`Disagreements: ${total - matched}`);
  console.log(`\nThese numbers describe divergence, not correctness. Use canary-replay.ts`);
  console.log(`(known-label corpus replay) for an actual promotion decision.`);

  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
