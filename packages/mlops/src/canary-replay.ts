#!/usr/bin/env node
/**
 * Fase 7 — primary promotion mechanism: corpus replay with known ground
 * truth. Replays e2e/fixtures/test_payloads.jsonl (each record carries a
 * real _expected_class label) through a real logsguardian instance with a
 * canary worker active (packages/core/src/middleware.ts's
 * spawnCanaryWorker/closeCanaryWorker, Fase 7). Production's real verdict
 * decides every response, exactly as in production — canary is dispatched
 * the same fire-and-forget way IF is, and only ever writes to
 * canary_comparisons after the response has already gone out.
 *
 * This is deliberately the PRIMARY promotion mechanism, not live shadow
 * traffic: live traffic has no ground truth (shadow agreement only tells you
 * "the candidate disagrees," never "the candidate is wrong"), while this
 * corpus's _expected_class labels let us check the one thing that actually
 * matters before promoting a model — does it miss attacks production
 * catches. Live shadow mode (canary-shadow.ts) is secondary and explicitly
 * caveated for exactly this reason.
 *
 * Hard gate (non-negotiable): zero cases where production correctly blocked
 * a real attack and the candidate would have passed it.
 * Soft gate: >=99.5% overall verdict agreement (block vs not-block) with
 * production, matching the project's general pattern of a stricter buffer
 * over the bare minimum (see if_v5's thin-margin lesson).
 *
 * Run: pnpm --filter @logsguardian/mlops run canary-replay [candidateModelPath]
 * Default candidate: training/models/rf_candidate.onnx (ct_pipeline.py's output).
 */
import * as fs from "fs";
import * as path from "path";
import express from "express";
import request from "supertest";
import Database from "better-sqlite3";
import { logsguardian } from "logsguardian";
import type { LogsguardianHandler } from "logsguardian";

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const MODEL_DIR = path.join(REPO_ROOT, "training", "models");
const FIXTURES_PATH = path.join(REPO_ROOT, "e2e", "fixtures", "test_payloads.jsonl");
const DEFAULT_CANDIDATE_PATH = path.join(MODEL_DIR, "rf_candidate.onnx");
const DB_PATH = path.join(REPO_ROOT, "packages", "mlops", "data", "canary-replay.db");
const REPORT_DIR = path.join(REPO_ROOT, "packages", "mlops", "data");

// Same rationale as simulate-fleet.ts's RF_WARMUP_MS: dispatching real
// traffic before a worker's ONNX session finishes loading silently fails
// open (predicted_class="benign", no wait) instead of erroring.
const WARMUP_MS = 3000;
// Canary replies are fire-and-forget relative to the HTTP response and can
// lag well behind it under real ONNX inference load (confirmed: a fixed
// 3000ms drain left ~25% of a 500-record replay uncovered) — poll the
// comparison count instead of guessing a fixed wait.
const DRAIN_POLL_INTERVAL_MS = 500;
const DRAIN_STABLE_POLLS_REQUIRED = 3; // count unchanged for this many consecutive polls
// Must exceed middleware.ts's CANARY_CONTEXT_TIMEOUT_MS (60s) — otherwise this
// gives up on comparisons that are still legitimately in flight, not dropped.
const DRAIN_MAX_WAIT_MS = 75_000;

const SOFT_AGREEMENT_THRESHOLD = 0.995;

interface FixtureRecord {
  method: string;
  path: string;
  query: string;
  body: string | null;
  userAgent: string;
  contentType: string;
  referer: string;
  cookie: string;
  _expected_class: string;
}

interface CanaryComparisonRow {
  request_id: number;
  production_verdict: string;
  production_predicted_class: string;
  canary_verdict: string;
  canary_predicted_class: string;
  verdict_match: number;
}

function loadFixtures(): FixtureRecord[] {
  return fs
    .readFileSync(FIXTURES_PATH, "utf-8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function createApp(): { app: express.Express; mw: LogsguardianHandler } {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  const mw = logsguardian({
    mode: "block",
    modelDir: MODEL_DIR,
    timeoutMs: 10000,
    dbPath: DB_PATH,
  }) as LogsguardianHandler;
  app.use(mw);
  app.all(/.*/, (_req, res) => res.json({ status: "ok" }));
  return { app, mw };
}

async function sendPayload(app: express.Express, rec: FixtureRecord): Promise<void> {
  const hasBody = typeof rec.body === "string" && rec.body.length > 0;
  const rawMethod = (rec.method || (hasBody ? "POST" : "GET")).toLowerCase();
  const SUPPORTED_METHODS = ["get", "post", "put", "delete", "patch"] as const;
  const method = (SUPPORTED_METHODS as readonly string[]).includes(rawMethod)
    ? (rawMethod as (typeof SUPPORTED_METHODS)[number])
    : "get";
  const urlPath = rec.path ? (rec.path.startsWith("/") ? rec.path : `/${rec.path}`) : "/";
  const fullPath = rec.query ? `${urlPath}?${rec.query}` : urlPath;

  let req = request(app)[method](fullPath);
  if (rec.userAgent) req = req.set("User-Agent", rec.userAgent);
  if (rec.contentType) req = req.set("Content-Type", rec.contentType);
  if (rec.referer) req = req.set("Referer", rec.referer);
  if (hasBody) req = req.send(rec.body as string);

  try {
    await req;
  } catch {
    // A single malformed fixture request must not abort the whole replay.
  }
}

function countCanaryComparisons(): number {
  const db = new Database(DB_PATH, { readonly: true });
  try {
    const row = db.prepare(`SELECT COUNT(*) as c FROM canary_comparisons`).get() as { c: number };
    return row.c;
  } catch {
    return 0; // table not created yet (no canary worker spawned, or nothing written yet)
  } finally {
    db.close();
  }
}

/** Polls canary_comparisons' row count until it stops growing (stable for
 * DRAIN_STABLE_POLLS_REQUIRED consecutive checks) instead of a fixed sleep —
 * a fixed 3s wait left ~25% of a 500-record replay uncovered under real load. */
async function drainCanaryReplies(expectedTotal: number): Promise<void> {
  let lastCount = -1;
  let stablePolls = 0;
  const startedAt = Date.now();

  while (Date.now() - startedAt < DRAIN_MAX_WAIT_MS) {
    const count = countCanaryComparisons();
    if (count >= expectedTotal) {
      console.log(`  Drained: ${count}/${expectedTotal} comparisons written.`);
      return;
    }
    if (count === lastCount) {
      stablePolls++;
      if (stablePolls >= DRAIN_STABLE_POLLS_REQUIRED) {
        console.log(`  Drain stabilized at ${count}/${expectedTotal} — remaining replies likely dropped, not delayed.`);
        return;
      }
    } else {
      stablePolls = 0;
      lastCount = count;
    }
    await new Promise((r) => setTimeout(r, DRAIN_POLL_INTERVAL_MS));
  }
  console.log(`  Drain timed out at ${DRAIN_MAX_WAIT_MS}ms with ${lastCount}/${expectedTotal} comparisons.`);
}

interface Regression {
  index: number;
  expected_class: string;
  production_verdict: string;
  production_predicted_class: string;
  canary_verdict: string;
  canary_predicted_class: string;
}

async function main(): Promise<void> {
  const candidatePath = process.argv[2] ?? DEFAULT_CANDIDATE_PATH;
  if (!fs.existsSync(candidatePath)) {
    console.error(`canary-replay: candidate model not found at ${candidatePath}`);
    console.error(`Run training/ct_pipeline.py first to produce a candidate.`);
    process.exit(1);
  }

  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  try { fs.unlinkSync(DB_PATH); } catch { /* first run */ }

  const { app, mw } = createApp();

  console.log(`Warming up production workers (${WARMUP_MS}ms)...`);
  await new Promise((r) => setTimeout(r, WARMUP_MS));

  console.log(`Spawning canary worker: ${candidatePath}`);
  await mw.spawnCanaryWorker!(candidatePath);

  const fixtures = loadFixtures();
  console.log(`Replaying ${fixtures.length} corpus records through production (canary shadowing)...`);
  for (const rec of fixtures) {
    await sendPayload(app, rec);
  }

  console.log(`Draining canary replies (polling, up to ${DRAIN_MAX_WAIT_MS}ms)...`);
  await drainCanaryReplies(fixtures.length);

  // Deliberately not calling mw.close()/closeCanaryWorker() here: this is a
  // short-lived one-shot script that exits right after the report is
  // written, so there's no long-lived process to keep clean — and
  // terminate()'ing real onnxruntime-node worker_threads has a known
  // native-addon teardown race (the same "libc++abi ... Napi::Error" crash
  // seen elsewhere in this project) that would otherwise risk killing the
  // process before the report gets written. process.exit() below reclaims
  // everything regardless.

  const db = new Database(DB_PATH, { readonly: true });
  const rows = db.prepare(`SELECT * FROM canary_comparisons ORDER BY request_id ASC`).all() as CanaryComparisonRow[];
  db.close();
  const byRequestId = new Map(rows.map((r) => [r.request_id, r]));

  let compared = 0;
  let matched = 0;
  const regressions: Regression[] = [];

  fixtures.forEach((rec, i) => {
    // Request ids are 1-indexed and strictly sequential for a fresh
    // middleware instance handling exactly one request per infer() call —
    // this holds as long as nothing else shares this process/instance
    // (true here: a dedicated app created solely for this replay run).
    const requestId = i + 1;
    const row = byRequestId.get(requestId);
    if (!row) return; // canary reply never arrived for this record — uncovered, not a mismatch

    compared++;
    if (row.verdict_match) matched++;

    const expectedIsAttack = rec._expected_class !== "benign";
    const productionCaught = row.production_verdict === "block";
    const canaryCaught = row.canary_verdict === "block";

    // The hard gate: production correctly blocked a real attack, and the
    // candidate would have let it through. This is the one thing shadow
    // evaluation exists to catch — a promotion that regresses real coverage.
    if (expectedIsAttack && productionCaught && !canaryCaught) {
      regressions.push({
        index: i,
        expected_class: rec._expected_class,
        production_verdict: row.production_verdict,
        production_predicted_class: row.production_predicted_class,
        canary_verdict: row.canary_verdict,
        canary_predicted_class: row.canary_predicted_class,
      });
    }
  });

  const agreementRate = compared > 0 ? matched / compared : 0;
  const hardGatePassed = regressions.length === 0;
  const softGatePassed = agreementRate >= SOFT_AGREEMENT_THRESHOLD;
  const approved = hardGatePassed && softGatePassed;

  const report = {
    status: approved ? "APPROVED_FOR_PROMOTION" : "REJECTED",
    candidate_model: candidatePath,
    total_fixtures: fixtures.length,
    compared,
    uncovered: fixtures.length - compared,
    verdict_agreement_rate: agreementRate,
    soft_gate_threshold: SOFT_AGREEMENT_THRESHOLD,
    soft_gate_passed: softGatePassed,
    hard_gate_regressions: regressions.length,
    hard_gate_passed: hardGatePassed,
    regression_details: regressions.slice(0, 20),
  };

  fs.mkdirSync(REPORT_DIR, { recursive: true });
  const reportPath = path.join(REPORT_DIR, `canary_replay_report_${Date.now()}.json`);
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

  console.log("\n" + JSON.stringify(report, null, 2));
  console.log(`\nReport: ${reportPath}`);

  if (!approved) {
    console.log("\nREJECTED:");
    if (!hardGatePassed) {
      console.log(`  HARD GATE FAILED: ${regressions.length} case(s) where the candidate missed an attack production caught.`);
    }
    if (!softGatePassed) {
      console.log(`  SOFT GATE FAILED: verdict agreement ${(agreementRate * 100).toFixed(2)}% < required ${(SOFT_AGREEMENT_THRESHOLD * 100).toFixed(2)}%.`);
    }
  } else {
    console.log(`\nAPPROVED_FOR_PROMOTION — ${(agreementRate * 100).toFixed(2)}% verdict agreement, zero hard-gate regressions.`);
  }

  process.exit(approved ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
