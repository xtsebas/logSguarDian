/**
 * Fase 8 — `mlops promote-canary`: promotes a canary candidate to
 * production, but only if a canary-replay.ts run already produced
 * APPROVED_FOR_PROMOTION (Fase 7's hard/soft gates). Archives the current
 * production models before overwriting them — never a silent overwrite —
 * updates parity_report.json's version tracking, and appends an audit-trail
 * entry to promotion_log.jsonl (the record a thesis committee or future
 * maintainer would need to answer "what's running and when did it change").
 *
 * IMPORTANT — this only updates files on disk. worker.ts loads its ONNX
 * session exactly once, at worker_thread startup (loadSession() runs a
 * single time; there is no reload path) — promoting here has no effect on
 * an already-running process. The application must be restarted for a
 * promoted model to actually take effect. This command is intentionally
 * NOT trying to hot-reload sessions inside live worker threads — that is a
 * materially larger, riskier change than file versioning and is out of
 * scope for Fase 8.
 */
import * as fs from "fs";
import * as path from "path";

const MLOPS_DIR = path.resolve(__dirname, "..", "..");
const DATA_DIR = path.join(MLOPS_DIR, "data");
const MODELS_DIR = path.resolve(MLOPS_DIR, "..", "..", "training", "models");
const ARCHIVE_DIR = path.join(MODELS_DIR, "archive");
const PARITY_REPORT_PATH = path.join(MODELS_DIR, "parity_report.json");
const PROMOTION_LOG_PATH = path.join(MODELS_DIR, "promotion_log.jsonl");

interface ParityReport {
  rf_model_version: string;
  if_model_version: string;
  [key: string]: unknown;
}

interface ReplayReport {
  status: string;
  candidate_model: string;
  verdict_agreement_rate: number;
  hard_gate_regressions: number;
}

function findLatestReplayReport(): { path: string; report: ReplayReport } {
  const files = fs.existsSync(DATA_DIR)
    ? fs.readdirSync(DATA_DIR).filter((f) => f.startsWith("canary_replay_report_") && f.endsWith(".json"))
    : [];
  if (files.length === 0) {
    throw new Error(`no canary_replay_report_*.json found in ${DATA_DIR} — run 'canary-replay' first`);
  }
  files.sort(); // filenames embed a millisecond timestamp — lexical sort is chronological
  const reportPath = path.join(DATA_DIR, files[files.length - 1]);
  const report: ReplayReport = JSON.parse(fs.readFileSync(reportPath, "utf-8"));
  return { path: reportPath, report };
}

/** "rf_v10" -> 10. Falls back to 0 (so the next version is 1) if the string
 * doesn't parse — a simple incrementing counter, matching the convention
 * already established in parity_report.json's rf_model_version/if_model_version. */
function parseVersionNumber(version: string): number {
  const match = version.match(/(\d+)$/);
  return match ? parseInt(match[1], 10) : 0;
}

function nextVersion(prefix: "rf" | "if", currentVersion: string): string {
  return `${prefix}_v${parseVersionNumber(currentVersion) + 1}`;
}

function appendPromotionLog(entry: Record<string, unknown>): void {
  fs.appendFileSync(PROMOTION_LOG_PATH, JSON.stringify({ timestamp: new Date().toISOString(), ...entry }) + "\n");
}

export function runPromoteCanary(_args: string[]): void {
  const { path: replayReportPath, report: replayReport } = (() => {
    try {
      return findLatestReplayReport();
    } catch (err) {
      console.error(`mlops promote-canary: ${(err as Error).message}`);
      process.exit(1);
    }
  })();

  if (replayReport.status !== "APPROVED_FOR_PROMOTION") {
    console.error(`mlops promote-canary: refusing to promote — latest replay report is '${replayReport.status}', not APPROVED_FOR_PROMOTION.`);
    console.error(`  Report: ${replayReportPath}`);
    console.error(`  hard_gate_regressions=${replayReport.hard_gate_regressions}, verdict_agreement_rate=${replayReport.verdict_agreement_rate}`);
    console.error(`No files were touched.`);
    process.exit(1);
  }

  const rfCandidate = path.join(MODELS_DIR, "rf_candidate.onnx");
  const ifCandidate = path.join(MODELS_DIR, "if_candidate.onnx");
  const rfProd = path.join(MODELS_DIR, "rf.onnx");
  const ifProd = path.join(MODELS_DIR, "if.onnx");

  for (const p of [rfCandidate, ifCandidate, rfProd, ifProd, PARITY_REPORT_PATH]) {
    if (!fs.existsSync(p)) {
      console.error(`mlops promote-canary: expected file not found: ${p}`);
      console.error(`No files were touched.`);
      process.exit(1);
    }
  }

  const parityReport: ParityReport = JSON.parse(fs.readFileSync(PARITY_REPORT_PATH, "utf-8"));
  const oldRfVersion = parityReport.rf_model_version;
  const oldIfVersion = parityReport.if_model_version;
  const newRfVersion = nextVersion("rf", oldRfVersion);
  const newIfVersion = nextVersion("if", oldIfVersion);

  fs.mkdirSync(ARCHIVE_DIR, { recursive: true });

  // Archive current production BEFORE overwriting — never a silent overwrite.
  const archivedRfPath = path.join(ARCHIVE_DIR, `${oldRfVersion}.onnx`);
  const archivedIfPath = path.join(ARCHIVE_DIR, `${oldIfVersion}.onnx`);
  fs.copyFileSync(rfProd, archivedRfPath);
  fs.copyFileSync(ifProd, archivedIfPath);

  // Promote the candidate.
  fs.copyFileSync(rfCandidate, rfProd);
  fs.copyFileSync(ifCandidate, ifProd);

  // Version tracking only — rf_n_features/parity diffs/etc are left as-is;
  // Fase 6's gate_parity.py already validated this exact candidate's parity
  // before it could reach APPROVED_FOR_PROMOTION, so there's nothing to
  // recompute here.
  parityReport.rf_model_version = newRfVersion;
  parityReport.if_model_version = newIfVersion;
  fs.writeFileSync(PARITY_REPORT_PATH, JSON.stringify(parityReport, null, 2));

  appendPromotionLog({
    action: "promote",
    old_rf_version: oldRfVersion,
    old_if_version: oldIfVersion,
    new_rf_version: newRfVersion,
    new_if_version: newIfVersion,
    archived_rf: archivedRfPath,
    archived_if: archivedIfPath,
    replay_report: replayReportPath,
    replay_verdict_agreement_rate: replayReport.verdict_agreement_rate,
  });

  console.log(`Promoted candidate to production:`);
  console.log(`  RF: ${oldRfVersion} -> ${newRfVersion}  (archived: ${archivedRfPath})`);
  console.log(`  IF: ${oldIfVersion} -> ${newIfVersion}  (archived: ${archivedIfPath})`);
  console.log(`  Based on: ${replayReportPath} (verdict_agreement_rate=${replayReport.verdict_agreement_rate})`);
  console.log(`  Audit log: ${PROMOTION_LOG_PATH}`);
  console.log(`\nModels updated on disk. Restart the application for changes to take effect —`);
  console.log(`worker.ts loads its ONNX session once at startup; there is no hot-reload path.`);
}
