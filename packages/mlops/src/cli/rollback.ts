/**
 * Fase 8 — `mlops rollback [--to <version>]`: reverts production models to
 * a previously archived version. Without --to, reverts to whatever the
 * most recent promotion_log.jsonl entry (a promote or an earlier rollback)
 * replaced. With --to <version> (e.g. "rf_v10" or "if_v9"), finds the log
 * entry that archived that version and restores the pair it recorded — RF
 * and IF are always promoted/archived together, so one version string is
 * enough to identify the whole event.
 *
 * Same versioning discipline as promotion: the model being rolled back
 * FROM is archived too, never silently discarded — rollback is itself
 * always reversible, and shows up as its own entry in promotion_log.jsonl.
 *
 * Same restart requirement as promotion — see promote-canary.ts's doc
 * comment for why.
 */
import * as fs from "fs";
import * as path from "path";

const MLOPS_DIR = path.resolve(__dirname, "..", "..");
const MODELS_DIR = path.resolve(MLOPS_DIR, "..", "..", "training", "models");
const ARCHIVE_DIR = path.join(MODELS_DIR, "archive");
const PARITY_REPORT_PATH = path.join(MODELS_DIR, "parity_report.json");
const PROMOTION_LOG_PATH = path.join(MODELS_DIR, "promotion_log.jsonl");

interface ParityReport {
  rf_model_version: string;
  if_model_version: string;
  [key: string]: unknown;
}

interface LogEntry {
  timestamp: string;
  action: "promote" | "rollback";
  old_rf_version: string;
  old_if_version: string;
  new_rf_version: string;
  new_if_version: string;
  [key: string]: unknown;
}

function readLog(): LogEntry[] {
  if (!fs.existsSync(PROMOTION_LOG_PATH)) return [];
  return fs.readFileSync(PROMOTION_LOG_PATH, "utf-8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function appendPromotionLog(entry: Record<string, unknown>): void {
  fs.appendFileSync(PROMOTION_LOG_PATH, JSON.stringify({ timestamp: new Date().toISOString(), ...entry }) + "\n");
}

function parseArgs(argv: string[]): { to?: string } {
  const toIdx = argv.indexOf("--to");
  return { to: toIdx >= 0 ? argv[toIdx + 1] : undefined };
}

export function runRollback(args: string[]): void {
  const { to } = parseArgs(args);
  const log = readLog();

  if (log.length === 0) {
    console.error(`mlops rollback: no promotion_log.jsonl entries found at ${PROMOTION_LOG_PATH} — nothing to roll back.`);
    console.error(`No files were touched.`);
    process.exit(1);
  }

  let targetEntry: LogEntry | undefined;
  if (to) {
    // Most recent entry matching first (in case a version string was reused
    // across multiple promote/rollback cycles).
    targetEntry = [...log].reverse().find((e) => e.old_rf_version === to || e.old_if_version === to);
    if (!targetEntry) {
      console.error(`mlops rollback: no promotion_log.jsonl entry archives version '${to}'.`);
      console.error(`Available versions: ${[...new Set(log.flatMap((e) => [e.old_rf_version, e.old_if_version]))].join(", ")}`);
      console.error(`No files were touched.`);
      process.exit(1);
    }
  } else {
    targetEntry = log[log.length - 1];
  }

  const restoreRfVersion = targetEntry.old_rf_version;
  const restoreIfVersion = targetEntry.old_if_version;
  const restoreRfPath = path.join(ARCHIVE_DIR, `${restoreRfVersion}.onnx`);
  const restoreIfPath = path.join(ARCHIVE_DIR, `${restoreIfVersion}.onnx`);

  for (const p of [restoreRfPath, restoreIfPath, PARITY_REPORT_PATH]) {
    if (!fs.existsSync(p)) {
      console.error(`mlops rollback: expected archived file not found: ${p}`);
      console.error(`No files were touched.`);
      process.exit(1);
    }
  }

  const parityReport: ParityReport = JSON.parse(fs.readFileSync(PARITY_REPORT_PATH, "utf-8"));
  const currentRfVersion = parityReport.rf_model_version;
  const currentIfVersion = parityReport.if_model_version;

  const rfProd = path.join(MODELS_DIR, "rf.onnx");
  const ifProd = path.join(MODELS_DIR, "if.onnx");

  // Archive what's currently active BEFORE overwriting — same discipline as
  // promotion, so this rollback is itself reversible.
  fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
  const archivedRfPath = path.join(ARCHIVE_DIR, `${currentRfVersion}.onnx`);
  const archivedIfPath = path.join(ARCHIVE_DIR, `${currentIfVersion}.onnx`);
  fs.copyFileSync(rfProd, archivedRfPath);
  fs.copyFileSync(ifProd, archivedIfPath);

  fs.copyFileSync(restoreRfPath, rfProd);
  fs.copyFileSync(restoreIfPath, ifProd);

  parityReport.rf_model_version = restoreRfVersion;
  parityReport.if_model_version = restoreIfVersion;
  fs.writeFileSync(PARITY_REPORT_PATH, JSON.stringify(parityReport, null, 2));

  appendPromotionLog({
    action: "rollback",
    old_rf_version: currentRfVersion,
    old_if_version: currentIfVersion,
    new_rf_version: restoreRfVersion,
    new_if_version: restoreIfVersion,
    archived_rf: archivedRfPath,
    archived_if: archivedIfPath,
    rolled_back_to_log_entry: targetEntry.timestamp,
  });

  console.log(`Rolled back production models:`);
  console.log(`  RF: ${currentRfVersion} -> ${restoreRfVersion}  (${currentRfVersion} archived: ${archivedRfPath})`);
  console.log(`  IF: ${currentIfVersion} -> ${restoreIfVersion}  (${currentIfVersion} archived: ${archivedIfPath})`);
  console.log(`  Audit log: ${PROMOTION_LOG_PATH}`);
  console.log(`\nModels updated on disk. Restart the application for changes to take effect —`);
  console.log(`worker.ts loads its ONNX session once at startup; there is no hot-reload path.`);
}
