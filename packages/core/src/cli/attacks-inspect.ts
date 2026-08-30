import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";
import { requireConfig, parseFormat } from "./guard";
import type { MiddlewareOptions } from "../types";

const VALID_TYPES = ["sqli", "xss", "path_traversal", "cmdi"] as const;
type AttackType = (typeof VALID_TYPES)[number];

interface ClassMetric {
  f1: number | null;
  precision: number | null;
  recall: number | null;
}

interface ClassMetrics {
  eval_set: string;
  eval_note: string;
  macro_f1: number;
  classes: Record<string, ClassMetric>;
}

interface FeatureEntry {
  rank: number;
  name: string;
  importance: number;
}

interface FeatureImportance {
  note: string;
  features: FeatureEntry[];
}

interface PayloadRow {
  query_string: string;
}

/** Static model metadata shipped in packages/core/data/ (see postbuild script). */
function loadDataFile<T>(filename: string): T {
  const dataDir = path.join(__dirname, "..", "..", "data");
  return JSON.parse(fs.readFileSync(path.join(dataDir, filename), "utf-8")) as T;
}

/**
 * Payload examples come from detection_events (real traffic the middleware
 * has seen), not the training JSONL files — those aren't shipped with the
 * npm package.
 */
function loadPayloadExamples(dbPath: string, attackType: AttackType): string[] {
  if (!fs.existsSync(dbPath)) return [];

  const db = new Database(dbPath, { readonly: true });
  try {
    const rows = db
      .prepare(
        `SELECT query_string
         FROM detection_events
         WHERE predicted_class = ?
           AND verdict IN ('block', 'pass_anomaly')
           AND query_string != ''
         ORDER BY id DESC
         LIMIT 3`
      )
      .all(attackType) as PayloadRow[];
    return rows.map((r) => r.query_string);
  } finally {
    db.close();
  }
}

export function runAttacksInspect(args: string[]): void {
  const config = requireConfig() as unknown as MiddlewareOptions;

  const attackType = args[0];
  if (!attackType) {
    console.error("logsguardian: attacks inspect requires a type argument");
    console.error("Usage: logsguardian attacks inspect <type>");
    console.error(`Valid types: ${VALID_TYPES.join(", ")}`);
    process.exit(1);
  }
  if (!(VALID_TYPES as readonly string[]).includes(attackType)) {
    console.error(`logsguardian: unknown attack type '${attackType}'`);
    console.error(`Valid types: ${VALID_TYPES.join(", ")}`);
    process.exit(1);
  }

  const format = parseFormat(args, ["table", "json"] as const, "table");

  const classMetrics = loadDataFile<ClassMetrics>("class_metrics.json");
  const featureImportance = loadDataFile<FeatureImportance>("feature_importance.json");

  const dbPath = path.resolve(process.cwd(), config.dbPath ?? "logsguardian.db");
  const payloadExamples = loadPayloadExamples(dbPath, attackType as AttackType);

  const classInfo = classMetrics.classes[attackType];
  const topFeatures = featureImportance.features.slice(0, 5);

  const result = {
    attack_type: attackType,
    detection_rate: {
      f1: classInfo?.f1 ?? null,
      precision: classInfo?.precision ?? null,
      recall: classInfo?.recall ?? null,
      eval_set: classMetrics.eval_set,
      eval_note: classMetrics.eval_note,
    },
    top_features: topFeatures.map((f) => ({
      rank: f.rank,
      feature: f.name,
      importance: f.importance,
    })),
    feature_importance_note: featureImportance.note,
    payload_examples: payloadExamples,
  };

  if (format === "json") {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  printTable(attackType, classMetrics, classInfo, topFeatures, featureImportance.note, payloadExamples);
}

function printTable(
  attackType: string,
  classMetrics: ClassMetrics,
  classInfo: ClassMetric | undefined,
  topFeatures: FeatureEntry[],
  featureNote: string,
  payloadExamples: string[]
): void {
  const typeLabel = attackType.toUpperCase().replace("_", " ");

  console.log(`\nlogSguarDian — Attack Inspect: ${typeLabel}\n`);

  console.log("  DETECTION RATE");
  console.log("  " + "─".repeat(40));
  if (classInfo?.f1 != null) {
    console.log(`  F1 Score (${classMetrics.eval_set} set): ${(classInfo.f1 * 100).toFixed(1)}%`);
  } else {
    console.log("  F1 Score: not available");
  }
  if (classInfo?.precision != null && classInfo?.recall != null) {
    console.log(`  Precision: ${(classInfo.precision * 100).toFixed(1)}%  Recall: ${(classInfo.recall * 100).toFixed(1)}%`);
  }
  console.log(`  Note: ${classMetrics.eval_note}`);
  console.log();

  console.log("  TOP FEATURES (overall RF importance)");
  console.log("  " + "─".repeat(40));
  const rankW = 6;
  const nameW = 30;
  const impW = 12;
  console.log("  " + "RANK".padEnd(rankW) + "FEATURE".padEnd(nameW) + "IMPORTANCE".padEnd(impW));
  console.log("  " + "─".repeat(rankW + nameW + impW));
  for (const f of topFeatures) {
    console.log(
      "  " + String(f.rank).padEnd(rankW) + f.name.padEnd(nameW) + f.importance.toFixed(4).padEnd(impW)
    );
  }
  console.log(`  (${featureNote})`);
  console.log();

  console.log("  PAYLOAD EXAMPLES (from detection store)");
  console.log("  " + "─".repeat(40));
  if (payloadExamples.length === 0) {
    console.log("  No examples in store yet — run the middleware against real traffic first");
  } else {
    for (const p of payloadExamples) {
      const truncated = p.length > 80 ? p.slice(0, 77) + "..." : p;
      console.log(`  ${truncated}`);
    }
  }
  console.log();
}
