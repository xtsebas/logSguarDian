import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";
import { requireConfig } from "./guard";
import type { MiddlewareOptions } from "../types";

type Severity = "high" | "medium" | "low";

interface SummaryRow {
  path: string;
  method: string;
  severity: Severity;
  predicted_class: string;
  count: number;
}

const SEVERITY_RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

function parseDateArg(raw: string, label: string): number {
  const d = new Date(raw);
  if (isNaN(d.getTime())) {
    console.error(`logsguardian: invalid ${label} date '${raw}' — expected YYYY-MM-DD or ISO 8601`);
    process.exit(1);
  }
  return d.getTime();
}

/**
 * Severity maps onto the existing decision policy verdict
 * (docs/decision-policy.md §3.1) instead of a new confidence-bucket
 * scheme: high = block (crossed RF_THRESHOLD), medium = pass_anomaly
 * (IF flagged), low = pass but still classified as an attack type
 * (RF saw it, confidence just didn't cross the blocking threshold).
 */
export function runAttacksSummary(args: string[]): void {
  const config = requireConfig() as unknown as MiddlewareOptions;

  const format = (() => {
    const idx = args.indexOf("--format");
    return idx !== -1 ? args[idx + 1] : "table";
  })();

  const fromIdx = args.indexOf("--from");
  const from = fromIdx !== -1 ? parseDateArg(args[fromIdx + 1], "--from") : 0;

  const toIdx = args.indexOf("--to");
  let to = Number.MAX_SAFE_INTEGER;
  if (toIdx !== -1) {
    const raw = args[toIdx + 1];
    to = parseDateArg(raw, "--to");
    if (DATE_ONLY.test(raw)) to += 24 * 60 * 60 * 1000 - 1; // date-only --to is inclusive of the whole day
  }

  if (from > to) {
    console.error("logsguardian: --from must be before --to");
    process.exit(1);
  }

  const endpointIdx = args.indexOf("--endpoint");
  const endpoint = endpointIdx !== -1 ? args[endpointIdx + 1] : undefined;

  const dbPath = path.resolve(process.cwd(), config.dbPath ?? "logsguardian.db");

  if (!fs.existsSync(dbPath)) {
    console.error(`logsguardian: no database found at '${dbPath}'`);
    console.error("Run the middleware first to generate detection events.");
    process.exit(1);
  }

  const db = new Database(dbPath, { readonly: true });

  const whereClauses = ["predicted_class != 'benign'", "timestamp >= @from", "timestamp <= @to"];
  const params: Record<string, unknown> = { from, to };
  if (endpoint) {
    whereClauses.push("path = @endpoint");
    params.endpoint = endpoint;
  }

  const rows = db
    .prepare(
      `SELECT
         path,
         method,
         CASE verdict WHEN 'block' THEN 'high' WHEN 'pass_anomaly' THEN 'medium' ELSE 'low' END AS severity,
         predicted_class,
         COUNT(*) AS count
       FROM detection_events
       WHERE ${whereClauses.join(" AND ")}
       GROUP BY path, method, severity, predicted_class`
    )
    .all(params) as SummaryRow[];
  db.close();

  rows.sort((a, b) => {
    if (a.path !== b.path) return a.path < b.path ? -1 : 1;
    if (a.method !== b.method) return a.method < b.method ? -1 : 1;
    if (SEVERITY_RANK[a.severity] !== SEVERITY_RANK[b.severity]) {
      return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    }
    return b.count - a.count;
  });

  if (format === "json") {
    console.log(JSON.stringify(rows, null, 2));
    return;
  }

  printTable(rows);
}

function printTable(rows: SummaryRow[]): void {
  console.log("\nlogSguarDian — Attack Summary\n");

  if (rows.length === 0) {
    console.log("  No attack types classified in this range.\n");
    return;
  }

  let currentKey = "";
  for (const r of rows) {
    const key = `${r.path} (${r.method})`;
    if (key !== currentKey) {
      console.log(`  ${key}`);
      currentKey = key;
    }
    console.log("    " + r.severity.toUpperCase().padEnd(8) + r.predicted_class.padEnd(16) + String(r.count));
  }
  console.log();
}
