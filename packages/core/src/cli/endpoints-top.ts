import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";
import { requireConfig } from "./guard";
import type { MiddlewareOptions } from "../types";

const DEFAULT_LIMIT = 10;

interface EndpointRow {
  path: string;
  method: string;
  incident_count: number;
  risk_score: number;
}

/**
 * risk_score = incident_count * avg_confidence, rounded to 2 decimals.
 * Combines frequency (how often the route is attacked) with severity
 * (how confident the RF model was on those incidents) into a single
 * comparable number. An "incident" is any request classified as
 * verdict = 'block' or 'pass_anomaly' — the same set that triggers
 * webhooks, see docs/decision-policy.md §3.1.
 */
export function runEndpointsTop(args: string[]): void {
  const config = requireConfig() as unknown as MiddlewareOptions;

  const limit = (() => {
    const idx = args.indexOf("--limit");
    if (idx === -1) return DEFAULT_LIMIT;
    const n = parseInt(args[idx + 1], 10);
    return Number.isInteger(n) && n > 0 ? n : DEFAULT_LIMIT;
  })();

  const format = (() => {
    const idx = args.indexOf("--format");
    return idx !== -1 ? args[idx + 1] : "table";
  })();

  const dbPath = path.resolve(process.cwd(), config.dbPath ?? "logsguardian.db");

  if (!fs.existsSync(dbPath)) {
    console.error(`logsguardian: no database found at '${dbPath}'`);
    console.error("Run the middleware first to generate detection events.");
    process.exit(1);
  }

  const db = new Database(dbPath, { readonly: true });
  const rows = db
    .prepare(
      `
      SELECT
        path,
        method,
        COUNT(*) AS incident_count,
        AVG(confidence) AS avg_confidence
      FROM detection_events
      WHERE verdict IN ('block', 'pass_anomaly')
      GROUP BY path, method
      ORDER BY incident_count DESC
      LIMIT @limit
      `
    )
    .all({ limit }) as Array<{
      path: string;
      method: string;
      incident_count: number;
      avg_confidence: number;
    }>;
  db.close();

  const ranked: EndpointRow[] = rows.map((r) => ({
    path: r.path,
    method: r.method,
    incident_count: r.incident_count,
    risk_score: Math.round(r.incident_count * r.avg_confidence * 100) / 100,
  }));

  if (format === "json") {
    console.log(JSON.stringify(ranked, null, 2));
    return;
  }

  printTable(ranked);
}

function printTable(rows: EndpointRow[]): void {
  console.log("\nlogSguarDian — Top Endpoints by Attack Frequency\n");

  if (rows.length === 0) {
    console.log("  No detection events found.\n");
    return;
  }

  const methodWidth = Math.max(...rows.map((r) => r.method.length), 6);
  const pathWidth = Math.max(...rows.map((r) => r.path.length), 5);

  const header =
    "  " +
    "METHOD".padEnd(methodWidth + 2) +
    "ROUTE".padEnd(pathWidth + 2) +
    "INCIDENTS".padEnd(11) +
    "RISK SCORE";
  console.log(header);
  console.log("  " + "─".repeat(header.length - 2));

  for (const r of rows) {
    console.log(
      "  " +
        r.method.padEnd(methodWidth + 2) +
        r.path.padEnd(pathWidth + 2) +
        String(r.incident_count).padEnd(11) +
        r.risk_score.toFixed(2)
    );
  }
  console.log();
}
