import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";
import { requireConfig } from "./guard";
import type { MiddlewareOptions } from "../types";

interface AttackTypeCount {
  predicted_class: string;
  count: number;
}

interface EndpointReportRow {
  path: string;
  method: string;
  incident_count: number;
  block_count: number;
  pass_anomaly_count: number;
  risk_score: number;
  top_attack_class: string;
  attack_types: AttackTypeCount[];
  top_source_ip: string;
}

export function runEndpointsReport(args: string[]): void {
  const config = requireConfig() as unknown as MiddlewareOptions;

  const format = (() => {
    const idx = args.indexOf("--format");
    const f = idx !== -1 ? args[idx + 1] : "json";
    if (f !== "json" && f !== "csv") {
      console.error(`logsguardian: --format must be 'json' or 'csv', got '${f}'`);
      process.exit(1);
    }
    return f;
  })();

  const outputPath = (() => {
    const idx = args.indexOf("--output");
    return idx !== -1 ? args[idx + 1] : undefined;
  })();

  const dbPath = path.resolve(process.cwd(), config.dbPath ?? "logsguardian.db");

  if (!fs.existsSync(dbPath)) {
    console.error(`logsguardian: no database found at '${dbPath}'`);
    console.error("Run the middleware first to generate detection events.");
    process.exit(1);
  }

  const db = new Database(dbPath, { readonly: true });

  const routes = db
    .prepare(
      `SELECT
         path,
         method,
         COUNT(*) AS incident_count,
         SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END) AS block_count,
         SUM(CASE WHEN verdict = 'pass_anomaly' THEN 1 ELSE 0 END) AS pass_anomaly_count,
         AVG(confidence) AS avg_confidence
       FROM detection_events
       WHERE verdict IN ('block', 'pass_anomaly')
       GROUP BY path, method
       ORDER BY incident_count DESC`
    )
    .all() as Array<{
      path: string;
      method: string;
      incident_count: number;
      block_count: number;
      pass_anomaly_count: number;
      avg_confidence: number;
    }>;

  const attackTypeStmt = db.prepare(
    `SELECT predicted_class, COUNT(*) AS count
     FROM detection_events
     WHERE path = @path AND method = @method AND verdict IN ('block', 'pass_anomaly')
     GROUP BY predicted_class ORDER BY count DESC`
  );

  const topIpStmt = db.prepare(
    `SELECT client_ip, COUNT(*) AS count
     FROM detection_events
     WHERE path = @path AND method = @method AND verdict IN ('block', 'pass_anomaly') AND client_ip != ''
     GROUP BY client_ip ORDER BY count DESC LIMIT 1`
  );

  const rows: EndpointReportRow[] = routes.map((r) => {
    const attackTypes = attackTypeStmt.all({ path: r.path, method: r.method }) as AttackTypeCount[];
    const topIp = topIpStmt.get({ path: r.path, method: r.method }) as
      | { client_ip: string; count: number }
      | undefined;
    return {
      path: r.path,
      method: r.method,
      incident_count: r.incident_count,
      block_count: r.block_count,
      pass_anomaly_count: r.pass_anomaly_count,
      risk_score: Math.round(r.incident_count * r.avg_confidence * 100) / 100,
      top_attack_class: attackTypes[0]?.predicted_class ?? "",
      attack_types: attackTypes,
      top_source_ip: topIp?.client_ip ?? "",
    };
  });

  db.close();

  const output = format === "json" ? toJson(rows) : toCsv(rows);

  if (outputPath) {
    const resolvedOutput = path.resolve(process.cwd(), outputPath);
    fs.writeFileSync(resolvedOutput, output, "utf-8");
    console.log(`Wrote ${rows.length} route(s) to ${resolvedOutput}`);
  } else {
    console.log(output);
  }
}

function toJson(rows: EndpointReportRow[]): string {
  return JSON.stringify(rows, null, 2);
}

const CSV_HEADERS = [
  "path",
  "method",
  "incident_count",
  "block_count",
  "pass_anomaly_count",
  "risk_score",
  "top_attack_class",
  "attack_types",
  "top_source_ip",
];

function csvEscape(value: string | number): string {
  const s = String(value);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function toCsv(rows: EndpointReportRow[]): string {
  const lines = [CSV_HEADERS.join(",")];
  for (const r of rows) {
    const attackTypesCell = r.attack_types.map((t) => `${t.predicted_class}:${t.count}`).join(";");
    lines.push(
      [
        r.path,
        r.method,
        r.incident_count,
        r.block_count,
        r.pass_anomaly_count,
        r.risk_score,
        r.top_attack_class,
        attackTypesCell,
        r.top_source_ip,
      ]
        .map(csvEscape)
        .join(",")
    );
  }
  return lines.join("\n");
}
