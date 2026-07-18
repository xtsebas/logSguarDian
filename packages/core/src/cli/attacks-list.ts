import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";
import { requireConfig } from "./guard";
import type { MiddlewareOptions } from "../types";

interface AttackTypeRow {
  predicted_class: string;
  total_count: number;
  last_detected: number;
}

/**
 * Catalogs by predicted_class (what the RF classified), not by verdict.
 * A low-confidence sqli classification that ultimately passed still shows
 * up here — this answers "what has the model seen", not "what did we block"
 * (that's the `endpoints` incident set, verdict IN block/pass_anomaly).
 * 'benign' is excluded — it is not an attack type.
 */
export function runAttacksList(args: string[]): void {
  const config = requireConfig() as unknown as MiddlewareOptions;

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
      `SELECT predicted_class, COUNT(*) AS total_count, MAX(timestamp) AS last_detected
       FROM detection_events
       WHERE predicted_class != 'benign'
       GROUP BY predicted_class
       ORDER BY total_count DESC`
    )
    .all() as AttackTypeRow[];
  db.close();

  if (format === "json") {
    console.log(JSON.stringify(rows, null, 2));
    return;
  }

  printTable(rows);
}

function printTable(rows: AttackTypeRow[]): void {
  console.log("\nlogSguarDian — Attack Type Catalog\n");

  if (rows.length === 0) {
    console.log("  No attack types classified yet.\n");
    return;
  }

  const typeWidth = Math.max(...rows.map((r) => r.predicted_class.length), 4);

  console.log("  " + "TYPE".padEnd(typeWidth + 2) + "TOTAL COUNT".padEnd(13) + "LAST DETECTED (UTC)");
  console.log("  " + "─".repeat(typeWidth + 2 + 13 + 22));
  for (const r of rows) {
    console.log(
      "  " +
        r.predicted_class.padEnd(typeWidth + 2) +
        String(r.total_count).padEnd(13) +
        new Date(r.last_detected).toISOString()
    );
  }
  console.log();
}
