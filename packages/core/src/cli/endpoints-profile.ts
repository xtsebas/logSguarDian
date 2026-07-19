import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";
import { requireConfig } from "./guard";
import type { MiddlewareOptions } from "../types";

interface AttackTypeRow {
  predicted_class: string;
  count: number;
}

interface HourlyRow {
  hour: number;
  count: number;
}

interface IpRow {
  client_ip: string;
  count: number;
}

interface RouteProfile {
  path: string;
  total_incidents: number;
  block_count: number;
  pass_anomaly_count: number;
  methods: Array<{ method: string; count: number }>;
  attack_types: AttackTypeRow[];
  hourly_distribution: HourlyRow[];
  top_source_ips: IpRow[];
  source_ranges: IpRow[];
}

/** First 3 octets of an IPv4 address, e.g. '203.0.113.5' -> '203.0.113.0/24'. Non-IPv4 values pass through unchanged. */
function toSubnet(ip: string): string {
  const parts = ip.split(".");
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p))) return ip;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

export function runEndpointsProfile(args: string[]): void {
  const config = requireConfig() as unknown as MiddlewareOptions;

  const route = args.find((a) => !a.startsWith("--"));
  if (!route) {
    console.error("Usage: logsguardian endpoints profile <route> [--method <METHOD>] [--format table|json]");
    process.exit(1);
  }

  const method = (() => {
    const idx = args.indexOf("--method");
    return idx !== -1 ? args[idx + 1].toUpperCase() : undefined;
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
  const whereClauses = ["path = @route", "verdict IN ('block', 'pass_anomaly')"];
  const params: Record<string, unknown> = { route };
  if (method) {
    whereClauses.push("method = @method");
    params.method = method;
  }
  const where = whereClauses.join(" AND ");

  const totals = db
    .prepare(`SELECT verdict, COUNT(*) AS count FROM detection_events WHERE ${where} GROUP BY verdict`)
    .all(params) as Array<{ verdict: string; count: number }>;

  const methods = db
    .prepare(`SELECT method, COUNT(*) AS count FROM detection_events WHERE ${where} GROUP BY method ORDER BY count DESC`)
    .all(params) as Array<{ method: string; count: number }>;

  const attackTypes = db
    .prepare(
      `SELECT predicted_class, COUNT(*) AS count FROM detection_events WHERE ${where} GROUP BY predicted_class ORDER BY count DESC`
    )
    .all(params) as AttackTypeRow[];

  const hourly = db
    .prepare(
      `SELECT CAST(strftime('%H', timestamp / 1000, 'unixepoch') AS INTEGER) AS hour, COUNT(*) AS count
       FROM detection_events WHERE ${where} GROUP BY hour ORDER BY hour ASC`
    )
    .all(params) as HourlyRow[];

  const topIps = db
    .prepare(
      `SELECT client_ip, COUNT(*) AS count FROM detection_events WHERE ${where} AND client_ip != ''
       GROUP BY client_ip ORDER BY count DESC LIMIT 10`
    )
    .all(params) as IpRow[];

  db.close();

  const rangeCounts = new Map<string, number>();
  for (const row of topIps) {
    const subnet = toSubnet(row.client_ip);
    rangeCounts.set(subnet, (rangeCounts.get(subnet) ?? 0) + row.count);
  }
  const sourceRanges: IpRow[] = Array.from(rangeCounts.entries())
    .map(([client_ip, count]) => ({ client_ip, count }))
    .sort((a, b) => b.count - a.count);

  const blockCount = totals.find((t) => t.verdict === "block")?.count ?? 0;
  const anomalyCount = totals.find((t) => t.verdict === "pass_anomaly")?.count ?? 0;

  const profile: RouteProfile = {
    path: route,
    total_incidents: blockCount + anomalyCount,
    block_count: blockCount,
    pass_anomaly_count: anomalyCount,
    methods,
    attack_types: attackTypes,
    hourly_distribution: hourly,
    top_source_ips: topIps,
    source_ranges: sourceRanges,
  };

  if (format === "json") {
    console.log(JSON.stringify(profile, null, 2));
    return;
  }

  printProfile(profile);
}

function printProfile(p: RouteProfile): void {
  console.log(`\nlogSguarDian — Route Profile: ${p.path}\n`);

  if (p.total_incidents === 0) {
    console.log("  No detection events found for this route.\n");
    return;
  }

  console.log(`  Total incidents: ${p.total_incidents} (block: ${p.block_count}, pass_anomaly: ${p.pass_anomaly_count})`);
  console.log(`  Methods: ${p.methods.map((m) => `${m.method} (${m.count})`).join(", ")}`);

  console.log("\n  Attack types:");
  for (const t of p.attack_types) {
    console.log(`    ${t.predicted_class.padEnd(16)}${t.count}`);
  }

  console.log("\n  Hourly distribution (UTC):");
  for (const h of p.hourly_distribution) {
    console.log(`    ${String(h.hour).padStart(2, "0")}:00${" ".repeat(11)}${h.count}`);
  }

  console.log("\n  Top source IPs:");
  if (p.top_source_ips.length === 0) {
    console.log("    (no client_ip recorded for these events)");
  } else {
    for (const ip of p.top_source_ips) {
      console.log(`    ${ip.client_ip.padEnd(20)}${ip.count}`);
    }
  }

  console.log("\n  Source ranges (/24):");
  if (p.source_ranges.length === 0) {
    console.log("    (no client_ip recorded for these events)");
  } else {
    for (const r of p.source_ranges) {
      console.log(`    ${r.client_ip.padEnd(20)}${r.count}`);
    }
  }
  console.log();
}
