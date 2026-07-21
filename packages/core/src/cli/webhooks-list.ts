import * as path from "path";
import { requireConfig } from "./guard";
import { WebhookStore } from "../webhook-store";
import type { MiddlewareOptions } from "../types";

export function runWebhooksList(args: string[]): void {
  const config = requireConfig() as unknown as MiddlewareOptions;

  const format = (() => {
    const idx = args.indexOf("--format");
    return idx !== -1 ? args[idx + 1] : "table";
  })();

  const dbPath = path.resolve(process.cwd(), config.dbPath ?? "logsguardian.db");
  const store = new WebhookStore(dbPath);
  const rows = store.list();
  store.close();

  if (format === "json") {
    console.log(
      JSON.stringify(
        rows.map((r) => ({
          id: r.id,
          url: r.url,
          created_at: new Date(r.created_at).toISOString(),
          status: r.status,
        })),
        null,
        2
      )
    );
    return;
  }

  printTable(rows);
}

function printTable(rows: ReturnType<WebhookStore["list"]>): void {
  console.log("\nlogSguarDian — Registered Webhooks\n");

  if (rows.length === 0) {
    console.log("  No webhooks registered.");
    console.log("  Run 'logsguardian webhooks add <url>' to register one.\n");
    return;
  }

  const idW = 6;
  const statusW = 10;
  const dateW = 25;

  console.log("  " + "ID".padEnd(idW) + "STATUS".padEnd(statusW) + "CREATED".padEnd(dateW) + "URL");
  console.log("  " + "─".repeat(idW + statusW + dateW + 20));
  for (const r of rows) {
    const created = new Date(r.created_at).toISOString().replace("T", " ").slice(0, 19) + " UTC";
    console.log("  " + String(r.id).padEnd(idW) + r.status.padEnd(statusW) + created.padEnd(dateW) + r.url);
  }
  console.log();
}
