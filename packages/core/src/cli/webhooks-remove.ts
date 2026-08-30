import * as path from "path";
import { requireConfig } from "./guard";
import { WebhookStore } from "../webhook-store";
import type { MiddlewareOptions } from "../types";

export function runWebhooksRemove(args: string[]): void {
  const config = requireConfig() as unknown as MiddlewareOptions;

  const raw = args[0];
  if (raw === undefined) {
    console.error("logsguardian: webhooks remove requires an id argument");
    console.error("Usage: logsguardian webhooks remove <id>");
    process.exit(1);
  }
  const id = parseInt(raw, 10);
  if (!Number.isInteger(id) || String(id) !== raw) {
    console.error(`logsguardian: invalid id '${raw}' — must be a positive integer`);
    console.error("Usage: logsguardian webhooks remove <id>");
    process.exit(1);
  }

  const dbPath = path.resolve(process.cwd(), config.dbPath ?? "logsguardian.db");
  const store = new WebhookStore(dbPath);
  const removed = store.remove(id);
  store.close();

  if (!removed) {
    console.error(`logsguardian: webhook #${id} not found`);
    process.exit(1);
  }

  console.log(`Removed webhook #${id}`);
}
