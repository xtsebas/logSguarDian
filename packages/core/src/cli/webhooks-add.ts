import * as path from "path";
import { requireConfig } from "./guard";
import { WebhookStore } from "../webhook-store";
import type { MiddlewareOptions } from "../types";

export function runWebhooksAdd(args: string[]): void {
  const config = requireConfig() as unknown as MiddlewareOptions;

  const url = args[0];
  if (!url) {
    console.error("Usage: logsguardian webhooks add <url>");
    process.exit(1);
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    console.error(`logsguardian: invalid URL '${url}'`);
    process.exit(1);
  }

  if (parsed.protocol !== "https:") {
    console.error(
      `logsguardian: webhook URL must be HTTPS, got '${parsed.protocol.replace(":", "")}' (${url})`
    );
    process.exit(1);
  }

  const dbPath = path.resolve(process.cwd(), config.dbPath ?? "logsguardian.db");
  const store = new WebhookStore(dbPath);
  const id = store.add(url);
  store.close();

  console.log(`Registered webhook #${id}: ${url}`);
}
