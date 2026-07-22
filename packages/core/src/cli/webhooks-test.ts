import * as path from "path";
import { requireConfig } from "./guard";
import { WebhookStore } from "../webhook-store";
import { sendWebhook } from "../webhook";
import type { MiddlewareOptions, DetectionEvent } from "../types";

/** Same shape as a real DetectionEvent (see types.ts) — sent to prove the destination is reachable. */
function buildTestPayload(): DetectionEvent {
  return {
    timestamp: Date.now(),
    method: "GET",
    path: "/logsguardian-test",
    query_string: "test=true",
    user_agent: "logsguardian-webhook-test/1.0",
    client_ip: "127.0.0.1",
    verdict: "block",
    predicted_class: "sqli",
    confidence: 0.99,
    if_score: -0.1,
    is_anomaly: false,
    webhook_sent: false,
    elapsed_ms: 0,
  };
}

export async function runWebhooksTest(args: string[]): Promise<void> {
  const config = requireConfig() as unknown as MiddlewareOptions;

  const raw = args[0];
  const id = raw !== undefined ? parseInt(raw, 10) : NaN;
  if (raw === undefined || !Number.isInteger(id) || String(id) !== raw) {
    console.error("Usage: logsguardian webhooks test <id>");
    process.exit(1);
  }

  const dbPath = path.resolve(process.cwd(), config.dbPath ?? "logsguardian.db");
  const store = new WebhookStore(dbPath);
  const webhook = store.getById(id);
  store.close();

  if (!webhook) {
    console.error(`logsguardian: webhook #${id} not found`);
    process.exit(1);
  }

  console.log(`Sending test payload to webhook #${id}: ${webhook.url}`);

  const status = await sendWebhook(webhook.url, buildTestPayload());

  if (status === null) {
    console.log("No response received (network error or timeout).");
    process.exit(1);
  }

  console.log(`Response: HTTP ${status}`);
  if (status >= 200 && status < 300) {
    console.log("Webhook delivered successfully.");
  } else {
    console.log("Webhook endpoint returned a non-2xx status.");
  }
}
