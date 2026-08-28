#!/usr/bin/env node
/**
 * Fase 2 of the CT/CI/CD pipeline — simulates N independent logsguardian
 * deployments ("hosts") sending real traffic (the e2e benign+attack corpus)
 * through the actual middleware, each with `telemetryUrl` pointed at a
 * shared MLOps collector and a distinct `sourceId`. Demonstrates that a
 * central collector accumulates vectors from multiple distinct sources
 * without needing real users — see packages/mlops/collector.
 *
 * Run: pnpm --filter @logsguardian/mlops run simulate-fleet
 */
import * as fs from "fs";
import * as path from "path";
import express from "express";
import request from "supertest";
import { logsguardian } from "logsguardian";
import { createCollectorApp } from "./collector/server";

const FLEET_SIZE = 5;
const MODEL_DIR = path.resolve(__dirname, "..", "..", "..", "training", "models");
const FIXTURES_PATH = path.resolve(__dirname, "..", "..", "..", "e2e", "fixtures", "test_payloads.jsonl");
const TELEMETRY_DRAIN_MS = 2000;

interface FixtureRecord {
  method: string;
  path: string;
  query: string;
  body: string | null;
  userAgent: string;
  contentType: string;
  referer: string;
  cookie: string;
  _expected_class: string;
}

function loadFixtures(): FixtureRecord[] {
  return fs
    .readFileSync(FIXTURES_PATH, "utf-8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

/** Splits payloads round-robin across N simulated hosts. */
function partitionByHost(records: FixtureRecord[], hostCount: number): FixtureRecord[][] {
  const buckets: FixtureRecord[][] = Array.from({ length: hostCount }, () => []);
  records.forEach((rec, i) => buckets[i % hostCount].push(rec));
  return buckets;
}

function createSimulatedHost(sourceId: string, telemetryUrl: string): express.Express {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(
    logsguardian({
      mode: "monitor",
      modelDir: MODEL_DIR,
      timeoutMs: 10000,
      dbPath: ":memory:",
      telemetryUrl,
      sourceId,
    })
  );
  app.all(/.*/, (_req, res) => res.json({ status: "ok" }));
  return app;
}

async function sendPayload(app: express.Express, rec: FixtureRecord): Promise<void> {
  const hasBody = typeof rec.body === "string" && rec.body.length > 0;
  const rawMethod = (rec.method || (hasBody ? "POST" : "GET")).toLowerCase();
  const SUPPORTED_METHODS = ["get", "post", "put", "delete", "patch"] as const;
  const method = (SUPPORTED_METHODS as readonly string[]).includes(rawMethod)
    ? (rawMethod as (typeof SUPPORTED_METHODS)[number])
    : "get";
  const urlPath = rec.path ? (rec.path.startsWith("/") ? rec.path : `/${rec.path}`) : "/";
  const fullPath = rec.query ? `${urlPath}?${rec.query}` : urlPath;

  let req = request(app)[method](fullPath);
  if (rec.userAgent) req = req.set("User-Agent", rec.userAgent);
  if (rec.contentType) req = req.set("Content-Type", rec.contentType);
  if (rec.referer) req = req.set("Referer", rec.referer);
  if (hasBody) req = req.send(rec.body as string);

  try {
    await req;
  } catch {
    // A single malformed fixture request must not abort the whole run.
  }
}

async function main(): Promise<void> {
  const { app: collectorApp, store } = createCollectorApp({ dbPath: ":memory:" });
  const collectorServer = collectorApp.listen(0);
  await new Promise<void>((resolve) => collectorServer.once("listening", resolve));
  const { port } = collectorServer.address() as { port: number };
  const telemetryUrl = `http://127.0.0.1:${port}/telemetry`;

  const fixtures = loadFixtures();
  const buckets = partitionByHost(fixtures, FLEET_SIZE);

  console.log(`Simulating ${FLEET_SIZE} hosts against collector at ${telemetryUrl}`);
  console.log(`Traffic corpus: ${fixtures.length} records from e2e/fixtures/test_payloads.jsonl\n`);

  await Promise.all(
    buckets.map(async (records, i) => {
      const sourceId = `sim-host-${i + 1}`;
      const app = createSimulatedHost(sourceId, telemetryUrl);
      for (const rec of records) {
        await sendPayload(app, rec);
      }
      console.log(`  ${sourceId}: sent ${records.length} requests`);
    })
  );

  // Telemetry is fire-and-forget — give in-flight POSTs time to land before reading the store.
  await new Promise((resolve) => setTimeout(resolve, TELEMETRY_DRAIN_MS));

  console.log(`\nCollector accumulated ${store.count()} telemetry events`);
  console.log(`Distinct sources seen: ${store.sources().join(", ")}`);

  store.close();
  collectorServer.close();
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
