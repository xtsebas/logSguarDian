/**
 * Real memory footprint of the RF/IF worker-pool architecture WITH a 4th
 * worker added — a dedicated candidate-RF worker, the shape Fase 7's canary
 * shadow dispatch would add on top of the existing 1 RF + 2 IF pool.
 *
 * Extends onnx-memory-pool.bench.js's exact methodology (spawns the real
 * compiled worker.js via real worker_threads, same readiness handshake) by
 * one more `role: "rf"` worker pointed at the same modelDir. Loading rf.onnx
 * twice (as a stand-in for "production RF" + "candidate RF") is a valid
 * proxy for this measurement — the memory cost of a worker thread hosting
 * an RF-shaped ONNX session comes from the architecture/hyperparameters
 * (onnxruntime-node's per-thread native init + the tree ensemble's in-memory
 * size), not which specific trained weights are loaded, since a real
 * candidate would be the same n_estimators/max_depth family as production.
 *
 * Run (from repo root, after `pnpm --filter logsguardian build`):
 *   node benchmarks/onnx-memory-pool-canary.bench.js
 *
 * Gate: total process RSS ≤ 300 MB (unchanged — Fase 7 doesn't get a bigger
 * budget just because it's a new feature).
 */

"use strict";

const path = require("path");
const { Worker } = require("worker_threads");

const WORKER_PATH = path.join(__dirname, "../packages/core/dist/worker.js");
const MODEL_DIR = path.join(__dirname, "../training/models");
const IF_POOL_SIZE = 2; // must match middleware.ts's IF_POOL_SIZE

function gc() {
  if (typeof global.gc === "function") global.gc();
}

function snapshot(label) {
  gc();
  const mem = process.memoryUsage();
  console.log(`\n=== ${label} ===`);
  console.log(`RSS: ${(mem.rss / 1024 / 1024).toFixed(2)} MB`);
  return mem;
}

function spawnAndWaitReady(role) {
  return new Promise((resolve, reject) => {
    const w = new Worker(WORKER_PATH, { workerData: { role, modelDir: MODEL_DIR } });
    w.on("message", (msg) => {
      if (msg && msg.ready) resolve(w);
    });
    w.on("error", reject);
  });
}

async function main() {
  const baseline = snapshot("Baseline (main thread, before spawning any worker)");

  const rfWorker = await spawnAndWaitReady("rf");
  const afterRf = snapshot("After production RF worker ready (session loaded)");

  const ifWorkers = [];
  for (let i = 0; i < IF_POOL_SIZE; i++) {
    ifWorkers.push(await spawnAndWaitReady("if"));
  }
  const afterPool = snapshot(`After ${IF_POOL_SIZE} IF worker(s) ready (production baseline complete)`);

  const canaryRfWorker = await spawnAndWaitReady("rf");
  const afterCanary = snapshot("After candidate-RF (canary) worker ready");

  // Drive real inference through all 4 workers, same leak-check pattern as
  // onnx-memory-pool.bench.js, to catch any post-ready growth specific to
  // running a canary worker alongside the production pool.
  const canonical = {
    method: "GET", path: "/bench", query: "q=test", body: "",
    userAgent: "", contentType: "", referer: "", cookie: "", extraHeaders: {},
  };
  let id = 0;
  async function roundTrip(worker) {
    id++;
    const thisId = id;
    return new Promise((resolve) => {
      const handler = (msg) => {
        if (msg.id === thisId) { worker.off("message", handler); resolve(); }
      };
      worker.on("message", handler);
      worker.postMessage({ id: thisId, canonical });
    });
  }
  for (let i = 0; i < 200; i++) {
    await roundTrip(rfWorker);
    await roundTrip(ifWorkers[i % ifWorkers.length]);
    await roundTrip(canaryRfWorker);
  }
  const afterLoad = snapshot("After 200x round-trip per worker, including canary (leak check)");

  console.log("\n=== SUMMARY ===");
  const deltaRf = (afterRf.rss - baseline.rss) / 1024 / 1024;
  const deltaPool = (afterPool.rss - afterRf.rss) / 1024 / 1024;
  const deltaCanary = (afterCanary.rss - afterPool.rss) / 1024 / 1024;
  const deltaLoad = (afterLoad.rss - afterCanary.rss) / 1024 / 1024;
  const totalDelta = (afterLoad.rss - baseline.rss) / 1024 / 1024;
  const productionOnlyRss = afterPool.rss / 1024 / 1024;
  const withCanaryRss = afterLoad.rss / 1024 / 1024;

  console.log(`Δ RSS from production RF worker (fixed cost, once per process): ${deltaRf.toFixed(2)} MB`);
  console.log(`Δ RSS from ${IF_POOL_SIZE} IF worker(s):                                 ${deltaPool.toFixed(2)} MB`);
  console.log(`Production baseline (1 RF + ${IF_POOL_SIZE} IF), fully warm:             ${productionOnlyRss.toFixed(2)} MB`);
  console.log(`Δ RSS from adding the candidate-RF (canary) worker:              ${deltaCanary.toFixed(2)} MB  <-- the number this benchmark exists to measure`);
  console.log(`Δ RSS from 200x round-trips incl. canary (leak check):           ${deltaLoad.toFixed(2)} MB`);
  console.log(`Total process RSS with canary worker active, fully warm:        ${withCanaryRss.toFixed(2)} MB`);
  console.log(`\nGATE (total RSS with canary ≤ 300 MB): ${withCanaryRss <= 300 ? "PASS ✓" : "FAIL ✗"}`);
  console.log(`Margin with canary active: ${(300 - withCanaryRss).toFixed(2)} MB`);

  if (deltaLoad > 5) {
    console.log(`\nWARNING: ${deltaLoad.toFixed(2)} MB growth over 200 round-trips may indicate a leak.`);
  }

  process.exit(0);
}

main().catch((err) => { console.error(err); process.exit(1); });
