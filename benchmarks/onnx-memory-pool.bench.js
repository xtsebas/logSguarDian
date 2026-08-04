/**
 * Real memory footprint of the RF/IF worker-pool architecture
 * (1 dedicated RF worker_thread + IF_POOL_SIZE dedicated IF worker_threads,
 * readiness-gated — see packages/core/src/middleware.ts / worker.ts).
 *
 * Unlike benchmarks/onnx-memory.bench.js (F4.4's historical same-thread
 * measurement, kept as-is for the record — see docs/decision-policy.md,
 * docs/results.md), this spawns the actual compiled worker.js via real
 * worker_threads, matching production exactly: same readiness handshake,
 * same role-flag dispatch, same IF_POOL_SIZE.
 *
 * Run (from repo root, after `pnpm --filter logsguardian build`):
 *   node benchmarks/onnx-memory-pool.bench.js
 *
 * Gate: total process RSS ≤ 300 MB, with real margin.
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
  const afterRf = snapshot("After RF worker ready (session loaded)");

  const ifWorkers = [];
  for (let i = 0; i < IF_POOL_SIZE; i++) {
    ifWorkers.push(await spawnAndWaitReady("if"));
  }
  const afterPool = snapshot(`After ${IF_POOL_SIZE} IF worker(s) ready`);

  // Drive real inference through the pool the same way the middleware does,
  // to catch any post-ready growth (leak check equivalent to F4.4's 1000x loop).
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
  }
  const afterLoad = snapshot("After 200x round-trip per worker (leak check)");

  console.log("\n=== SUMMARY ===");
  const deltaRf = (afterRf.rss - baseline.rss) / 1024 / 1024;
  const deltaPool = (afterPool.rss - afterRf.rss) / 1024 / 1024;
  const deltaLoad = (afterLoad.rss - afterPool.rss) / 1024 / 1024;
  const totalDelta = (afterLoad.rss - baseline.rss) / 1024 / 1024;

  console.log(`Δ RSS from RF worker (session load, one-time fixed cost):  ${deltaRf.toFixed(2)} MB`);
  console.log(`Δ RSS from ${IF_POOL_SIZE} IF worker(s):                          ${deltaPool.toFixed(2)} MB`);
  console.log(`Δ RSS from 200x round-trips per worker (leak check):        ${deltaLoad.toFixed(2)} MB`);
  console.log(`Total process RSS (baseline → fully warm pool):             ${(afterLoad.rss / 1024 / 1024).toFixed(2)} MB`);
  console.log(`\nGATE (total RSS ≤ 300 MB): ${afterLoad.rss / 1024 / 1024 <= 300 ? "PASS ✓" : "FAIL ✗"}`);
  console.log(`Margin: ${(300 - afterLoad.rss / 1024 / 1024).toFixed(2)} MB`);

  if (deltaLoad > 5) {
    console.log(`\nWARNING: ${deltaLoad.toFixed(2)} MB growth over 200 round-trips may indicate a leak.`);
  }

  process.exit(0);
}

main().catch((err) => { console.error(err); process.exit(1); });
