/**
 * PLAN.md F4.4 — ONNX session memory footprint in Node.js
 *
 * Measures RSS delta from baseline → both models loaded → warmup → 2000 calls.
 * Gate criterion: total Δ RSS ≤ 300 MB (revised — see docs/results.md §F4.4).
 *
 * Run from repo root:
 *   node benchmarks/onnx-memory.bench.js
 *
 * Run with explicit GC for cleaner deltas (if results are ambiguous):
 *   node --expose-gc benchmarks/onnx-memory.bench.js
 */

"use strict";

const path = require("path");
const ort = require(
  path.join(__dirname, "../node_modules/.pnpm/onnxruntime-node@1.26.0/node_modules/onnxruntime-node")
);

const MODEL_DIR = path.join(__dirname, "../training/models");
const RF_N_FEATURES = 67;
const IF_N_FEATURES = 61;

function gc() {
  if (typeof global.gc === "function") global.gc();
}

function snapshot(label) {
  gc();
  const mem = process.memoryUsage();
  console.log(`\n=== ${label} ===`);
  console.log(`RSS:          ${(mem.rss / 1024 / 1024).toFixed(2)} MB`);
  console.log(`Heap Used:    ${(mem.heapUsed / 1024 / 1024).toFixed(2)} MB`);
  console.log(`Heap Total:   ${(mem.heapTotal / 1024 / 1024).toFixed(2)} MB`);
  console.log(`External:     ${(mem.external / 1024 / 1024).toFixed(2)} MB`);
  console.log(`ArrayBuffers: ${(mem.arrayBuffers / 1024 / 1024).toFixed(2)} MB`);
  return mem;
}

async function main() {
  const baseline = snapshot("Baseline (before loading models)");

  const rfSession = await ort.InferenceSession.create(
    path.join(MODEL_DIR, "rf.onnx")
  );
  const afterRf = snapshot("After loading rf.onnx");

  const ifSession = await ort.InferenceSession.create(
    path.join(MODEL_DIR, "if.onnx")
  );
  const afterIf = snapshot("After loading if.onnx");

  const rfDummy = new ort.Tensor(
    "float32",
    new Float32Array(RF_N_FEATURES),
    [1, RF_N_FEATURES]
  );
  const ifDummy = new ort.Tensor(
    "float32",
    new Float32Array(IF_N_FEATURES),
    [1, IF_N_FEATURES]
  );

  for (let i = 0; i < 10; i++) {
    await rfSession.run({ float_input: rfDummy });
    await ifSession.run({ float_input: ifDummy });
  }
  const afterWarmup = snapshot("After warmup (10x inference each)");

  for (let i = 0; i < 1000; i++) {
    await rfSession.run({ float_input: rfDummy });
    await ifSession.run({ float_input: ifDummy });
  }
  const afterLoad = snapshot("After 1000x inference each (leak check)");

  console.log("\n=== SUMMARY ===");
  const mb = (b) => (b / 1024 / 1024).toFixed(2);
  const deltaModels = (afterIf.rss - baseline.rss) / 1024 / 1024;
  const deltaWarmup = (afterWarmup.rss - afterIf.rss) / 1024 / 1024;
  const deltaLoad   = (afterLoad.rss - afterWarmup.rss) / 1024 / 1024;
  const totalDelta  = (afterLoad.rss - baseline.rss) / 1024 / 1024;

  console.log(`Δ RSS from loading both models:     ${deltaModels.toFixed(2)} MB`);
  console.log(`Δ RSS from warmup (20 calls):        ${deltaWarmup.toFixed(2)} MB`);
  console.log(`Δ RSS from 2000 calls (leak check):  ${deltaLoad.toFixed(2)} MB`);
  console.log(`Total Δ RSS (baseline → fully warm): ${totalDelta.toFixed(2)} MB`);
  console.log(
    `\nGATE F4.4 (≤ 300 MB): ${totalDelta <= 300 ? "PASS ✓" : "FAIL ✗"}`
  );

  if (deltaLoad > 5) {
    console.log(
      `\nWARNING: ${deltaLoad.toFixed(2)} MB growth over 2000 calls ` +
        `may indicate a leak. Re-run with --expose-gc to confirm.`
    );
  }
}

main().catch(console.error);
