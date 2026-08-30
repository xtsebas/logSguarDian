/**
 * PLAN.md F1.8 — extractFeatureVector() latency benchmark
 *
 * Measures per-request extraction latency across representative payloads
 * for all 5 classes (benign, sqli, xss, path_traversal, cmdi).
 * Gate criterion: p95 <= 1ms per request (mixed traffic).
 *
 * Serial measurement only (not burst-fire) — burst-fire measures queuing
 * artifacts, not per-request cost (see A15/A20 latency methodology note
 * in docs/results.md).
 *
 * Run from repo root (requires packages/extractor to be built):
 *   pnpm --filter @logsguardian/extractor build
 *   node benchmarks/extractor.bench.js
 */

"use strict";

const path = require("path");
const { extractFeatureVector, FEATURE_NAMES } = require(
  path.join(__dirname, "../packages/extractor/dist/index.js")
);

// CanonicalRequest.body is a string (not an object) — JSON bodies are
// stringified the same way middleware.ts does before calling the extractor.
const FIXTURES = [
  {
    label: "benign",
    req: {
      method: "GET",
      path: "/api/products",
      query: "category=electronics&sort=price&page=2",
      body: "",
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      contentType: "",
      referer: "https://example.com/shop",
      cookie: "session=abc123",
      extraHeaders: {},
    },
  },
  {
    label: "sqli",
    req: {
      method: "GET",
      path: "/api/users",
      query: "id=1' UNION SELECT username,password FROM users--",
      body: "",
      userAgent: "sqlmap/1.7",
      contentType: "",
      referer: "",
      cookie: "",
      extraHeaders: {},
    },
  },
  {
    label: "xss",
    req: {
      method: "POST",
      path: "/api/comments",
      query: "",
      body: JSON.stringify({ content: "<script>alert(document.cookie)</script>" }),
      userAgent: "Mozilla/5.0",
      contentType: "application/json",
      referer: "",
      cookie: "",
      extraHeaders: {},
    },
  },
  {
    label: "path_traversal",
    req: {
      method: "GET",
      path: "/api/files",
      query: "path=../../../../etc/passwd",
      body: "",
      userAgent: "curl/7.68.0",
      contentType: "",
      referer: "",
      cookie: "",
      extraHeaders: {},
    },
  },
  {
    label: "cmdi",
    req: {
      method: "POST",
      path: "/api/ping",
      query: "",
      body: JSON.stringify({ host: "127.0.0.1; cat /etc/passwd" }),
      userAgent: "python-requests/2.28.0",
      contentType: "application/x-www-form-urlencoded",
      referer: "",
      cookie: "",
      extraHeaders: {},
    },
  },
];

const WARMUP_ITERS = 200;
const BENCH_ITERS = 2000;

function percentile(sortedTimes, p) {
  return sortedTimes[Math.floor(sortedTimes.length * p)];
}

function measure(req, iters) {
  const times = new Array(iters);
  for (let i = 0; i < iters; i++) {
    const t0 = process.hrtime.bigint();
    extractFeatureVector(req);
    const t1 = process.hrtime.bigint();
    times[i] = Number(t1 - t0) / 1_000_000; // ns -> ms
  }
  return times;
}

function bench(label, req) {
  measure(req, WARMUP_ITERS); // warmup — discarded

  const times = measure(req, BENCH_ITERS).sort((a, b) => a - b);
  const p50 = percentile(times, 0.5);
  const p95 = percentile(times, 0.95);
  const p99 = percentile(times, 0.99);
  const mean = times.reduce((s, t) => s + t, 0) / times.length;
  const throughput = Math.round(1000 / mean);

  console.log(`\n  [${label}]`);
  console.log(`  mean:       ${mean.toFixed(4)} ms`);
  console.log(`  p50:        ${p50.toFixed(4)} ms`);
  console.log(`  p95:        ${p95.toFixed(4)} ms`);
  console.log(`  p99:        ${p99.toFixed(4)} ms`);
  console.log(`  throughput: ${throughput.toLocaleString()} req/s`);

  return { label, mean, p50, p95, p99, throughput };
}

function main() {
  console.log("=== logSguarDian — Extractor Benchmark (F1.8) ===");
  console.log(`Node ${process.version} | ${process.platform}/${process.arch}`);
  console.log(`Fixtures: ${FIXTURES.length} | Warmup: ${WARMUP_ITERS} | Bench: ${BENCH_ITERS} iters each`);
  console.log(`Feature vector dimension: ${FEATURE_NAMES.length}`);

  const results = FIXTURES.map(({ label, req }) => bench(label, req));

  // Mixed traffic pass — round-robin across all 5 fixtures, one combined
  // sample of BENCH_ITERS, for a representative production-like number.
  for (let i = 0; i < WARMUP_ITERS; i++) {
    extractFeatureVector(FIXTURES[i % FIXTURES.length].req);
  }
  const mixedTimes = new Array(BENCH_ITERS);
  for (let i = 0; i < BENCH_ITERS; i++) {
    const req = FIXTURES[i % FIXTURES.length].req;
    const t0 = process.hrtime.bigint();
    extractFeatureVector(req);
    const t1 = process.hrtime.bigint();
    mixedTimes[i] = Number(t1 - t0) / 1_000_000;
  }
  mixedTimes.sort((a, b) => a - b);
  const mixedP50 = percentile(mixedTimes, 0.5);
  const mixedP95 = percentile(mixedTimes, 0.95);
  const mixedP99 = percentile(mixedTimes, 0.99);
  const mixedMean = mixedTimes.reduce((s, t) => s + t, 0) / mixedTimes.length;
  const mixedThroughput = Math.round(1000 / mixedMean);

  console.log("\n=== SUMMARY ===");
  console.log("Criterion (PLAN.md F1.8): p95 <= 1ms per request");
  console.log("\n  Mixed traffic (all 5 classes, round-robin):");
  console.log(`  mean:       ${mixedMean.toFixed(4)} ms`);
  console.log(`  p50:        ${mixedP50.toFixed(4)} ms`);
  console.log(`  p95:        ${mixedP95.toFixed(4)} ms`);
  console.log(`  p99:        ${mixedP99.toFixed(4)} ms`);
  console.log(`  throughput: ${mixedThroughput.toLocaleString()} req/s`);
  console.log(`\n  GATE p95 <= 1ms: ${mixedP95 <= 1 ? "PASS ✓" : "FAIL ✗"}`);

  console.log("\nHardware:");
  console.log(`  Platform: ${process.platform}/${process.arch}`);
  console.log(`  Node:     ${process.version}`);
  const mem = process.memoryUsage();
  console.log(`  RSS:      ${(mem.rss / 1024 / 1024).toFixed(1)} MB`);

  return { results, mixed: { mean: mixedMean, p50: mixedP50, p95: mixedP95, p99: mixedP99, throughput: mixedThroughput } };
}

main();
