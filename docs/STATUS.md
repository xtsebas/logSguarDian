# logSguarDian — Repository Status Report
**Date:** 2026-06-14 (updated from 2026-06-11 original)  
**Auditor:** Library engineer  
**Branch:** main  

---

## Section 1 — What exists and works

| Artifact | Phase | Verified |
|----------|-------|---------|
| `packages/extractor/src/` — 72-feature TS extractor (7 source files) | F1.2–1.5 | 21/21 tests pass |
| `packages/extractor/src/cli.ts` — batch CLI `extractor <in.jsonl> <out.csv>` | F1.7 | Built, tested |
| `packages/extractor/dist/` — compiled JS (gitignored, rebuild with `npm run build`) | F1.7 | Clean build |
| `training/parsers/parse_*.py` — 7 parsers, flat CanonicalRequest output | F2.2 | All regenerated |
| `training/data_clean/*.jsonl` — 7 source JSONL files (~974K total raw records) | F2.2 | Present |
| `training/unify.py` — dedup (exact + near-dup), produces `unified.jsonl` | F2.4 | 399,642 rows after dedup |
| `training/split.py` — stratified 70/15/15 split by class+source | F2.6 | All 3 checks pass |
| `training/splits/test.lock.sha256` | F2.7 GATE | Committed before training |
| `training/models/rf_v1.pkl` — Random Forest (100 trees, max_depth=40) | F3.2 | Trained, macro F1=0.975 on val |
| `training/models/if_v1.pkl` — Isolation Forest (200 trees, benign-only) | F3.5 | recall=0.665, FP=0.099 on val |
| `training/models/rf.onnx` — RF exported, opset 17 | F4.1 | max_prob_diff=1.6e-7 |
| `training/models/if.onnx` — IF exported, opset 17/ml=3 | F4.1 | max_score_diff=1.9e-7 |
| `training/models/parity_report.json` — parity_passed=true, n_features=66 | F4.4 GATE | **CLEARED** |
| `training/results/baseline_results.csv`, `rf_confusion_matrix.png`, `if_recall_fp_curve.png` | F3 | Present |
| `training/notebooks/02–05_*.ipynb` — all 4 executed cleanly | F3–F4 | All gates pass |
| `training/FEATURE_NOTES.md` — documents the 6 excluded features and 66-dim contract | — | Present |

---

## Section 2 — What exists but needs work

### LOW: `packages/extractor` node_modules not installed in fresh clone
Run `npm install` in `packages/extractor/` before building. The root workspace has no shared dependency installation script yet.

### LOW: Split parquets are gitignored and must be regenerated
`training/splits/train|val|test.parquet` are excluded by `.gitignore`. After a fresh clone, regenerate by running:
```
python3 training/unify.py
node packages/extractor/dist/cli.js training/data_clean/unified.jsonl training/data_clean/features.csv
python3 -c "import pandas as pd; df=pd.read_csv(...) ... df.to_parquet(...)"   # see pipeline docs
python3 training/split.py
```
(A `Makefile` or `pipeline.sh` for this is missing — not yet implemented.)

---

## Section 3 — What does not exist yet

| Artifact | Phase | Blocked by |
|----------|-------|-----------|
| `packages/core/` — middleware, worker_thread, SQLite store | F5 | Nothing — parity CLEARED |
| `docs/api.md` — public middleware API design | F5.1 | Unblocked |
| `docs/decision-policy.md` — hybrid RF+IF decision logic | F3.7 | Unblocked (F3 done) |
| `.github/workflows/ci.yml` — CI pipeline | F0.4 | Unblocked |
| `benchmarks/` — extractor and load benchmarks | F1.8, F6 | F1.8 unblocked; F6 blocked on F5 |
| `datasets/splits/test.lock.sha256` | F2.7 | Done (in `training/splits/`) |
| E2E detection test suite | F5.7 GATE | F5 complete |
| Artillery load benchmarks | F6 | F5 complete |
| npm package publishing workflow | F7.4 | F6 GATE |

---

## Section 4 — Next actions (updated)

### Action 1 — Build `packages/core/` middleware (LIBRARY ENGINEER)
`parity_report.json` is cleared. Build `src/worker.ts` (loads ONNX sessions, exposes inference queue), `src/middleware.ts` (normalizes req → CanonicalRequest, calls extractor, dispatches to worker), `src/store.ts` (SQLite event log), `src/types.ts` (public API).

Key contracts from `parity_report.json`:
- `n_features = 66` — drop the 6 excluded features before passing vector to ONNX
- `threshold_if = 0.0445` — IF score < threshold → anomaly flag (if_v2, post-retrain)
- `if_onnx_output_index = 1` — scores are at output index 1, not 0
- `rf_onnx_output_index = 1` — probabilities are at output index 1
- `rf_classes = ["benign","cmdi","path_traversal","sqli","xss"]` — class order in proba vector

### Action 2 — Document decision policy (DIEGO or BOTH)
`docs/decision-policy.md` — how RF and IF verdicts combine. Draft pseudocode based on F3.7 from PLAN.md before the middleware wires the logic.

### Action 3 — Extractor benchmark F1.8 (LIBRARY ENGINEER)
`benchmarks/extractor.bench.ts` — p50/p95/p99 latency per request. Criterion: p95 ≤ 1ms.

---

## Section 5 — Critical path to first working middleware

```
parity_report.json ✓ CLEARED
  → packages/core/src/worker.ts (load ONNX, warmup, message queue)
    → packages/core/src/middleware.ts (extractor call + worker dispatch)
      → Supertest: SQLi payload → 403, legit → pass
        → app.use(logsguardian()) running inference  ← first working middleware
```

---

## Train/Serve Skew — Temporal Features (RESOLVED)

**Reported by:** Sebastián (2026-06-14)  
**Claim:** "Group 9" — 5 temporal features — are always 0 at runtime but populated during training.

**Finding:** No train/serve skew exists. The decision to exclude these features was already made and executed before any model training.

### What "Group 9" is in the source code

`packages/extractor/src/index.ts` comment at line 56 labels 5 features as Group 9:
```
req_count_1s, req_count_5s, req_count_60s,
error_rate_4xx_60s, endpoint_diversity_60s
```
These 5 are always hardcoded to 0 (see `TEMPORAL_FEATURES` constant at line 66). This is by design.

### The 6th excluded feature Sebastián missed

`status_code` is in **Group 8** (HTTP request features, line 55) — not Group 9 — but is equally unavailable at RASP intercept time. It is a response field: the response does not exist when the middleware intercepts the request. It was included in Group 8 to support dataset sources that include response codes (owasp_logs, russellmitchell), but must be excluded from training for the same reason as the temporal features.

### What the ML pipeline actually did

`training/FEATURE_NOTES.md` documents the correct 6-feature exclusion applied before training:

| Feature | Group | Reason for exclusion |
|---------|-------|---------------------|
| `status_code` | 8 (HTTP) | Response field — unavailable at intercept time |
| `req_count_1s` | 9 (temporal) | Requires cross-request state |
| `req_count_5s` | 9 (temporal) | Same |
| `req_count_60s` | 9 (temporal) | Same |
| `error_rate_4xx_60s` | 9 (temporal) | Response codes + cross-request state |
| `endpoint_diversity_60s` | 9 (temporal) | Cross-request state |

These 6 were dropped from `features.csv` before `split.py` ran. The split parquets never contained them. The notebook `DROP_COLS` lists include all 6. `parity_report.json` confirms `n_features=66`.

### Why these features appeared non-zero in some datasets

`owasp_logs` and `russellmitchell` are log-based datasets built from completed HTTP exchanges. They include response codes (`status_code`) and sometimes aggregated fields that map loosely to the temporal features. These values appear non-zero in the raw JSONL but are **response-time artifacts** — they do not represent data available at request-intercept time in production.

### Resolution

No retraining required. No re-split required. The models were trained correctly on 66 features that are all computable at request-intercept time.

**Worker_thread contract:** extract all 72 features via `extractFeatureVector()`, then slice to 66 by dropping the 6 excluded features in the same order they appear in `FEATURE_NAMES`. The ONNX sessions expect exactly 66 inputs.

The list of features to drop, in `FEATURE_NAMES` index order:
```typescript
// indices 66-71 (Group 9: status_code + behavioural rate features)
const EXCLUDED_FEATURE_INDICES = [66, 67, 68, 69, 70, 71];
// names: status_code, req_count_1s, req_count_5s, req_count_60s,
//        error_rate_4xx_60s, endpoint_diversity_60s
```
