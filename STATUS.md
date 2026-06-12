# logSguarDian — Repository Status Report
**Date:** 2026-06-11  
**Auditor:** Library engineer  
**Branch:** main  

---

## Section 1 — What exists and works

| Artifact | Phase | Verified |
|----------|-------|---------|
| `packages/extractor/src/types.ts` — CanonicalRequest schema + normalizeCanonicalRequest | F0.5 | Compiles |
| `packages/extractor/src/entropy.ts` — shannonEntropy, extendedAsciiRatio | F1.2 | 21/21 tests |
| `packages/extractor/src/patterns.ts` — all regex patterns (groups 2-8) | F1.3-1.4 | 21/21 tests |
| `packages/extractor/src/structural.ts` — computeLengthFeatures, computeHttpFeatures | F1.2 | 21/21 tests |
| `packages/extractor/src/encoding.ts` — computeCompositionFeatures, computeEncodingFeatures | F1.4 | 21/21 tests |
| `packages/extractor/src/semantic.ts` — computeSqliFeatures, computeXssFeatures, computePathTraversalFeatures, computeCommandInjectionFeatures | F1.3 | 21/21 tests |
| `packages/extractor/src/index.ts` — extractFeatures(), extractFeatureVector(), FEATURE_NAMES[72] | F1.5 | 21/21 tests |
| `packages/extractor/src/cli.ts` — batch CLI `extractor <in.jsonl> <out.csv>` | F1.7 | Built, manual smoke test pass |
| `packages/extractor/dist/` — compiled JS + type declarations | F1.7 | `npm run build` clean |
| `packages/extractor/tests/extractFeatures.test.ts` — 21 determinism/attack/legit tests | F1.5-1.6 | 21/21 pass |
| `training/data_clean/capec.jsonl` — 289,287 attack records | F2.2 | Present |
| `training/data_clean/command_injection.jsonl` — 2,105 records | F2.2 | Present |
| `training/data_clean/modsec_learn.jsonl` — 539,074 records | F2.2 | Present |
| `training/data_clean/owasp_logs.jsonl` — 56,399 records | F2.2 | Present |
| `training/data_clean/payload_full.jsonl` — 31,067 records | F2.2 | Present |
| `training/data_clean/payloads_csv.jsonl` — 43,216 records | F2.2 | Present |
| `training/data_clean/xss_dataset.jsonl` — 13,570 records | F2.2 | Present |
| `training/parsers/parse_*.py` — 7 parsers + validate_canonical.py | F2.2 | Present (format bug — see Section 2) |
| `training/CANONICAL_REQUEST_NOTES.md` — schema decision document | F0.5 | Present |
| `training/ML_READINESS.md` — blocker analysis (dated 2026-06-10) | F0 | Present |
| `training/notebooks/02_baseline.ipynb` through `05_onnx_export.ipynb` | F3-F4 | Present (execution state unknown) |
| `training/split.py`, `training/unify.py` | F2.6 | Present |
| `data/processed/*.parquet` — Python-computed parquets (reference only) | F2.8 | Present (R1 violation — must not use for training) |

---

## Section 2 — What exists but needs work

### CRITICAL: Schema mismatch between parsers and TS extractor

All 7 parsers output JSONL in the **intermediate nested format** from CANONICAL_REQUEST_NOTES.md §3:
```json
{ "method": "GET", "path": "/...", "query": "...", "headers": { "userAgent": "sqlmap/1.6", "contentType": "..." }, "body": null, "label": "sqli" }
```

The TS extractor CLI (`types.ts` + `normalizeCanonicalRequest`) expects the **final flat format** from §6:
```json
{ "method": "GET", "path": "/...", "query": "...", "userAgent": "sqlmap/1.6", "contentType": "...", "referer": "", "cookie": "", "extraHeaders": {}, "body": null, "label": "sqli" }
```

**Impact:** Running the CLI on any current JSONL file silently discards all header data. HTTP feature group (Group 8: `ua_present`, `ua_length`, `ua_suspicious`, `content_type_encoded`, `unusual_headers_count`) will be 0 for all capec and owasp records even when real values exist. For datasets that have no headers (modsec_learn, payload_full, xss_dataset, command_injection) the impact is zero since those fields are empty anyway.

**Fix:** Update all 7 parsers to output flat CanonicalRequest. This is a mechanical change — `headers.userAgent → userAgent` at top level, `headers.contentType → contentType`, etc.

### HIGH: `owasp_logs.jsonl` has no benign samples
Per ML_READINESS.md, all 56,399 owasp records are attack-labelled. The owasp log parser needs to include 200 OK responses (no CRS rule fired) as `label: "benign"`. This reduces the benign training pool for the Isolation Forest.

### HIGH: `capec.jsonl` missing benign records
The capec parser only emits attack-labelled rows (discards rows with no target-class match). Capec contains legitimate traffic that is discarded. This is intentional but documented as a limitation.

### MEDIUM: `command_injection.jsonl` only 2,105 records
Per ML_READINESS.md, cmdi class needs ≥5,000 samples for viable F1 ≥ 0.80. After capec parser fix + proper JSONL re-run, capec should contribute ~7,090 cmdi samples. Total would reach ~9,195, which is sufficient.

### LOW: `packages/extractor/package.json` missing root-level install
`node_modules/` is not installed in the root workspace — only locally in packages/extractor after manual `npm install`. The root `package.json` has no `devDependencies`. When a `packages/core` is created, this will need workspace-level dep management.

---

## Section 3 — What does not exist yet

| Artifact | Phase | Blocked by |
|----------|-------|-----------|
| `packages/core/` — middleware, worker_thread, SQLite store | F5 | parity_report.json (F4.4 GATE) for inference; can be scaffolded now |
| `training/models/rf.onnx`, `training/models/if.onnx` | F4.1 | F3.8 GATE (trained models) |
| `training/models/parity_report.json` | F4.3-4.4 | F4.1 |
| `features_train.csv`, `features_val.csv`, `features_test.csv` | F2.8 | Parser format fix + CLI re-run |
| `training/splits/` — train/val/test manifests | F2.6 | Features CSVs (F2.8) |
| `docs/feature-spec.md` — feature justification table (1.1) | F1.1 | Unblocked (documentation task) |
| `docs/api.md` — public middleware API design | F5.1 | Unblocked (design task) |
| `docs/decision-policy.md` — hybrid RF+IF decision logic | F3.7 | F3 results |
| `.github/workflows/ci.yml` — CI pipeline | F0.4 | Unblocked |
| `benchmarks/` — extractor and load benchmarks | F1.8, F6 | F1.8 unblocked; F6 blocked on F5 |
| `tsconfig.base.json` extended in packages/core | F0.2 | Unblocked |
| `datasets/splits/test.lock.sha256` — test set lock | F2.7 GATE | Split (F2.6) |
| E2E detection test suite | F5.7 GATE | F5 complete + parity |
| Artillery load benchmarks | F6 | F5 complete |
| npm package publishing workflow | F7.4 | F6 GATE |

---

## Section 4 — Next 5 concrete actions

### Action 1 — Fix parser output format to flat CanonicalRequest
**Owner:** LIBRARY ENGINEER (done this session — see below)  
**Task:** Update all 7 `training/parsers/parse_*.py` files to emit flat-field JSONL matching `types.ts` schema. Replace `headers: { userAgent, contentType, ... }` with top-level `userAgent`, `contentType`, `referer`, `cookie`. Add `extraHeaders: {}` for datasets that have additional headers (capec, owasp).  
**Blocked by:** Nothing — unblocked now.  
**Unblocks:** All downstream F2.8, F3, F4, F5.

### Action 2 — Re-run parsers and generate features CSVs
**Owner:** DIEGO  
**Task:** Re-run all 7 parsers to regenerate `training/data_clean/*.jsonl` with flat format. Then run `node packages/extractor/dist/cli.js <dataset.jsonl> <features.csv>` for each. Fix owasp parser to include benign traffic (label=0) for requests with no ModSec rule match.  
**Blocked by:** Action 1 complete.  
**Unblocks:** F2.6 split, F3 training.

### Action 3 — Run train/val/test split and lock test set
**Owner:** DIEGO  
**Task:** Run `training/split.py` on unified features CSV to produce stratified 70/15/15 split by class AND source. Commit `datasets/splits/test.lock.sha256` before any training run.  
**Blocked by:** Action 2 complete.  
**Unblocks:** F3, F2.7 GATE.

### Action 4 — Run training notebooks and export ONNX
**Owner:** DIEGO  
**Task:** Execute `02_baseline.ipynb`, `03_random_forest.ipynb`, `04_isolation_forest.ipynb`, `05_onnx_export.ipynb`. Validate parity (sklearn vs onnxruntime Python). Write `training/models/parity_report.json` with `parity_passed`, `n_features`, `threshold_if`, `rf_onnx_path`, `if_onnx_path`.  
**Blocked by:** Action 3 complete.  
**Unblocks:** F5 (middleware), F4.4 GATE.

### Action 5 — Scaffold `packages/core/` middleware and worker_thread
**Owner:** LIBRARY ENGINEER  
**Task:** Create `packages/core/` with `src/worker.ts` (ONNX session load + message queue, inference NOT wired until parity_report.json passes), `src/middleware.ts` (CanonicalRequest normalization + extractor call + worker dispatch stub), `src/store.ts` (SQLite event log), `src/types.ts` (public API types). Wire `extractFeatureVector()` from `@logsguardian/extractor`.  
**Blocked by:** Nothing for scaffolding; inference wiring blocked by Action 4 (parity_report.json).  
**Unblocks:** F5 completion once parity confirmed.

---

## Section 5 — Critical path to first working middleware

```
Action 1: Fix parser format (library engineer)
  → Action 2: Re-run parsers + generate features CSVs (Diego)
    → Action 3: Train/val/test split + lock test set (Diego)
      → Action 4: Run notebooks → rf.onnx + if.onnx + parity_report.json (Diego)
        → Wire inference in packages/core/src/worker.ts (library engineer)
          → app.use(logsguardian()) running inference  ← first working middleware
```

**Parallel track (no dependencies):**  
Action 5 (core scaffold) can run in parallel with Actions 2-4. The scaffold compiles and the middleware normalizes requests and calls the extractor correctly — it just stubs the inference call until parity_report.json exists.

**Current blocker:** Parser format mismatch (Action 1). Being fixed now.

---

## Notes on feature dimension

`FEATURE_NAMES` in `index.ts` has 72 entries. Before training, the ML pipeline must drop 6 features that are unavailable at RASP intercept time:
- `status_code` (response field — unknown at request intercept)
- `req_count_1s`, `req_count_5s`, `req_count_60s` (require cross-request state)
- `error_rate_4xx_60s`, `endpoint_diversity_60s` (same)

Training model input dimension = **66**. This will be confirmed in `parity_report.json` as `n_features`.  
The worker_thread must pass only the 66 non-temporal, non-response features to the ONNX session. Do not use the raw 72-vector directly.
