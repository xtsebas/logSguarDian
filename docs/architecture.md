# Architecture — logSguarDian

This document describes how the repository is organized and how data flows
from raw traffic samples to a published npm package. The repository has two
halves that are developed somewhat independently but ship together as a
single package:

- **ML / training side** — `data/`, `data_manager/`, `training/`. Builds the
  labeled dataset and trains the ONNX models.
- **Library side** — `packages/extractor`, `packages/core`. The TypeScript
  code that ships to npm as `logsguardian` and runs inside a consumer's
  Express app.

The two sides are connected by a single rule (**R1**, see
`.claude/PLAN.md`): there is exactly **one** implementation of the 73-feature
vector, written in TypeScript inside `packages/extractor`. The Python/Jupyter
pipeline never recomputes features — it only produces `CanonicalRequest`
JSONL and then shells out to the extractor's CLI to get features. This
guarantees the vector a trained model sees is bit-for-bit the same one the
middleware computes at request time.

---

## 1. Top-level layout

```
logSguarDian/
├── data/                   # Raw datasets + generated canonical/feature files
├── data_manager/           # Notebooks: raw sources -> CanonicalRequest -> dataset_final.parquet
├── training/               # Python: train/val/test split, model training, ONNX export
├── packages/
│   ├── extractor/          # @logsguardian/extractor — canonical 73-feature extractor (TS)
│   └── core/                # logsguardian — publishable middleware package
├── docs/                   # This document, repository status, design docs
├── .claude/                # Project context (CLAUDE.md), execution plan (PLAN.md), schema notes
├── pnpm-workspace.yaml     # packages/* workspace
├── tsconfig.base.json      # Shared TS compiler options
└── package.json            # Private workspace root (name "logsguardian", private: true)
```

---

## 2. ML / training side

### 2.1 `data/` — raw sources and generated artifacts

Contains the raw datasets as received from each source (OWASP CRS request
logs under `data/owasp/<date>/`, `XSS_dataset.csv`, ModSecurity-Learn
legitimate/attack JSON, the `omurugur` Path Traversal payload list, the
RussellMitchell intranet Apache logs, CAPEC multi-label payloads, etc.).

`data/processed/` holds everything derived from those raw sources:

- `data/processed/canonical/*.jsonl` — one JSONL file per source (9 total:
  `payloads_csv`, `payload_full`, `command_injection`, `xss_dataset`,
  `data_capec`, `modsec_learn`, `pt_wordlists`, `owasp_logs`,
  `russellmitchell`). Each line is a `CanonicalRequest` plus
  `{sample_id, label, timestamp}` — produced by `data_manager/02_feature_engineering.ipynb`.
- `data/processed/<source>.parquet` and `<source>_features.csv` — the 72
  canonical features for each source, computed by the
  `packages/extractor` CLI from the corresponding `canonical/*.jsonl` file
  (this is the only R1-compliant feature source).
- `data/processed/dataset_final.parquet` — the unified training dataset:
  **1,155,302 rows × 75 columns** (72 features + `sample_id`, `label`,
  `timestamp`), produced by `data_manager/03_dataset_construction.ipynb` by
  concatenating the 9 per-source parquet files. Class distribution:
  legitimate 64.4%, sqli 25.6%, path_traversal 6.0%, xss 3.2%,
  command_injection 0.9%.

### 2.2 `data_manager/` — dataset construction notebooks

- `01_data_audit.ipynb` — initial audit of raw sources (row counts, schema
  checks).
- `02_feature_engineering.ipynb` — **the canonical mapping step**. For each
  of the 9 sources, parses the raw format and emits `CanonicalRequest` JSONL
  into `data/processed/canonical/`. Also derives the Group 9 temporal
  features (`req_count_*`, `error_rate_4xx_60s`, `endpoint_diversity_60s`)
  for sources that carry real timestamps/IPs (`owasp_logs`,
  `russellmitchell`) via `add_temporal_features()`. This notebook does
  **not** compute any of the 72 canonical features itself — that is
  delegated to `packages/extractor`.
- `03_dataset_construction.ipynb` — reads the 9 `data/processed/<source>.parquet`
  files (each already containing the 72 features, produced by the extractor
  CLI) and concatenates them into `dataset_final.parquet`.

### 2.3 `training/` — splitting, model training, ONNX export

- `split.py`, `unify.py` — build the stratified train/val/test split from
  `dataset_final.parquet`. `training/splits/test.lock.sha256` locks the test
  set hash so it cannot silently change after training begins (R2/R3,
  `.claude/PLAN.md`). The split parquet files themselves
  (`train.parquet`/`val.parquet`/`test.parquet`) are git-ignored and
  regenerated locally.
- `notebooks/02_baseline.ipynb` … `05_onnx_export.ipynb` — train the Random
  Forest (supervised) and Isolation Forest (unsupervised) models on
  `train.parquet`/`val.parquet`, then export both to ONNX.
- `models/rf.onnx` (45 MB) and `models/if.onnx` (1 MB) — the trained models.
  Both reduce the input vector from 72 to **66 features**: `status_code`
  (unknown at request-intercept time) and the 5 Group 9 temporal features
  are dropped before training.
- `models/parity_report.json` — F4.4 GATE result.
  `parity_passed: true`, `n_features: 66`, `target_opset: 17`,
  `rf_max_prob_diff: 9.81e-8`, `if_max_score_diff: 2.38e-7`,
  `rf_onnx_output_index: 1`, `if_onnx_output_index: 1`. (rf_v3/if_v2 generation.)
- `models/if_v2_metadata.json` — Isolation Forest operating point:
  `threshold: 0.02901575`, `contamination: 0.05`, trained on benign-only data,
  `val_recall: 0.5596`, `val_fp_rate: 0.0800`.
- `parsers/parse_*.py` + `validate_canonical.py` — **legacy**. These predate
  `data_manager/02_feature_engineering.ipynb` and are not invoked by any
  current notebook or script. They should be removed or explicitly archived
  once confirmed unused (see `docs/STATUS.md`).
- `results/` — baseline metrics CSV and confusion-matrix / recall-FP plots
  from the training notebooks.

---

## 3. Library side

### 3.1 `packages/extractor` (`@logsguardian/extractor`)

The canonical, single-source-of-truth implementation of the 73-feature
vector. Pure TypeScript, no runtime dependencies beyond Node's standard
library.

```
src/
├── types.ts        # CanonicalRequest schema + normalizeCanonicalRequest()
├── patterns.ts     # Regex patterns: SQLi, XSS, Path Traversal, Command Injection, encoding
├── entropy.ts       # Shannon entropy, extended-ASCII ratio
├── body-parser.ts   # Per-field urlencoded body analysis — isolates the highest-signal field
│                     # in a multi-field body instead of scoring the whole body as one string
├── structural.ts    # Group 1 (lengths/URI) + Group 8 (HTTP request)
├── encoding.ts      # Group 2 (character composition) + Group 3 (encoding)
├── semantic.ts       # Groups 4-7 (SQLi, XSS, Path Traversal, Command Injection) + non_form_operator_count
├── index.ts          # extractFeatures(), extractFeatureVector(), FEATURE_NAMES (73, ordered), deriveRawPayload()
└── cli.ts            # extractor <input.jsonl> <output.csv> — the R1 bridge to Python
```

`tests/` — Jest, covering the 5 categories (SQLi, XSS, Path Traversal,
Command Injection, legitimate) plus numeric parity against the original
Python reference implementation, multi-field body isolation, and
score-based field selection in `deriveRawPayload()`.

Group 9 (temporal) features are **always 0** in `extractFeatures()` — they
require cross-request state that does not exist at the point a single
request is normalized. `worker.ts` (below) excludes them, plus `status_code`,
from the vector before calling either ONNX model — see §6.

### 3.2 `packages/core` (`logsguardian`)

The publishable middleware package. Fully implemented — detection, CLI, and
event/webhook storage are all in place; what remains before the first npm
publish is docs/packaging polish, not core logic.

```
package.json        # name "logsguardian" (unscoped), files: ["dist","models","data"]
                     # deps: @logsguardian/extractor (workspace), onnxruntime-node, better-sqlite3
                     # peerDependency: express
src/
├── index.ts          # Public entry point (re-exports middleware + types)
├── types.ts           # Public API types (docs/api.md)
├── worker.ts           # ONNX inference worker_thread — one worker per model role ('rf' | 'if'),
│                        # RF slices the 73-dim vector to the 67 it expects, IF to 61
├── middleware.ts        # Express middleware: req -> CanonicalRequest -> worker pool -> decision
│                        # policy (docs/decision-policy.md). RF resolves the response immediately
│                        # (dedicated worker, no queue); a small round-robin pool of IF workers
│                        # never blocks the response — a late IF reply patches the already-
│                        # written log row asynchronously instead of being discarded.
├── store.ts             # SQLite event log via better-sqlite3 (`detection_events` table)
├── webhook-store.ts      # SQLite webhook registry (`webhooks` table, same db file as store.ts)
├── webhook.ts             # sendWebhook() — fire-and-forget POST, 3s timeout, silent failure
├── cli.ts                 # Binary entry point — dispatches `config|attacks|endpoints|webhooks <subcommand>`
└── cli/                    # One handler module per subcommand + guard.ts (requires a config file
                             # to exist before running anything except `config init`)
models/
├── rf.onnx, if.onnx      # Copied from training/models/ (git-ignored, synced before build/publish)
└── model-metadata.json    # Consolidates parity_report.json (classes, ONNX output indices, thresholds)
tests/                     # Jest — middleware (worker-pool mocking, webhook dispatch, late-IF-patch
                           # behavior), store, CLI subcommands
```

Build matches `packages/extractor`: plain `tsc`, `tsconfig.json` extends
`tsconfig.base.json` with `outDir: dist, rootDir: src`.

---

## 4. End-to-end data flow

```
Raw sources (data/*)
   │
   ▼  data_manager/02_feature_engineering.ipynb
data/processed/canonical/<source>.jsonl   (CanonicalRequest + sample_id/label/timestamp)
   │
   ▼  packages/extractor CLI  (extractFeatures — THE canonical implementation)
data/processed/<source>.parquet           (72 features + sample_id/label/timestamp)
   │
   ▼  data_manager/03_dataset_construction.ipynb
data/processed/dataset_final.parquet      (1,155,302 rows x 75 cols)
   │
   ▼  training/split.py  (stratified, locked by training/splits/test.lock.sha256)
training/splits/{train,val,test}.parquet  (RF: 67-feature vector, IF: 61-feature vector —
                                            73 minus status_code/Group 9, IF additionally
                                            minus 6 zero-variance-on-benign features)
   │
   ▼  training/notebooks/02-05 (RandomForest, IsolationForest, ONNX export)
training/models/{rf.onnx, if.onnx, parity_report.json}
   │
   ▼  copied + consolidated into model-metadata.json
packages/core/models/{rf.onnx, if.onnx, model-metadata.json}


Runtime (consumer's Express app)
   │
   ▼  packages/core/src/middleware.ts
HTTP request -> CanonicalRequest -> dispatched to the RF worker AND the next IF worker in rotation
   │
   ▼  packages/core/src/worker.ts (worker_thread, onnxruntime-node) — extraction runs HERE,
      not on the main thread: extractFeatureVector() (73-dim) -> slice by feature name ->
      67-dim (rf.onnx) or 61-dim (if.onnx)
   │
   ▼  RF replies -> decision policy (docs/decision-policy.md, docs/api.md) resolves the
      response immediately, never waiting on IF -> packages/core/src/store.ts logs the event
   │
   ▼  IF replies later (always slower than RF by design) -> patches the same log row's
      if_score/is_anomaly in place; a 'pass' verdict can flip to 'pass_anomaly' retroactively
verdict (block / pass / pass_anomaly / timeout) -> SQLite event log + optional webhook dispatch
```

---

## 5. Workspace / build tooling

- **pnpm workspace** (`pnpm-workspace.yaml`: `packages/*`). Root
  `package.json` is `private: true`, `name: "logsguardian"`, `version:
  "0.0.0"` — it is never published itself; it only orchestrates
  `pnpm -r run build|test`.
- Two npm package names coexist deliberately:
  - `@logsguardian/extractor` (scoped) — internal building block, also
    useful standalone for anyone who wants the feature vector without the
    middleware.
  - `logsguardian` (unscoped) — the package end users `npm install`, per
    the root README.
- `tsconfig.base.json` is shared (`ES2020`, `commonjs`, `strict: true`,
  `declaration: true`). Each package extends it with its own `outDir`/`rootDir`.
- `packages/core` depends on `@logsguardian/extractor` via
  `workspace:*` — `pnpm install` must be run at the repo root after adding
  this dependency (not yet done as of this writing).

---

## 6. Known architectural caveats

- **Group 9 / temporal features train-serve skew**: `extractFeatures()`
  always returns 0 for the 5 Group 9 features, but
  `add_temporal_features()` in `data_manager/02_feature_engineering.ipynb`
  fills in real values for `owasp_logs` and `russellmitchell` (≈88% of the
  path_traversal class and 100% of one legitimate-traffic source
  respectively). This is a genuine discrepancy between what the model was
  trained on and what the middleware can provide at inference time — both
  are excluded from the vector actually passed to either ONNX model (see
  next item), so it does not affect runtime behavior, but it is a real
  property of the training data worth knowing about.
- **73 vs 67/61 features (implemented)**: `packages/core/src/worker.ts`
  extracts the full 73-dim vector, then slices it by feature name to 67
  inputs for `rf.onnx` and 61 for `if.onnx` (RF's 67 minus 6 further
  features confirmed to have zero/near-zero variance on benign traffic,
  dropped only for IF — see `docs/decision-policy.md` §4 and
  `docs/limitations.md`).
- **`training/parsers/`** appears to be superseded by
  `data_manager/02_feature_engineering.ipynb` and is not referenced by any
  current pipeline step.
- **`docs/decision-policy.md` §3/§4** record the *history* of threshold
  recalibration in detail, but their decision-table/constants snapshot
  predates the current single-`RF_THRESHOLD` design and several IF_THRESHOLD
  recalibrations — see the note at the top of that document's §3, and
  `docs/api.md` for the values actually shipped today.
