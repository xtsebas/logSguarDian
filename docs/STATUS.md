# logSguarDian — Repository Status Report

**Date:** 2026-06-13
**Branch:** main

This report supersedes the 2026-06-11 version (previously at the repo root).
Sections 1-3 of that version are out of date: the parser format bug
described there has been fixed, the dataset has been regenerated, the models
have been trained and passed parity, and `packages/core` has been scaffolded.
See `docs/architecture.md` for the full repository layout and data flow.

---

## Section 1 — What exists and works

| Artifact | Phase | Verified |
|----------|-------|---------|
| `packages/extractor/` — full 72-feature canonical extractor (`types`, `patterns`, `entropy`, `structural`, `encoding`, `semantic`, `index`, `cli`) | F0-F1 | 21/21 Jest tests pass, `npm run build` clean |
| `data_manager/02_feature_engineering.ipynb` — raw sources -> `data/processed/canonical/*.jsonl` (9 sources), including Group 9 temporal derivation for `owasp_logs`/`russellmitchell` | F2.2 | Executed clean, no errors/warnings (3 bugs fixed this cycle, see below) |
| `data/processed/<source>.parquet` (9 files) — 72 features per source, computed via `packages/extractor` CLI | F2.8 | R1-compliant (CLI output, not Python-computed) |
| `data/processed/dataset_final.parquet` | F2.8 | 1,155,302 rows x 75 cols. Distribution: legitimate 743,708 (64.4%), sqli 295,690 (25.6%), path_traversal 69,310 (6.0%), xss 36,606 (3.2%), command_injection 9,988 (0.9%). No nulls. |
| `training/splits/test.lock.sha256` | F2.7 GATE | Present — test set locked |
| `training/models/rf.onnx` (45 MB), `training/models/if.onnx` (1 MB) | F4.1 | Present, trained |
| `training/models/parity_report.json` | F4.3-4.4 GATE | `parity_passed: true`, `n_features: 66`, `target_opset: 17`, `rf_max_prob_diff: 1.57e-7`, `if_max_score_diff: 1.89e-7` |
| `training/models/if_v1_metadata.json` | F4.1 | `threshold: 0.0443`, `contamination: 0.05`, trained on benign-only, `val_recall: 0.665`, `val_fp_rate: 0.099` |
| `LICENSE` (MIT, root) | F7.3 | Present |
| `packages/core/` — skeleton (package.json, tsconfig, jest config, src/*.ts placeholders, models/{rf.onnx, if.onnx, model-metadata.json}, tests/) | F5 (scaffold only) | Structure only, no implementation |

---

## Section 2 — What exists but needs work

### Corrected this cycle: `data_manager/02_feature_engineering.ipynb` (3 bugs, all fixed)

1. **IP regex** in the OWASP/RussellMitchell log parsing did not capture
   client IPs correctly — fixed, 1,337 unique IPs now extracted (was
   falling back to `"0.0.0.0"`).
2. **Temporal dtype** issue in `add_temporal_features()` — fixed.
3. **OWASP timestamp format** — `pd.Timestamp(...)` cannot parse Apache CLF
   datetimes (`01/Aug/2025:00:03:24 +0200`), silently fell back to
   midnight-of-directory-date for all 56,504 records, collapsing Group 9 to
   all-zero. Fixed with
   `pd.to_datetime(..., format="%d/%b/%Y:%H:%M:%S %z").tz_convert("UTC").tz_localize(None)`.
   Now produces 28,070 unique timestamps and non-zero Group 9 values for
   26,497-42,152 / 56,504 rows depending on column.

### CRITICAL (open): Group 9 train/serve skew

`extractFeatures()` in `packages/extractor` always returns 0 for the 5
Group 9 temporal features (`req_count_1s/5s/60s`, `error_rate_4xx_60s`,
`endpoint_diversity_60s`) — they require cross-request state not available
when normalizing a single request.

However, `data_manager/02_feature_engineering.ipynb`'s
`add_temporal_features()` fills in **real, non-zero** values for these
features for 2 of the 9 sources:

- `owasp_logs` — 56,504 rows, ~88% of the `path_traversal` class
- `russellmitchell` — 3,435 rows, 100% `legitimate`

This means the model is trained on a feature distribution it will never see
at inference time for these two sources/classes, while
`.claude/PLAN.md §1.1` states "ninguna feature depende de timestamps". This
is flagged but **not resolved** — the user has not yet chosen between:

1. Excluding Group 9 entirely from the training vector (drop 5 more
   columns, retrain on 61 features).
2. Documenting it as an accepted limitation with an ablation study showing
   impact on `path_traversal`/`legitimate` F1.
3. Implementing real cross-request state in `packages/core` (e.g., a small
   in-memory/SQLite sliding window keyed by client IP) so the middleware can
   actually populate Group 9 at runtime.

This decision should be made **before** F5.3 (middleware) is implemented,
since it determines whether `worker.ts` receives 61 or 66 features and
whether `middleware.ts` needs request-history state.

### MEDIUM: `training/parsers/*.py` + `validate_canonical.py` likely dead code

These 7 parsers + validator predate `data_manager/02_feature_engineering.ipynb`
and are not invoked by any current notebook, script, or the workspace
`package.json`/`pyproject` tooling. Recommend confirming and then removing
or moving to an `archive/` directory — keeping them risks someone running
the stale pipeline and producing non-R1-compliant data again.

### LOW: `pnpm install` not run since `packages/core` was added

`packages/core/package.json` declares `@logsguardian/extractor` (workspace
link), `onnxruntime-node`, and `better-sqlite3`, but
`packages/core/node_modules/` does not exist yet. Run `pnpm install` at the
repo root before starting F5 implementation.

---

## Section 3 — What does not exist yet

| Artifact | Phase | Blocked by |
|----------|-------|-----------|
| `packages/core/src/{index,types,worker,middleware,store}.ts` implementation | F5.1-5.5 | Group 9 decision (above) for `worker.ts`/`middleware.ts` feature-vector width |
| `docs/feature-spec.md` — feature justification table | F1.1 | Unblocked (documentation task) |
| `docs/api.md` — public middleware API design | F5.1 | Unblocked (design task) |
| `docs/decision-policy.md` — hybrid RF+IF decision logic | F3.7 | Unblocked — RF/IF outputs and thresholds already known from `model-metadata.json` |
| `.github/workflows/ci.yml` — CI pipeline | F0.4 | Unblocked |
| `benchmarks/` — extractor and load benchmarks | F1.8, F6 | F1.8 unblocked; F6 blocked on F5 |
| E2E detection test suite | F5.7 GATE | F5 implementation |
| Artillery load benchmarks | F6 | F5 complete |
| npm package publishing workflow | F7.4 | F6 GATE |

---

## Section 4 — Next concrete actions

1. **Resolve the Group 9 decision** (Section 2, CRITICAL) — this determines
   the input width (61 vs 66) for `rf.onnx`/`if.onnx` consumption in
   `worker.ts`, and whether `middleware.ts` needs to maintain per-client
   request history.
2. **Write `docs/api.md` and `docs/decision-policy.md`** — both are
   unblocked and gate F5.1/F5.3.
3. **Run `pnpm install`** at the repo root to link `packages/core` against
   `@logsguardian/extractor` and pull in `onnxruntime-node`/`better-sqlite3`.
4. **Implement F5.2 (`worker.ts`)** — load `models/rf.onnx` and
   `models/if.onnx` via `onnxruntime-node` inside a `worker_thread`, apply
   the feature-vector reduction from `model-metadata.json`, expose a message
   queue.
5. **Implement F5.3 (`middleware.ts`)** — normalize `req` to
   `CanonicalRequest`, call `@logsguardian/extractor`, dispatch to the
   worker, apply the decision policy from step 2.
6. **Confirm and remove/archive `training/parsers/*.py`** (Section 2,
   MEDIUM) once it is verified nothing depends on them.

---

## Notes on feature dimension

`FEATURE_NAMES` in `packages/extractor/src/index.ts` has 72 entries. The
ONNX models in `training/models/` were trained on **66** features —
`status_code` plus the 5 Group 9 features are dropped before training
(`parity_report.json: n_features: 66`). `packages/core/src/worker.ts` must
apply the same 72->66 reduction before calling the ONNX session. Do not pass
the raw 72-vector directly to `rf.onnx`/`if.onnx`.
