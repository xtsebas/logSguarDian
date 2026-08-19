# logSguarDian — Repository Status Report

**Date:** 2026-08-16
**Supersedes:** the pre-`packages/core` version of this document (2026-06-14) — that snapshot described an empty `packages/core` skeleton and `rf_v1`/`if_v1`. Everything below reflects the current implementation.

---

## Section 1 — What exists and works

| Artifact | Verified |
|----------|---------|
| `packages/extractor/src/` — 73-feature TS extractor (73rd feature, `non_form_operator_count`, added post-launch to fix a form-syntax false positive) | 68/68 tests pass, including numeric parity against the Python reference |
| `packages/extractor/src/cli.ts` — batch CLI, JSONL → CSV | Built, tested |
| `packages/core/src/middleware.ts` — Express middleware, RF-dedicated + IF-pool worker architecture, async log-patch (no grace-window latency cost) | 147/147 core tests pass |
| `packages/core/src/worker.ts` — ONNX inference (RF: 67 features, IF: 61) | Parity verified against `parity_report.json` |
| `packages/core/src/store.ts` + `webhook-store.ts` + `webhook.ts` — SQLite event log, webhook registry (live, no restart needed), fire-and-forget delivery | Tested, verified live against real Config 2 traffic |
| `packages/core/src/cli.ts` + `cli/` — 4 command groups (`config`, `attacks`, `endpoints`, `webhooks`), 14 subcommands | 113/113 CLI tests pass |
| `training/models/{rf,if}.onnx` — currently rf_v10 / if_v9, worker-pool architecture | Coverage: sqli 100%, xss 100%, path_traversal 93%, cmdi 100% (all ≥80% gate); parity <0.1% |
| Config 1/2/3 evaluations against `logSguarDian-vulnerable-project` | Config 1 (baseline) and Config 2 (+logsguardian) closed and documented; Config 3 (+WAF) in progress, see Section 3 |
| npm publish readiness audit (READMEs, `docs/api.md`, `docs/decision-policy.md`, `docs/architecture.md`, `package.json` metadata, real `pnpm pack` + solo-install verification) | Complete — see `.claude/decisiones.md` "Auditoría de docs pre-publish npm" and follow-up entries |

---

## Section 2 — Known gaps and accepted limitations (not blocking, but real)

| Item | Status | Note |
|------|--------|------|
| **Δp95 latency criterion (OE3, `.claude/CLAUDE.md`)** | **Unresolved as literally worded** | The relative-% gate (≤5-10%) is structurally very hard to pass against this project's near-zero-latency reference app baseline — absolute overhead is small (single-digit ms) but the ratio still fails. Needs an explicit decision (reinterpret as absolute ms, or re-measure against a more realistic baseline) before reporting this objective as met. See `docs/results.md` §F6.5. |
| **IF `pass_anomaly` rate on benign traffic** | Accepted limitation, not a bug | Root-caused to a User-Agent representation gap in IF's training data (see `docs/limitations.md`). Does not affect blocking — RF holds sole blocking authority. |
| **`middleware.test.ts` timing flakiness under full-suite parallel load** | Documented, not fixed | Several tests depend on real `setTimeout` margins; under 18-suite parallel CPU contention, different tests intermittently exceed their margin (each individually passes in isolation). One deterministic case (too-tight 5ms margin) was fixed; the broader pattern (real timers vs. fake timers) was not — same treatment as `smoke.test.ts`'s existing CI exclusion. |
| **`docs/architecture.md` §2 (ML/training side)** | Stale numbers, not verified this cycle | Still cites "72 features"/"1,155,302 rows" for the raw dataset-construction pipeline — no confirmed current number to replace it with; flagged in the doc itself rather than silently left wrong. |
| **cmdi/sqli class-attribution confusion** | Documented, not fixed | ~49% of cmdi payloads get labeled `sqli` in reporting (still correctly blocked) — affects triage accuracy in `attacks`/`endpoints` output, not detection. See `docs/limitations.md` §1. |

---

## Section 3 — In progress, outside this repo

- **Config 3 (WAF defense-in-depth)** — `logSguarDian-vulnerable-project` repo, branches `feat/waf-modsecurity-crs` (Config 3a, WAF-only baseline) and `feat/config3-waf-plus-logsguardian` (Config 3b, layered stack). ModSecurity v3 + OWASP CRS (PL1) in front of the app. Round 4 (590-payload SecLists corpus across all 4 configs) has raw results (`attack-sim/results_config{1,2,3a,3b}.json`) but the analysis comparing "evaded WAF, caught by logsguardian" is not yet written up.

---

## Section 4 — Next actions

1. **Resolve the Δp95 latency criterion wording** (Section 2) — needed before any final thesis reporting of OE3 as met.
2. **Actual `npm publish`** — everything in Section 1 is ready; publishing itself has not been run.
3. **Config 3 write-up** — turn the Round 4 raw results into the evasion-rate analysis originally scoped.
4. Optional: verify/update `docs/architecture.md` §2's dataset numbers if a source of truth is available; investigate the broader `middleware.test.ts` timing-flakiness pattern (fake timers) if it starts causing real CI noise.
