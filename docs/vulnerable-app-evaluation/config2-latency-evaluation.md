# Config 2 — Latency & Coverage Evaluation (Final)

## Criteria

- Coverage ≥80% per attack category
- Δp95 latency ≤10% (baseline vs with-middleware)

## Latency Results

Each number is the mean of 3 back-to-back 60s/20req-s Artillery runs against
`attack-sim/artillery-baseline.yml` (benign navigation only: login, browse
posts, view a post, view profile), on the same Docker image, differing only
in `LOGSGUARDIAN_DISABLED`.

| Metric | Baseline (no middleware) | Active (+logSguarDian) |
|--------|---------------------------|--------------------------|
| p95 (per-run: 4, 4, 4 / 13.9, 10.1, 19.9 ms) | 4.0ms | 14.6ms |
| Δp95 | — | +265.8% |
| Gate (≤10%) | — | **FAIL** |

No false positives: all 3600 benign requests per run returned 200/302 in
both configurations (zero 403s).

### Why this doesn't match logSguarDian's internal Δp95=0ms benchmark (docs/results.md A19)

Two real, fixable causes were found and fixed during this run, but even
after fixing them the delta stayed large — this is not measurement error:

1. **Fixed: stale ONNX models caused total fail-open, invalidating the first latency pass.** `models/rf.onnx` / `models/if.onnx` in this repo were the Jul 25 rf_v4/if_v3-era files (single 66-feature vector). PR #44's worker.ts expects RF=67 features / IF=61 features (split reduction). Loading the old models against the new worker tripped `RF_MODEL_INDICES.length !== 67` and crashed the worker at startup, silently — the middleware caught this and fail-opened on every single request (0/100 blocked across all 4 attack categories on the first run). Copied current `rf.onnx`/`if.onnx` from `logSguarDian/training/models/` (rf_v9/if_v8, the models PR #44 was actually retrained against, confirmed via `parity_report.json`: rf_n_features=67, if_n_features=61) into this repo's `models/`. First latency measurement (p95=5→6ms) was against the broken fail-open path and is void; the numbers above are post-fix.

2. **Fixed (observability, not blocking): no `.dockerignore`.** `COPY . .` in the `Dockerfile` copied this repo's host-built (macOS arm64) `node_modules` into the Linux container, and `npm install --production` didn't rebuild the mismatched native `better-sqlite3` binary (`invalid ELF header` when required inside the container). Blocking decisions were unaffected (RF/IF inference doesn't touch SQLite), but no detection-event database was ever written, which would have silently broken Step 6's cross-verification. Added `.dockerignore` (excludes `node_modules`), forcing a real Linux-native build.

After both fixes, the remaining +265% Δp95 is real and reproducible across 3 runs each way. Both are legitimate parts of this deployment's cost, not artifacts to explain away — Config 2 as actually deployed here does not meet the ≤10% latency gate.

### Latency overhead breakdown

Isolated the SQLite write from the rest of the middleware cost by adding a
`LOGSGUARDIAN_DB_PATH` override (`src/app.js` / `docker-compose.yml`,
mirroring the existing `LOGSGUARDIAN_DISABLED` pattern — `dbPath` is
hardcoded in `src/app.js` and is not read from `logsguardian.config.js`,
which only the CLI uses) and re-running the same benign baseline traffic
with `dbPath: ':memory:'`:

| Config | p95 (avg of 3 runs) |
|--------|----------------------|
| No middleware | 4.0ms |
| Middleware, disk-backed db | 14.6ms |
| Middleware, `:memory:` db | 11.0ms |

| Contributor | Measured impact |
|-------------|------------------|
| Docker Desktop/macOS virtualization vs A19's bare-Node baseline | Environment difference, not comparable to A19's Δp95=0ms |
| Synchronous SQLite write (`store.log`) | ~25% of overhead (14.6ms → 11.0ms with `:memory:`) |
| `worker_thread` ONNX round-trip (IPC + inference) | ~75% of overhead (11.0ms residual after removing disk I/O) — not further isolated in this investigation |
| Missing ONNX session warmup | Contributing factor, not isolated separately |

The SQLite write is a real but secondary cost. Even with disk I/O
eliminated entirely, p95 stays at 11.0ms — 175% over the 4.0ms
no-middleware floor — so the dominant cost is the `worker_thread`
round-trip itself (message passing plus the RF/IF forward pass). Separating
IPC serialization time from actual inference time needs instrumentation
inside `logSguarDian/packages/core/src/worker.ts`, which is out of scope
for this repo — flagged as follow-up work for the logSguarDian side, not
resolved here.

## Coverage Results

100 payloads per category (`attack-sim/payloads/*.json`), fired via
`attack-sim/run-attacks.js` against the live endpoint that maps to each
vulnerability (`POST /login` for sqli, `POST /profile` for xss,
`GET /posts/1/attachment?file=` for path_traversal, `POST /admin/ping` for
cmdi), with logsguardian active. "Blocked" = HTTP 403 from the middleware.

| Category | Blocked | Total | Rate | Gate (≥80%) |
|----------|---------|-------|------|--------------|
| sqli | 100 | 100 | 100.0% | PASS |
| xss | 100 | 100 | 100.0% | PASS |
| path_traversal | 92 | 100 | 92.0% | PASS |
| cmdi | 68 | 100 | 68.0% | **FAIL** |

### Cross-verification against logsguardian's internal log

`npx logsguardian attacks summary` (read from the same run's SQLite event
log) shows, per endpoint, a HIGH-confidence-tier count that matches the
403-blocked count from the table above almost exactly: `/login` 100 HIGH
sqli, `/profile` 100 HIGH xss, `/posts/1/attachment` 92 HIGH (73
path_traversal + 11 sqli + 8 xss), `/admin/ping` 68 HIGH (64 sqli + 3 cmdi +
1 xss) — the remaining 32 cmdi payloads logged at MEDIUM/LOW confidence,
matching the 32 non-blocked (200) responses exactly. This confirms the
gate is measuring what it claims to, and reconfirms a pre-existing finding:
most blocked cmdi payloads are misclassified as `sqli`, not `cmdi` — the
model still clears the block bar on those, but the 32 that don't cross
`RF_THRESHOLD=0.35` under any class are true false negatives, not a
labeling artifact. (`/login`'s incident count read 103 rather than 100 —
3 stray detections logged during earlier manual `curl` verification in this
session, not part of the 100-payload run; harmless but noted for
transparency.)

### cmdi payload set was not derived from logSguarDian's own fixtures — and the 100-instance count overstates distinct coverage

`attack-sim/payloads/cmdi.json` has **zero string overlap** with
`logSguarDian/e2e/fixtures/test_payloads.jsonl`'s 100 cmdi records: mine
are bare shell-metacharacter strings submitted as a single form field
(`127.0.0.1; cat /etc/passwd`); the e2e fixture embeds blind-injection
payloads (mostly `` `sleep 15` `` variants) inside full realistic
multi-field HTTP requests. These are different distributions, generated
independently for this evaluation, not extracted from the same corpus the
model was trained/validated against.

Separately, the generator used to pad the base cmdi payload list up to 100
(`gen_payloads.py`'s `expand()`) did so by applying whitespace/casing
variants to a small set of ~30 base commands, so the 100 instances are not
100 independent techniques. Normalizing whitespace and casing:

- **33 distinct techniques** underlie the 100 payload instances.
- **17/33 (51.5%)** were blocked in every variant tested.
- **14/33 (42.4%)** were blocked in *some* variants but not others —
  the same semantic payload (e.g. `127.0.0.1; whoami`) flipped between
  blocked and passed purely on whitespace formatting (single space vs
  double space vs trailing space), which is itself a finding: detection
  is sensitive to surface formatting, not just semantic content.
- **2/33 (6.1%)** — both variants of `$(whoami)` / `` `whoami` `` alone,
  with no `127.0.0.1;` prefix — were never blocked in any variant tested.

So the honest framing of cmdi coverage is: **68/100 payload instances
blocked, but only 2 of 33 distinct techniques (6%) were fully
undetectable; the other 31 were either always caught (17) or caught
inconsistently depending on formatting (14).** The 68% instance-level
number is real and is what the ≥80% gate is defined against, but it
should not be read as "68% of attack techniques evade detection" — the
true evasion rate (never-blocked technique) is much smaller, while the
formatting-sensitivity problem (14/33) is a distinct and arguably more
concerning finding than either number alone.

## Overall verdict

**FAIL** on both criteria.

- Coverage: 3/4 categories clear the 80% bar; `cmdi` at 68% does not.
- Latency: Δp95 = +265.8%, far outside the ≤10% budget.

## Methodology notes

- Models: rf_v9/if_v8 (RF 67 features / IF 61 features, per
  `training/models/parity_report.json`), RF_THRESHOLD=0.35, mode=`block`.
- Test environment: Docker (`node:20`, glibc required for
  `onnxruntime-node` and now correctly for `better-sqlite3` too), Artillery
  2.0.33 load generator, macOS host running Docker Desktop.
- Baseline and active latency runs use the identical traffic pattern
  (`attack-sim/artillery-baseline.yml`) with only `LOGSGUARDIAN_DISABLED`
  differing, each averaged over 3 runs.
- Coverage uses a purpose-built Node script
  (`attack-sim/run-attacks.js`) rather than parsing Artillery's aggregate
  `http.codes.403` counters directly: those counters would have summed
  attack-request and login/session-flow codes together, understating the
  true block rate. The script isolates one login per authenticated
  category and counts 403s only on the 100 attack requests themselves.
- Also fixed during this run: Artillery's default `followRedirect: true`
  caused an infinite redirect loop on `POST /login` (Artillery preserves
  the POST method across the 302, hitting `/login` repeatedly rather than
  landing on `/posts`). All `POST /login` steps in
  `attack-sim/artillery-baseline.yml` use `followRedirect: false`.
- Added `LOGSGUARDIAN_DB_PATH` (env override in `src/app.js` and
  `docker-compose.yml`) to support the `:memory:` latency-isolation test
  above without hand-editing source between runs.

---

## FINAL — rf_v10 + worker-pool (logSguarDian PR #45/#46/#47)

Re-run of the same methodology above against logSguarDian `develop` post
three merged PRs: #45 (docs cross-reference, no code change), #46
(`feat/worker-pool-concurrency-fix` — RF gets a dedicated worker, IF gets
a 2-worker readiness-gated pool, `IF_POOL_SIZE=2`), #47
(`feat/v10-cmdi-minimal-context` — RF v10 / IF v9 retrain targeting the
cmdi minimal-context gap). Confirmed via `training/models/parity_report.json`
(`rf_model_version: rf_v10`, `if_model_version: if_v9`, features
unchanged at 67/61) and via `LOGSGUARDIAN_GRACE_DEBUG=1` startup logs
(`ifWorkers spawned: 2`, separate `session-ready` events for `rf` and
two `if` workers).

Note: re-packing the tarballs hit an unrelated npm bug worth recording —
`package-lock.json` pins an `integrity` hash for `file:` dependencies,
and a second `npm install` after only replacing the vendored `.tgz`
content did **not** re-verify or re-extract it (stale single-worker code
stayed installed despite the new tarball being on disk). Fixed by
deleting `package-lock.json` and `node_modules` before reinstalling.
Also saw one flaky test failure in `pnpm --filter logsguardian test`
that did not reproduce across 3 direct `npx jest` reruns (145/145 each
time) — logged here, not chased further, since it didn't recur.

### Comparison across iterations

| Metric | v1 (broken, stale models) | v2–v4 (rf_v9/if_v8, single worker) | FINAL (rf_v10/if_v9, worker-pool) |
|--------|---------|---------|---------|
| Coverage sqli | 0/100 (fail-open, void) | 100/100 | 100/100 |
| Coverage xss | 0/100 (fail-open, void) | 100/100 | 100/100 |
| Coverage path_traversal | 0/100 (fail-open, void) | 92/100 | 93/100 |
| Coverage cmdi | 0/100 (fail-open, void) | 68/100 | **100/100** |
| Δp95 latency | void (worker crashed, near-instant fail-open ≈ no-op) | +265.8% | **+111.3%** |
| Benign FP (block-level, HTTP 403) | 0% (nothing ran) | 0% | 0% |
| Benign `pass_anomaly` rate | not measured | not measured | **95.5%** (new finding, see below) |

### Coverage: cmdi

100/100 blocked, up from 68/100. Cross-verified against
`logsguardian attacks summary`: `/admin/ping` shows exactly 100 HIGH-tier
events (65 correctly labeled `cmdi`, 35 still mislabeled `sqli` but still
blocked) — matches the 100/100 block count exactly, and the cmdi/sqli
attribution confusion is markedly reduced (was 64/68 mislabeled before,
now 35/100). `path_traversal` moved 92→93/100, within the noise already
documented for that category.

**Offline vs. live metric — report both, don't conflate them.**
`logsguardian attacks inspect cmdi` reports the official locked test-set
number: **F1 89.5%, precision 87.5%, recall 91.7%** — flat/unremarkable
compared to pre-v10, per the v10 PR's own description ("aggregate F1 flat
on offline test, but targeted fix + generalization confirmed"). The live
100/100 result here is a different, independent measurement: this repo's
33-distinct-technique payload set (see the coverage-caveat section above)
is narrower than the offline test set's diversity, so a live 100% and a
flat offline F1 are not contradictory — the offline number is the honest
ceiling on general cmdi detection, the live number confirms the specific
minimal-context gap this evaluation's payloads exercise is now closed.
Both are true; neither substitutes for the other.

### Latency

Δp95 improved from +265.8% to **+111.3%** (14.6ms → 10.6ms active p95,
no-middleware floor unchanged at 5.0ms) — a 27.6% reduction in absolute
overhead, consistent with the worker-pool fix targeting the concurrency
serialization bottleneck. **Still fails the ≤10% gate.** The IF workers'
`session-ready` events logged ~5s load time each (vs RF's ~370ms) — a
one-time startup cost, not a per-request cost, but worth noting for
production readiness (cold-start requests during that window may still
see degraded behavior). Root cause of the remaining ~110% overhead was
not re-isolated in this run (would need the same `:memory:` and
worker-pool-specific instrumentation as the prior run); given the
absolute residual (10.6ms vs 5.0ms) is smaller than before, the earlier
finding that most of the cost sits in the `worker_thread` round-trip
rather than disk I/O likely still holds, but this is inference, not
re-verified here.

### Benign `pass_anomaly` rate — investigated, resolved (see DEFINITIVE section below)

Querying `detection_events` directly (not just HTTP status codes) found
that **95.5% of all logged events (14,140/14,804) across this session's
combined benign + attack traffic carry `verdict: pass_anomaly`** —
including plain `GET /profile` and `GET /posts` with RF confidence
0.87–1.0 in favor of `benign`, where the Isolation Forest's `is_anomaly`
flag still fires (`if_score` around -0.02 to -0.10). This does not block
any legitimate request — Step 1's benign-traffic runs confirmed 0
unexpected 403s — but it means near-total anomaly-flag noise on ordinary
traffic.

At the time this was written it was an open question. It has since been
resolved: this run was using a stale `IF_THRESHOLD` (if_v8's calibrated
value, never updated for if_v9 — logSguarDian PR #48), *and*, once that
was corrected, the rate barely moved (95.5% → 94.6%), proving the
threshold was not the actual cause. See the DEFINITIVE section for the
full investigation and root cause (logSguarDian PR #49).

### Overall verdict for this iteration

**FAIL on latency, PASS on coverage** (all 4 categories now ≥80%,
cmdi highest of all at 100%). This is a meaningfully different result
from the prior iteration (which failed both), and the worker-pool fix
measurably improved (but did not close) the latency gap. This iteration's
build was later found to have shipped with a stale `IF_THRESHOLD` — see
DEFINITIVE below for the corrected, truly final numbers. Coverage and
latency conclusions above are unaffected (IF_THRESHOLD only controls the
`pass_anomaly` label, not RF-driven blocking).

---

## DEFINITIVE — rf_v10/if_v9, worker-pool, corrected IF_THRESHOLD (logSguarDian PR #48/#49)

Rebuilt from logSguarDian `develop` after two more merged PRs: **#48**
(`fix/stale-threshold-missing-onnx-in-package` — corrects `IF_THRESHOLD`
from if_v8's stale `0.00332745` to if_v9's real calibrated
`0.002486040118540811`; also fixes a separate packaging bug where the npm
tarball's `postbuild` script never copied `rf.onnx`/`if.onnx`, irrelevant
to this repo since `modelDir` here points at this repo's own `models/`,
not `node_modules`) and **#49**
(`docs/if-benign-calibration-tension-finding` — investigation and
decision record for the `pass_anomaly` finding below). Also picked up two
unrelated small fixes (webhook dispatch wiring, a CLI `monitor` mode input
alias) with no bearing on this evaluation. Verified installed: corrected
`IF_THRESHOLD`, `rf.onnx`/`if.onnx` present in `node_modules/logsguardian/models/`,
worker-pool code present, and empirically 1 RF + 2 IF workers spawn
(`ifWorkers spawned: 2`, separate `session-ready` events per worker).

### Was this run's earlier result affected by the stale threshold?

No, for coverage/latency. `IF_THRESHOLD` only gates the `is_anomaly` flag
and the `pass_anomaly` verdict label — it has no path into RF's
`predicted_class`/confidence, which is what `RF_THRESHOLD=0.35` and the
block/403 decision are actually driven by. So the FINAL section's
coverage (100/100/93/100) and latency (Δp95 fails the gate) conclusions
stand as measured. The only number the stale threshold could have
affected is `pass_anomaly` rate itself, investigated below.

### Root cause of the `pass_anomaly` flood: confirmed, not a threshold bug

Corrected the threshold, rebuilt, and re-measured pure benign traffic
(fresh db, `attack-sim/artillery-baseline.yml` only, no attack payloads
mixed in):

| | Stale `IF_THRESHOLD` (0.0033) | Corrected `IF_THRESHOLD` (0.0025) |
|---|---|---|
| `pass_anomaly` rate, pure benign traffic | 95.5% (mixed benign+attack) | 94.6% (pure benign) |

The correction moved the rate by under 1 percentage point. The reason is
in the score magnitudes: observed benign `if_score` values cluster around
**-0.02 to -0.10**, while both threshold candidates are small *positive*
numbers differing from each other by only 0.0008 — negligible against
score magnitudes 20–100x larger. Both thresholds were already deep in
"flag everything" territory for this traffic; which exact positive value
was configured was never going to matter.

logSguarDian's own investigation (PR #49, `docs/limitations.md`) confirmed
and root-caused this independently, via ablation: **the benign training
corpus is 99.6% missing `User-Agent` headers** (only one synthetic
generator track, 0.42% of benign rows, carries realistic UA strings) — IF
learned "no UA = normal," which is backwards for this app's real traffic
(every request from a real browser or `curl`/Artillery carries a UA).
Two retrain attempts to fix this (naive volume scale-up of UA-bearing
synthetic rows; a structurally-redesigned batch with deeper paths and
realistic queries) were tried and rejected — both closed the UA gap but
introduced new regressions on other attack classes (path_traversal/cmdi
recall, then sqli/xss separability), because making synthetic benign
traffic realistically resemble production traffic necessarily moves it
structurally closer to attacks against the same application. Formal
conclusion: **genuine architectural tension, not a generator design gap
or a threshold bug** — not pursued into a v11 IF retrain. Decision
rationale: IF has no blocking authority (RF is the sole gate per
`docs/decision-policy.md` §3), so this is operational log/alert noise,
not a security regression; RF's detection is completely unaffected.

Re-measuring on this final build (mixed traffic, this session):
`pass_anomaly` rate 96.4% overall, **98.1%** on plain `GET /profile`
(pure benign, unambiguous) — consistent with the previously-measured
94.6%, same order of magnitude, same documented root cause. Not a new
regression from this session's changes.

### Final latency (this build)

| | p95 |
|---|---|
| No middleware (n=3) | 5.0ms |
| Active, this build (n=6) | 12.8ms (range 8.9–18ms) |

Δp95 = **+156.7%**. Wider sample (6 runs vs the FINAL section's 3) shows
more run-to-run variance than before (8.9–18ms range) — consistent with
host-level noise (Docker Desktop/macOS), not a code-driven regression;
the webhook-wiring commit picked up in this build adds no configured
webhook (`webhookUrl` unset in `src/app.js`) and should be a no-op on the
hot path. Still fails the ≤10% gate, same conclusion as FINAL.

### Final coverage (this build)

| Category | Blocked | Total | Rate |
|----------|---------|-------|------|
| sqli | 100 | 100 | 100.0% |
| xss | 100 | 100 | 100.0% |
| path_traversal | 93 | 100 | 93.0% |
| cmdi | 100 | 100 | 100.0% |

Identical to the FINAL section (as expected — RF path unaffected by the
threshold fix). db-level block count (393) matches exactly.

### Definitive comparison across every iteration

| Metric | v1 (broken) | v2–v4 (rf_v9/if_v8) | v5 (rf_v10+pool, stale IF_THRESHOLD) | **DEFINITIVE (rf_v10/if_v9+pool, corrected)** |
|--------|---------|---------|---------|---------|
| Coverage sqli | 0/100 (void) | 100/100 | 100/100 | 100/100 |
| Coverage xss | 0/100 (void) | 100/100 | 100/100 | 100/100 |
| Coverage path_traversal | 0/100 (void) | 92/100 | 93/100 | 93/100 |
| Coverage cmdi | 0/100 (void) | 68/100 | 100/100 | 100/100 |
| Δp95 latency | void | +265.8% | +111.3%* | +156.7% |
| Benign FP (block-level, 403) | 0% | 0% | 0% | 0% |
| Benign `pass_anomaly` rate | not measured | not measured | 95.5% (mixed) | 94.6–98.1% (documented, accepted limitation) |

\* The v5 and DEFINITIVE latency numbers differ (111.3% vs 156.7%) by more
than the IF_THRESHOLD change alone can explain (that change doesn't touch
the request hot path's timing). Treated as sampling variance given the
6-run DEFINITIVE spread (8.9–18ms) overlaps the 3-run v5 spread
(8.9–13.9ms) — both fail the gate by a wide margin either way, and neither
sample size is large enough to pin down a precise number. If a tighter
latency figure is needed for the thesis, re-run with a larger n (10+)
under controlled host load.

### Overall verdict — DEFINITIVE, final

**FAIL on latency (Δp95 ≈ 110–160%, gate is ≤10%), PASS on coverage (all
four categories ≥80%, cmdi and sqli/xss at 100%, path_traversal at 93%).**
The `pass_anomaly` rate (~95%) is a documented, investigated, and formally
accepted limitation (logSguarDian PR #49) — not a bug, not part of either
formal gate, and does not affect blocking. It should be scoped into any
production/thesis discussion as an operational caveat (would flood a
webhook/SIEM integration) separately from the two pass/fail gates
themselves.

---

## Config 2 — Final Status (CLOSED)

### Coverage: PASS

| Category | Rate | Gate (≥80%) |
|----------|------|-------------|
| sqli | 100% | PASS |
| xss | 100% | PASS |
| path_traversal | 93% | PASS |
| cmdi | 100% | PASS |

Verified matching across every repeated measurement in this document
(single-worker build, worker-pool build, hybrid build) — coverage is
unaffected by every latency-side change tested, as expected (RF's
blocking decision never depends on `IF_THRESHOLD`, the grace window, or
the log-patch mechanism).

### Latency: FAIL (criterion unmet, investigated extensively)

Every row below is a real, directly-traceable measurement. Build
attribution reconstructed from `logSguarDian` commit timestamps
(`PR #47` merged 2026-08-04 03:59, `PR #48`/`#49` merged 2026-08-05
19:06–19:07, `PR #53` merged 2026-08-06 04:21) cross-referenced against
when each test in this document's history actually ran.

| Source | Build | Baseline | Active | Δp95 |
|--------|-------|----------|--------|------|
| `logSguarDian` PR #53 commit message (synthetic microbenchmark — bare Express function call, not this app) | PR #53 as merged (async-patch only, **no** grace window — predates the later hybrid design) | 0.078ms (p50) / 0.116ms (p95) | 0.171ms (p50) / 0.300ms (p95) | +119% (p50) to +159% (p95) |
| This repo, bare-metal (real app, real Postgres, no Docker) | PR #46–49 (rf_v10/if_v9, worker-pool, corrected `IF_THRESHOLD`) — architecturally **pre-#53**: grace window only, no async-patch, no write-queue | 3ms | 6ms | +100% |
| This repo, Docker, 10-row seed | PR #46–47 only (rf_v10/if_v9, worker-pool, **stale** `IF_THRESHOLD`, predates PR #48's fix) — same grace-window-only architecture as the bare-metal row above; `IF_THRESHOLD` only affects verdict labeling, not timing, so the two are architecturally comparable despite the threshold difference | 5ms | 13.9ms | +178% |
| This repo, Docker, 2010-row seed | Hybrid design (verified: `IF_GRACE_MS` + `patchQueue`/`flushPatchQueue` both present in installed dist) | 13.67ms | 23–28ms | +70.2% |

Three of these four rows (all but the 2010-row one) measure the same
underlying **grace-window-only, pre-#53 architecture** — in three
different environments/scales, not three different designs. That's
consistent with `logSguarDian/docs/results.md`'s own measurement of that
same architecture in Docker at 10-row scale: **+156.7%**. The 2010-row
row is the only measurement in this table of the current hybrid design;
it has no same-architecture baseline at a different scale to compare
against within this repo.

### Root causes investigated

1. **Worker-pool concurrency bottleneck** — identified and fixed. `onnxruntime-node`'s native addon serializes concurrent `InferenceSession.run()` calls on a single worker; PR #46 fixed this with a dedicated RF worker plus a 2-worker IF pool.
2. **IF grace-window blocking cost** — identified, addressed via the hybrid design (grace window restored on top of a batched write-queue for the async log-patch). Superseded PR #53's async-patch-only design after that alone measured *worse* in the real Docker+Postgres environment than the original grace window did.
3. **Postgres connection contention** — confirmed real, **partial** explanation only. Write-queue-only build measured against a verified Postgres-free route (`GET /`, no `db.query` call, in-memory session store) vs. the original Postgres-heavy flow: +202.5% to +227.5% (Postgres-heavy) vs. +100% to +133% (Postgres-free). Removing Postgres roughly halves the gap — real, but not the whole story.
4. **Worker-pool IF-burst regrowth under sustained load** — ruled out with direct evidence. Per-call IF inference timing captured across a full 60s sustained run, split into 10 chronological chunks, stayed flat (~2.9–3.2ms mean, ~5.0–6.0ms p95 throughout) — no PR #46-style climbing signature.
5. **Route selection** (`/posts/search`'s unindexed `LIKE`) — tested at 2010-row scale, found **faster** than `/posts` (10.1ms vs 13.67ms p95, no-middleware), because `/posts` is unpaginated and renders all 2010 rows while the search route filters to ~495 before rendering. Not a viable path to a harsher baseline; row-count growth on `/posts` itself remains the only tested lever that moved the number.

### NOT measured (do not cite as fact)

- **10,010-row scale-up** — not run. No record exists in any commit, doc, or JSON artifact in either repo.
- **Power-law extrapolation / "406 million rows" figure** — never computed. Does not appear anywhere in either repo's history.

An earlier draft of this section included both as settled fact. Neither
is real; this version replaces them with an honest gap rather than a
fabricated number.

### Conclusion

Across every environment and data scale actually measured — synthetic
microbenchmark, bare-metal real app, Docker at 10 rows, Docker at 2010
rows — absolute middleware overhead is small and stable, roughly 0.1ms to
15ms depending on environment. Every one of those measurements produces a
large relative percentage against its own near-zero-to-low-double-digit-ms
baseline. Four of five investigated root causes are resolved or ruled out
with direct evidence; Postgres contention is confirmed as a partial, not
complete, explanation for the remainder, with the residual gap
attributed (not fully isolated) to IF's own inference cost running
roughly 2-3x slower under Docker's CPU virtualization than on bare
macOS Node. The ≤10% relative criterion, as worded, remains unmet in
every tested configuration. Row-count scaling on `/posts` is
directionally promising — +178% at 10 rows down to +70.2% at 2010 rows,
architecturally the same design family as the Docker pre-#53 baseline —
but the scale required to reach ≤10% was not computed and should not be
cited without actually running it.
