# Config. 2 — Evaluation With logSguarDian (in progress)

## 1. Setup

Target app: `logSguarDian-vulnerable-project` (same app, same commit lineage as `docs/baseline-config1.md`), now with `logsguardian` mounted as Express middleware in `src/app.js`, right after the body parsers and before the session/route handlers.

**Config used** (`logsguardian.config.js` in the target repo):
```js
mode: 'block', threshold: 0.35, model: 'hybrid', timeoutMs: 50, dbPath: './logsguardian.db', webhookUrl: 'https://webhook.site/...'
```

**Packaging:** `logsguardian` isn't published to npm. Installed via `pnpm pack` (not `npm pack` — plain npm doesn't resolve the `workspace:*` protocol used for the internal `@logsguardian/extractor` dependency) on both `packages/extractor` and `packages/core`, producing two `.tgz` files installed together in the target repo (`npm install ./logsguardian-extractor-0.1.0.tgz ./logsguardian-0.1.0.tgz`) so npm resolves the internal dependency locally instead of hitting the registry.

**Two infrastructure bugs found and fixed during setup, not in logsguardian itself:**
- `Dockerfile` used `node:20-alpine`. `onnxruntime-node`'s native binary requires glibc; Alpine uses musl. The worker thread failed to load `onnxruntime-node` (`Error loading shared library ld-linux-x86-64.so.2`), and since `middleware.ts`'s `try/catch` around `new Worker(...)` swallows the error silently, the middleware fail-opened on **every single request** with no visible error anywhere — it looked like normal traffic, not a crash. Fixed by switching to `node:20-slim` (Debian-based, has glibc).
- `dbPath: './logsguardian.db'` resolves inside the container's filesystem, which isn't bind-mounted to the host. The host-side `logsguardian` CLI was reading a stale, empty file from an earlier local test, producing `SqliteError: no such table: detection_events` — not because nothing was being logged, but because it was looking at the wrong file. Fixed operationally: run all CLI commands as `docker compose exec app npx logsguardian ...` instead of from the host.

**Attack traffic:** the E2E fixture corpus (`e2e/fixtures/test_payloads.jsonl` — 500 payloads, 100/class, seed=42, the same corpus behind the F5.7 gate numbers in `docs/results.md`), replayed via Artillery with a custom `processor.js` (`beforeRequest` hook overriding method/url/headers/body per virtual user) rather than `curl`, to exercise the full corpus per category instead of the 6 hand-picked vectors from Config 1.

---

## 2. Attack 1 — SQL Injection (100 payloads, `e2e/fixtures/test_payloads.jsonl`, label=sqli)

**Result: 99/100 blocked (`HTTP 403`), 1/100 not blocked (`HTTP 404`, i.e. passed through to the app and 404'd there).**

Consistent with the official F1=99.6% / recall=99.6% test-set numbers surfaced live via `logsguardian attacks inspect sqli` against the running instance.

**Compared to Config 1 (zero protection):** both documented SQLi vectors (auth bypass, UNION exfiltration) were fully compromised with no protection. Config 2 blocks the equivalent attack class at ~99% over a 100-payload corpus — a direct, measured improvement, not just a claim.

### 2.1 False positive found on real browser traffic — not from the attack corpus

While manually navigating the app in Firefox during this test (unrelated to the Artillery run), a plain `GET /posts` — no attack payload — was blocked:

```
path: /posts
user_agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0
verdict: block
predicted_class: sqli
confidence: 0.62
if_score: 0.1213
```

**This would not have blocked at the original `RF_THRESHOLD = 0.70`** (0.62 < 0.70). It blocks under the current `RF_THRESHOLD = 0.35`, the result of four successive recalibrations (`docs/decision-policy.md` §2.2.1–2.3.2) made to fix xss/cmdi under-detection. The offline/E2E benign-FP measurement (~2%, `docs/results.md` §F5.7) did not surface this — likely because synthetic benign fixtures use short, simple User-Agent strings (`ua_length` is the #1 feature by RF importance, per `logsguardian attacks inspect`), unlike a real 78-character Firefox UA string.

This directly materializes the risk already flagged in `docs/limitations.md` §4 ("Data Source Coverage... real production traffic may differ in... User-Agent patterns... leave-one-source-out validation is pending") — no longer a theoretical concern, an observed one.

**Not investigated further at this point** — logged as a finding, continuing with the planned attack battery (XSS next) per team decision. A dedicated controlled benign-traffic run (real browser navigation, not synthetic) is worth doing separately to quantify how common this is beyond this one instance.

### 2.2 Webhook delivery

Confirmed working end-to-end — all block/pass_anomaly events during this run were received at the configured `webhookUrl` (webhook.site). Note: `webhookUrl` is a static field manually added to `logsguardian.config.js`; the separate `webhooks add/list/remove/test` CLI command group does **not** feed into the middleware's actual notification path yet — tracked separately as a backlog item (see `.claude/decisiones.md`).

---

## 3. Attack 2 — XSS (100 payloads, `e2e/fixtures/test_payloads.jsonl`, label=xss)

**Result: 93/97 delivered payloads blocked (`HTTP 403`), 4/97 not blocked (`HTTP 404`). 3/100 payloads per run failed client-side before reaching the network** (`Invalid URL` in Artillery — a handful of rows in this fixture's `label=xss` slice have the raw, un-encoded XSS payload directly in the `path` field, e.g. `<script>...</script>` as the literal path string, instead of percent-encoded like the sqli slice. Reproduced identically across two separate runs, so it's a property of those specific fixture rows, not a flake. Not investigated further for 3/100 rows — the other 97 are enough for a meaningful detection-rate read).

93/97 ≈ 96% — consistent with, slightly above, the official recall=97.8% (F1=98.4%) test-set number and the 94/100 E2E live number in `docs/results.md` §F5.7. Confirmed live via `logsguardian attacks inspect xss`, which also surfaced real payload examples pulled from the store, e.g. `sog=&quot%3B=&gt%3B=%2C&lt%3Bscript=&gt%3Balert%28document.cookie%29...`.

**Compared to Config 1 (zero protection):** both documented XSS vectors (bio field, post content) executed unescaped with zero protection. Config 2 blocks the equivalent attack class at ~96% over a 100-payload corpus.

One xss-labeled payload was misclassified as `cmdi` at low confidence and passed through (`verdict=pass`, severity `LOW` in `attacks summary`) — model confusion between attack classes, not a miss on "is this an attack" (still correctly flagged as *some* kind of attack, just the wrong one). Not concerning on its own since it didn't block anything; noted for completeness.

### 3.1 Webhook delivery

Zero webhooks arrived at webhook.site on the first XSS run, despite the DB confirming the middleware attempted all 66 (`webhook_sent=1` for every `predicted_class='xss'` row with `verdict IN ('block','pass_anomaly')`). Root cause: the free webhook.site testing URL hit its own rate limit after the SQLi run's 99 near-simultaneous requests (confirmed with a manual HTTPS POST from inside the container returning `STATUS: 429`) — a limitation of the disposable test endpoint, not of logsguardian. Confirmed delivered end-to-end after switching to a fresh webhook.site URL and re-running.

## 4. Attack 3 — Path Traversal / LFI (100 payloads, `e2e/fixtures/test_payloads.jsonl`, label=path_traversal)

**Result: 100/100 blocked (`HTTP 403`).** The cleanest result of the three attacks run so far — no delivery failures, no client-side errors (this fixture slice has no empty-path or raw-unencoded-payload rows, unlike sqli/xss).

Above the official recall=96.5% (F1=96.7%) test-set number and matching the 100/100 E2E live number in `docs/results.md` §F5.7.

**Compared to Config 1 (zero protection):** the documented LFI vector (`../../../etc/passwd` via the attachment endpoint) read real file contents from the container with zero protection. Config 2 blocks the equivalent attack class at 100% over a 100-payload corpus.

**Class-attribution nuance:** `attacks list` shows `path_traversal: 95`, plus `sqli: 3` and `cmdi: 2` newly attributed during this run — meaning verdict was correct 100/100 (every request blocked), but the RF model's specific class label was wrong for 5/100 payloads (still correctly recognized as *an* attack, misclassified as which one). Same pattern observed in the XSS run (§3) — model confusion between attack classes at the label level doesn't affect blocking behavior, but is worth noting since `attacks summary`/`attacks list` report by predicted class, not by ground truth.

**Webhook delivery:** confirmed arriving at the (working, non-rate-limited) webhook.site URL.

## 5. Attack 4 — Command Injection (100 payloads, `e2e/fixtures/test_payloads.jsonl`, label=cmdi)

**Result: 98/100 blocked (`HTTP 403`).** Above the official F1=89.5% / recall=91.7% test-set numbers and the 95/100 E2E live number in `docs/results.md` §F5.7 — cmdi is the historically weakest class (`docs/limitations.md` §1, feature-space separability), and this run outperformed expectations on raw block rate.

**Compared to Config 1 (zero protection):** the documented cmdi vector (`; whoami ; cat /etc/passwd` via the admin ping utility, running as **root** in the container) executed with full, unrestricted command execution with zero protection. Config 2 blocks the equivalent attack class at 98% over a 100-payload corpus.

### 5.1 Main finding — severe class-attribution confusion between cmdi and sqli

Unlike the minor (≤5%) misattribution seen in attacks 2-3, this run showed **roughly half of all cmdi payloads mislabeled as `sqli`.** Comparing `attacks list` totals before and after this run (cumulative, same DB throughout — not reset by the intermediate `docker compose up --build`):

| Class | Before this run | After this run | Δ (attributed to this run's ~100 cmdi payloads) |
|---|---:|---:|---:|
| sqli | 3 | 51 | **+48** |
| cmdi | 2 | 47 | +45 |
| path_traversal | 95 | 3 | +0 |

Of ~98 blocked cmdi payloads, **only ~45 (46%) were correctly labeled `cmdi`; ~48 (49%) were labeled `sqli` instead.** Blocking behavior is nearly unaffected (98/100 still blocked — the model correctly recognizes *an* attack either way), but the specific class label is wrong for roughly half the traffic.

**Root cause, from real payload examples pulled via `attacks inspect cmdi`:** the fixture's cmdi payloads lean heavily on time-based blind techniques — e.g. `rsd=%7C%7Csleep+15` (`||sleep 15`). `sleep(N)` as a delay-based oracle is syntactically and semantically the same technique used for SQLi time-based blind injection, and `semicolon_count` is an explicitly shared feature between the sqli and cmdi groups (`docs/feature-spec.md` #31: "SQLi / CMDi"). The model appears to have learned "sleep + separator characters" as primarily an SQLi signal, pulling a large fraction of cmdi's sleep-based payloads into the sqli bucket.

**Practical implication:** an operator reading `attacks summary`/`attacks list` output during a real cmdi attack would see it reported predominantly as **SQL Injection**, not Command Injection — the verdict (block) is trustworthy, but the *category* attribution used for triage/reporting is not, specifically for cmdi's sleep-based variants. Worth a mention alongside the existing cmdi separability limitation in `docs/limitations.md` §1, since it's a distinct failure mode (wrong label, not missed detection).

### 5.2 Webhook delivery

Confirmed arriving at the working webhook.site URL.

---

## 6. Summary — Config 2 version 1 vs. Config 1

| Category | Config 1 (no protection) | Config 2 (+logSguarDian) | Payloads blocked |
|---|---|---|---:|
| SQL Injection | 2/2 vectors fully compromised (auth bypass, credential dump) | Blocked | 99/100 |
| XSS (stored) | 2/2 vectors fully compromised (bio, post content) | Blocked | 93/97 delivered (96%) |
| Path Traversal / LFI | 1/1 vector fully compromised (`/etc/passwd` read) | Blocked | 100/100 |
| Command Injection | 1/1 vector fully compromised (root RCE) | Blocked | 98/100 |

**Overall: the same six baseline-compromising vectors, replayed at 100-payload-per-category scale, are blocked at 93-100% by Config 2** — a direct, measured reduction in effective attack surface versus Config 1's 6/6 zero-protection compromise rate.

**Findings beyond the headline block rate, in order of severity:**
1. **False positive on genuine browser navigation** (§2.1) — `GET /posts` blocked at 62% confidence, which would not have blocked at the original `RF_THRESHOLD=0.70`. A real cost of the four threshold recalibrations chasing xss/cmdi recall, not previously visible in offline/E2E benign-FP numbers (~2%).
2. **cmdi/sqli class-attribution confusion** (§5.1) — ~49% of cmdi payloads mislabeled as sqli in `attacks`/`endpoints` reporting, despite near-complete blocking. Affects triage accuracy, not protection.
3. **Minor class confusion in xss/path_traversal** (§3, §4) — ≤5% mislabeling, same failure mode as #2 at much smaller scale.
4. **Webhook rate-limiting** — resolved as an artifact of the disposable free testing endpoint (§3.1), not a logsguardian issue; no longer tracked as a finding.

**Infrastructure notes carried forward for anyone reproducing this** (§1): `pnpm pack` (not `npm pack`) required for the internal workspace dependency; `node:20-slim`, not `-alpine`, required for `onnxruntime-node`'s glibc dependency; `logsguardian.db` lives inside the container's writable layer with no volume mount, so all CLI queries must go through `docker compose exec app`.
