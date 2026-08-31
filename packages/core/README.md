# logsguardian

[![npm version](https://img.shields.io/npm/v/logsguardian.svg)](https://www.npmjs.com/package/logsguardian)
[![node](https://img.shields.io/node/v/logsguardian.svg)](https://www.npmjs.com/package/logsguardian)
[![license](https://img.shields.io/npm/l/logsguardian.svg)](./LICENSE)

> RASP middleware for Node.js/Express — detects SQL Injection, XSS, Path Traversal, and Command Injection in real time, using a hybrid ML model instead of static signature rules.

`logsguardian` inspects every incoming HTTP request against a hybrid ML model (Random Forest + Isolation Forest, running as ONNX in dedicated `worker_threads`) and blocks the ones it recognizes as attacks — without adding a separate WAF or IDS to your stack.

Models are trained offline and shipped fixed with each release. This package does not learn or retrain itself from your traffic after installation.

---

## Why

Most startups don't have a security team, and most application-layer protection (WAFs like ModSecurity) requires configuration expertise they don't have time for. `logsguardian` is meant to be the thing you actually install: one line in your Express app, no proxy to stand up, no rule tuning.

It's also not a WAF replacement — it's designed to sit *behind* one, catching what signature-based rules miss. In a 590-payload evaluation against ModSecurity + OWASP CRS (a well-configured, industry-standard WAF), `logsguardian` independently caught **37 of the 40 attacks the WAF let through** — using a statistical model that doesn't rely on the same pattern-matching rules an attacker might already know how to evade. Full methodology and results: [`docs/config3b-results.md`](https://github.com/xtsebas/logSguarDian/blob/develop/docs/vulnerable-app-evaluation/config3b-results.md).

## Install

```bash
npm install logsguardian
```

Requires Node.js ≥ 20 and Express 4 or 5 (peer dependency).

## Quick star

```bash
npx logsguardian config ini
```

This writes `logsguardian.config.js` in the current directory. Then mount the middleware **after** your body parsers (`express.urlencoded`/`express.json`, and any `multer` instance if your app accepts file uploads — logsguardian needs to see the parsed body to inspect it):

```js
const express = require('express');
const { logsguardian } = require('logsguardian');
const config = require('./logsguardian.config.js');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(logsguardian(config));
```

That's it — every request past this point is inspected. Attacks get an HTTP 403; everything else is forwarded unchanged.

## Configuration

```js
// logsguardian.config.js
module.exports = {
  mode: 'block',        // 'block' (HTTP 403 on detected attacks) or 'monitor' (log only, never blocks)
  threshold: 0.35,       // RF confidence (0–1) above which a request is blocked. Lower = more attacks
                          // caught, more false positives. Higher = fewer false positives, more misses.
  model: 'hybrid',        // 'rf' (blocking only), 'if' (anomaly logging only), or 'hybrid' (both)
  timeoutMs: 50,           // fail-open timeout — if inference doesn't finish in time, the request passes
  dbPath: './logsguardian.db', // SQLite event log + webhook registry
};
```

Start in `mode: 'monitor'` if you want to see what logsguardian would have blocked before turning on enforcement.

Full option reference (including `webhookUrl`, event schema, decision policy): [`docs/api.md`](https://github.com/xtsebas/logSguarDian/blob/develop/docs/api.md) in the monorepo.

## CLI

```bash
logsguardian --help
```

| Group | Commands |
|---|---|
| `config` | `init`, `show`, `set <key> <value>`, `validate` |
| `attacks` | `list`, `summary`, `inspect <type>` — query the detection log |
| `endpoints` | `top`, `profile <route>`, `report` — attack activity by route |
| `webhooks` | `add <url>`, `remove <id>`, `list`, `test <id>` — manage notification destinations at runtime, no restart needed |

Full reference: [`docs/commands.md`](https://github.com/xtsebas/logSguarDian/blob/develop/docs/commands.md) in the monorepo.

## What it detects

SQL Injection, Cross-Site Scripting (XSS), Path Traversal / Local File Inclusion, and Command Injection — classified by a Random Forest trained on a labeled corpus of ~380,000 HTTP requests, cross-checked against OWASP Top 10 2021 and MITRE ATT&CK. A secondary Isolation Forest flags statistically anomalous requests for logging (never blocking) even when they don't match a known signature.

### Measured performance

| Metric | Result |
|---|---|
| Detection coverage, standalone (per attack class, live evaluation) | 93–100% |
| Detection coverage, layered behind a WAF (590-payload independent corpus) | 99.5% overall |
| RF precision / recall (held-out test set) | 0.9996 / 0.9989 |
| Attacks the WAF missed that logsguardian caught independently | 37 / 40 |
| Middleware overhead, absolute (varies by environment) | ~0.1–15 ms |

Full methodology, per-class breakdowns, and the environments each number was measured in: [`docs/results.md`](https://github.com/xtsebas/logSguarDian/blob/develop/docs/results.md).

## Known limitations

Documented in detail, with root-cause investigations, in [`docs/limitations.md`](https://github.com/xtsebas/logSguarDian/blob/develop/docs/limitations.md). Summary:

- **No online learning** — detection quality depends on the model version you install, not on how long it has run.
- **Relative latency overhead** does not clear this project's original ≤10% target on every tested environment, though the *absolute* overhead is small (single-digit milliseconds in most configurations) — the relative-percentage criterion is mathematically hard to satisfy against near-instant baselines regardless of implementation quality. See `docs/results.md`.
- **Designed to run alongside a WAF, not replace one.** Neither layer alone is complete; see the "Why" section above for the defense-in-depth numbers.
- Only the four attack classes above are covered — no DDoS, BOLA, or authentication-vector detection.
- `pass_anomaly` events (from the Isolation Forest) currently fire more often on ordinary benign traffic than their offline-calibrated rate suggests, tied to how well the traffic's structural shape (particularly the User-Agent header) matches the training distribution — treat this signal as noisy, not precise. It never blocks a request either way.
- Detection confidence on command-injection payloads can vary with the shape and vocabulary of the request beyond just command syntax — an active area of ongoing data coverage work, tracked in `docs/limitations.md`.
## License

[MIT](./LICENSE)

## Source

This package is part of the [logSguarDian](https://github.com/xtsebas/logSguarDian) monorepo, built as a thesis project at Universidad del Valle de Guatemala. Issues, source, and the full research trail (including every experiment behind the numbers above): see the monorepo.