# logsguardian

> RASP middleware for Node.js/Express — detects SQL Injection, XSS, Path Traversal, and Command Injection in real time.

`logsguardian` inspects every incoming HTTP request against a hybrid ML model (Random Forest + Isolation Forest, running as ONNX in dedicated `worker_threads`) and blocks the ones it recognizes as attacks, without adding a separate WAF or IDS to your stack.

Models are trained offline and shipped fixed with each release — this package does not learn or retrain itself from your traffic after installation.

---

## Install

```bash
npm install logsguardian
```

Requires Node.js ≥ 20 and Express 4 or 5 (peer dependency).

## Quick start

```bash
npx logsguardian config init
```

This writes `logsguardian.config.js` in the current directory. Then mount the middleware **after** your body parsers (`express.urlencoded`/`express.json`, and any `multer` instance if your app accepts file uploads):

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
  mode: 'block',       // 'block' (HTTP 403 on detected attacks) or 'monitor' (log only, never blocks)
  threshold: 0.35,      // RF confidence (0–1) above which a request is blocked. Lower = more attacks
                         // caught, more false positives. Higher = fewer false positives, more misses.
  model: 'hybrid',       // 'rf' (blocking only), 'if' (anomaly logging only), or 'hybrid' (both)
  timeoutMs: 50,          // fail-open timeout — if inference doesn't finish in time, the request passes
  dbPath: './logsguardian.db', // SQLite event log + webhook registry
};
```

Start in `mode: 'monitor'` if you want to see what logsguardian would have blocked before turning on enforcement.

Full option reference (including `webhookUrl`, event schema, decision policy): [`docs/api.md`](../../docs/api.md) in the monorepo.

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

Full reference: `docs/commands.md` in the monorepo.

## What it detects

SQL Injection, Cross-Site Scripting (XSS), Path Traversal / Local File Inclusion, and Command Injection — classified by a Random Forest trained on a labeled corpus of ~380,000 HTTP requests, cross-checked against OWASP Top 10 2021 and MITRE ATT&CK. A secondary Isolation Forest flags statistically anomalous requests for logging (never blocking) even when they don't match a known signature.

## Known limitations

- **No online learning** — detection quality depends on the model version you install, not on how long it has run.
- **Latency overhead does not yet clear this project's own ≤10% relative-latency target** in every measured environment, though absolute overhead is small (low single-digit milliseconds in most configurations). See `docs/results.md` in the monorepo.
- **Designed to run alongside a WAF, not replace one.** In a defense-in-depth evaluation against ModSecurity + OWASP CRS, logsguardian independently caught most of what a well-configured WAF missed — but neither layer alone is complete.
- Only the four attack classes above are covered — no DDoS, BOLA, or authentication-vector detection.
- `pass_anomaly` events (from the Isolation Forest) currently fire more often on ordinary benign traffic than their offline-calibrated rate suggests — treat that signal as noisy, not precise, until this is recalibrated.

## Source

This package is part of the [logSguarDian](https://github.com/xtsebas/logSguarDian) monorepo, built as a thesis project at Universidad del Valle de Guatemala. Issues and source: see the monorepo's `packages/core`.
