# logsGuarDian

> RASP middleware for Node.js/Express — detects SQL Injection, XSS, Path Traversal, and Command Injection in real time using a hybrid ML model, no dedicated security team required.

**Status: pre-release.** Detection, CLI, and evaluation are functionally complete; this repo is in a final polish pass (docs, packaging, message copy) before the first npm publish.

---

## What is logsGuarDian?

logsGuarDian is an Express middleware that inspects every incoming HTTP request in real time and blocks the ones matching known attack patterns — SQL Injection, Cross-Site Scripting (XSS), Path Traversal / Local File Inclusion, and Command Injection — without adding a separate infrastructure component (WAF, IDS) to your stack.

Detection is powered by a hybrid model trained offline on a labeled corpus of ~380,000 HTTP requests:

- **Random Forest** — the sole blocking authority. Classifies each request into one of the four attack categories (or benign) and blocks it above a calibrated confidence threshold.
- **Isolation Forest** — a secondary, non-blocking anomaly detector. Flags statistically unusual requests for logging/alerting even when they don't match a known attack signature; it never blocks a response on its own.

Both models are exported to ONNX and run in dedicated `worker_threads`, so inference never blocks the Node.js Event Loop.

**Models are trained offline and shipped fixed with each release — logsGuarDian does not learn or retrain itself from your live traffic.** Detection quality depends on the training corpus and calibrated thresholds shipped with the version you install, not on how long it has run against your app.

---

## Why logsGuarDian?

Small and mid-sized tech companies in Guatemala and Latin America frequently operate without a dedicated security team. Their Node.js APIs and web services remain exposed to endpoint attacks with no automated detection in place.

logsGuarDian addresses this gap by providing:

- Easy installation via npm — no separate infrastructure to deploy or operate
- Zero cost — free and open source
- Detection that combines known-attack classification with statistical anomaly logging
- Designed to run alongside a WAF, not replace one — see [Known limitations](#known-limitations)

---

## Features

- Real-time detection middleware for Express — SQLi, XSS, Path Traversal/LFI, Command Injection
- Hybrid ML model (Random Forest + Isolation Forest), ONNX inference in `worker_threads`
- `block` mode (HTTP 403) or `monitor` mode (log only, never blocks)
- SQLite event log of every detection
- Webhook notifications on block / anomaly, managed via CLI (`webhooks add/list/remove/test`)
- CLI for configuration and reporting: `config`, `attacks`, `endpoints`, `webhooks` — see [docs/commands.md](docs/commands.md)

## Known limitations

- **No online learning.** Detection models are trained offline against a fixed dataset and shipped with each release; they do not adapt to your traffic after installation.
- **Latency overhead does not yet clear this project's own ≤10% relative gate** in every measured environment. Absolute overhead is small (low single-digit milliseconds in most configurations), but the relative criterion is difficult to satisfy against a very low-latency baseline — see `docs/results.md` for the full analysis.
- **Best used alongside a WAF, not instead of one.** In a defense-in-depth evaluation against ModSecurity + OWASP CRS, a well-configured WAF alone still missed real attacks on the test corpus; logsGuarDian independently caught most of what the WAF missed. See `docs/vulnerable-app-evaluation/`.
- Only the four attack classes listed above are covered — no DDoS, BOLA, or authentication-vector detection.

---

## Commands

- [docs/commands.md](docs/commands.md) — CLI reference: `config`, `attacks`, `endpoints`, `webhooks`.

---

## Documentation

- [docs/architecture.md](docs/architecture.md) — repository layout, end-to-end data flow (raw data → dataset → ONNX models → middleware), and workspace/build conventions.
- [docs/decision-policy.md](docs/decision-policy.md) — how RF and IF verdicts combine, and the threshold calibration history.
- [docs/api.md](docs/api.md) — public middleware API.

---

## Installation

> Not yet published to npm. See [packages/core](packages/core) for the workspace package in the meantime.

```bash
npm install logsguardian
```

```js
const { logsguardian } = require('logsguardian');
app.use(logsguardian({ mode: 'block' }));
```

Or generate a config file first via the CLI:

```bash
npx logsguardian config init
```

---

## Authors

- **Sebastian Huertas** — Cybersecurity integration, dataset verification, library architecture and structure, testing and core logic
- **Diego Valenzuela** — AI/ML model integration, library architecture and structure, pattern design for the ML model, testing and core logic

Universidad del Valle de Guatemala — 2026

---
