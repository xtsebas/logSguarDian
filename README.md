# logsGuarDian

> ML-powered endpoint attack detection for Node.js services — no security team required.

**Status: Work in Progress/develop**

---

## What is logsGuarDian?

logsGuarDian is an npm library designed to monitor server logs in Node.js applications and automatically detect anomalous patterns that may indicate active attacks on your endpoints.

It uses Machine Learning to identify and classify common attack types such as SQL Injection, Cross-Site Scripting (XSS), Path Traversal / Local File Inclusion, and Command Injection — giving startups and small tech companies a layer of automated security without needing a dedicated cybersecurity department.

The library learns from the traffic patterns of the system it is installed on, becoming more accurate over time to the specific behavior of your application.

---

## Why logsGuarDian?

Small and mid-sized tech companies in Guatemala and Latin America frequently operate without a dedicated security team. Their Node.js APIs and web services remain exposed to endpoint attacks with no automated detection in place.

logsGuarDian addresses this gap by providing:

- Easy installation via npm
- Zero cost — free and open source
- Autonomous operation without manual rule configuration
- Adaptive learning from your own system's traffic

---

## Planned Features

- Real-time log monitoring middleware for Express/Node.js
- ML-based classification of attack types (SQL Injection, XSS, Path Traversal / LFI, Command Injection)
- Anomaly detection trained on local traffic patterns
- Alert system for detected threats
- Minimal performance overhead

---

## Documentation

- [docs/architecture.md](docs/architecture.md) — repository layout, end-to-end data flow (raw data → dataset → ONNX models → middleware), and workspace/build conventions.
- [docs/STATUS.md](docs/STATUS.md) — current implementation status, open issues, and next steps.

---

## Installation

> Not yet published. Coming soon.

```bash
npm install logsguardian
```

---

## Usage

> API under development. Documentation will be available on release.

---

## Authors

- **Sebastian Huertas** — Cybersecurity integration, dataset verification, library architecture and structure, testing and core logic
- **Diego Valenzuela** — AI/ML model integration, library architecture and structure,  pattern design for the ML model, testing and core logic
  
Universidad del Valle de Guatemala — 2026

---
