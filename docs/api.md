# API Reference — logsguardian

**Package:** `logsguardian`  
**Entry point:** `dist/index.js` / `dist/index.d.ts`  
**Node.js requirement:** ≥ 20

---

## Quick start

```js
const express = require('express');
const { logsguardian } = require('logsguardian');
const config = require('./logsguardian.config.js');

const app = express();
app.use(express.json());
app.use(logsguardian(config));
```

Generate the config file with the CLI before mounting the middleware:

```bash
npx logsguardian config init
```

---

## `logsguardian(options?)`

Factory function. Returns an Express `RequestHandler` (compatible with Express 4 and 5).

```typescript
import { logsguardian } from 'logsguardian';

const mw = logsguardian(options?: MiddlewareOptions): RequestHandler;
app.use(mw);
```

On first call the factory:
1. Spawns the ONNX inference worker thread and begins loading `rf.onnx` + `if.onnx` in the background.
2. Opens the SQLite event log at `dbPath`.

Model loading is asynchronous and happens off the request path. Requests that arrive before the models are ready are **always passed through** (fail-open — see [Fail-open contract](#fail-open-contract)).

---

## `MiddlewareOptions`

```typescript
interface MiddlewareOptions {
  mode?: 'block' | 'monitor';
  timeoutMs?: number;
  dbPath?: string;
  modelDir?: string;
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `'block' \| 'monitor'` | `'block'` | **block** — sends HTTP 403 when a request is classified as an attack with `confidence ≥ 0.70`. **monitor** — computes and logs the verdict but never blocks; all requests are forwarded regardless of classification. Use `'monitor'` for dark-launch validation before enabling enforcement. |
| `timeoutMs` | `number` | `50` | Maximum time in milliseconds to wait for the worker to return an inference result. If the worker does not respond within this window the request is passed through and a `'timeout'` event is logged. See [Fail-open contract](#fail-open-contract). This value is provisional — it will be set to `p99_inference_latency × 3` once the F6 Artillery benchmarks run. |
| `dbPath` | `string` | `./logsguardian.db` (relative to `process.cwd()`) | Absolute or relative path to the SQLite event log file. The file and table are created automatically on first run. Use `':memory:'` in tests to avoid writing to disk. |
| `modelDir` | `string` | `<package>/models/` | Directory containing `rf.onnx`, `if.onnx`, and `model-metadata.json`. Defaults to the `models/` directory shipped with the package. Override in tests or CI environments where models live elsewhere (e.g. `training/models/`). |

---

## `DetectionEvent`

Every request processed by the middleware produces one `DetectionEvent` written to the SQLite log.

```typescript
interface DetectionEvent {
  timestamp: number;       // Unix epoch ms — Date.now() at request arrival
  method: string;          // HTTP verb (GET, POST, …)
  path: string;            // req.path
  verdict: Verdict;        // outcome of the decision policy
  predicted_class: AttackClass; // RF argmax class
  confidence: number;      // max(rf_probs) — probability of predicted_class
  if_score: number;        // Isolation Forest decision_function output
  elapsed_ms: number;      // wall-clock time from request arrival to verdict
}
```

### SQLite schema

```sql
CREATE TABLE IF NOT EXISTS detection_events (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp       INTEGER NOT NULL,
  method          TEXT    NOT NULL,
  path            TEXT    NOT NULL,
  verdict         TEXT    NOT NULL,
  predicted_class TEXT    NOT NULL,
  confidence      REAL    NOT NULL,
  if_score        REAL    NOT NULL,
  elapsed_ms      REAL    NOT NULL
);
```

---

## `Verdict`

```typescript
type Verdict = 'block' | 'pass' | 'pass_anomaly' | 'timeout';
```

| Value | Meaning |
|-------|---------|
| `'block'` | RF predicted an attack class with `confidence ≥ RF_THRESHOLD (0.70)`. In `'block'` mode the request receives HTTP 403. In `'monitor'` mode it is logged but forwarded. |
| `'pass'` | RF predicted `'benign'` with sufficient confidence, and the IF score is above the anomaly threshold. Normal traffic. |
| `'pass_anomaly'` | RF classified the request as benign (or below the block threshold), but the IF flagged it as statistically anomalous (`if_score < IF_THRESHOLD`). The request is **always forwarded** — the IF holds no blocking authority. Useful as a signal in downstream SIEM or alerting systems. |
| `'timeout'` | The worker did not return an inference result within `timeoutMs`. The request is forwarded (fail-open). |

---

## `AttackClass`

```typescript
type AttackClass = 'benign' | 'cmdi' | 'path_traversal' | 'sqli' | 'xss';
```

Matches the Random Forest output classes in `model-metadata.json`. The RF always returns one of these five classes as `predicted_class`, even when the verdict is `'pass'` or `'timeout'`.

---

## `Mode`

```typescript
type Mode = 'block' | 'monitor';
```

Alias for the `mode` option, exported for use in typed config files:

```typescript
// logsguardian.config.ts
import type { MiddlewareOptions } from 'logsguardian';

const config: MiddlewareOptions = {
  mode: 'monitor',
  timeoutMs: 50,
  dbPath: './logsguardian.db',
};

export default config;
```

---

## Decision policy

The middleware applies this policy on every inference result (source: `docs/decision-policy.md`):

```
rf_classes     = ['benign', 'cmdi', 'path_traversal', 'sqli', 'xss']
RF_THRESHOLD   = 0.70
IF_THRESHOLD   = 0.04428754289910031

predicted_class = rf_classes[argmax(rf_probs)]
confidence      = max(rf_probs)
is_attack       = predicted_class != 'benign'
is_anomaly      = if_score < IF_THRESHOLD

if is_attack AND confidence >= RF_THRESHOLD  →  verdict = 'block'
else if is_anomaly                           →  verdict = 'pass_anomaly'
else                                         →  verdict = 'pass'
```

**The Isolation Forest never blocks.** Its 10.1% false-positive rate on benign traffic makes IF-based blocking operationally unusable. The IF score enriches the event log and is available to downstream systems via `DetectionEvent.if_score`.

---

## Fail-open contract

The middleware **must not become a denial-of-service vector** against the host application. The following conditions all result in the request being forwarded unconditionally and a `'timeout'` event being logged:

- The worker thread has not yet finished loading the ONNX models.
- The worker thread did not respond within `timeoutMs`.
- The worker thread crashed or encountered an unrecoverable error.
- `dist/worker.js` was not found (e.g. package not built).
- The SQLite store failed to initialise.

In all these cases `next()` is called and the application continues normally.

---

## HTTP 403 response

When `mode = 'block'` and `verdict = 'block'`, the middleware sends:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "Forbidden",
  "class": "sqli"
}
```

`class` is the `predicted_class` value that triggered the block. No `next()` is called.

---

## Feature extraction

The middleware internally converts the Express `req` object to a `CanonicalRequest` (from `@logsguardian/extractor`) and calls `extractFeatureVector()` to compute the 72-feature vector. The 6 features excluded from model input (`status_code`, `req_count_1s`, `req_count_5s`, `req_count_60s`, `error_rate_4xx_60s`, `endpoint_diversity_60s`) are dropped by name inside the worker before calling the ONNX sessions. The resulting 66-feature vector matches exactly what the models were trained on.

This extraction is synchronous and runs on the main thread before the worker message is sent. It is pure and has no I/O.

---

## CLI

```bash
logsguardian --help
logsguardian config init     # generate logsguardian.config.js in cwd
```

All CLI commands other than `config init` require `logsguardian.config.js` to exist in `process.cwd()`. If it does not, the command exits with code 1 and prints:

```
logsguardian: no config found in /your/project
Run 'logsguardian config init' to initialise the project.
```

---

## Exports

```typescript
// Named exports from 'logsguardian'
export { logsguardian } from './middleware';
export type {
  MiddlewareOptions,
  DetectionEvent,
  Verdict,
  Mode,
  AttackClass,
} from './types';
```
