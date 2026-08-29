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
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(logsguardian(config));
```

Generate the config file with the CLI before mounting the middleware:

```bash
npx logsguardian config init
```

Mount `logsguardian` **after** your body parsers (`express.urlencoded`/`express.json`, and any `multer` instance if your app accepts `multipart/form-data`) so it inspects a populated `req.body`, not an empty one.

---

## `logsguardian(options?)`

Factory function. Returns an Express `RequestHandler` (compatible with Express 4 and 5).

```typescript
import { logsguardian } from 'logsguardian';

const mw = logsguardian(options?: MiddlewareOptions): RequestHandler;
app.use(mw);
```

On first call the factory:
1. Spawns one dedicated Random Forest (RF) inference worker, plus a small round-robin pool of Isolation Forest (IF) workers, and begins loading `rf.onnx` / `if.onnx` in each.
2. Opens the SQLite event log at `dbPath`.
3. Opens a second connection to the same database file for the webhook registry (see [`webhookUrl` and registered webhooks](#webhookurl-and-registered-webhooks)).

Model loading is asynchronous and happens off the request path. Requests that arrive before a worker has finished loading are dispatched only to workers that have already signaled readiness — a worker still loading is never sent real traffic. If the RF worker itself isn't ready yet, the request is **always passed through** (fail-open — see [Fail-open contract](#fail-open-contract)).

---

## `MiddlewareOptions`

```typescript
interface MiddlewareOptions {
  mode?: 'block' | 'monitor';
  threshold?: number;
  model?: 'rf' | 'if' | 'hybrid';
  timeoutMs?: number;
  dbPath?: string;
  modelDir?: string;
  webhookUrl?: string;
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `'block' \| 'monitor'` | `'block'` | **block** — sends HTTP 403 when a request is classified as an attack with `confidence ≥` the active threshold. **monitor** — computes and logs the verdict but never blocks; all requests are forwarded regardless of classification. Use `'monitor'` for dark-launch validation before enabling enforcement. |
| `threshold` | `number` | `0.35` | RF confidence threshold (0–1) above which an attack-classified request is blocked. Lowering it catches more attacks at the cost of more false positives on legitimate traffic; raising it does the opposite. `0.35` is the calibrated default — see `docs/decision-policy.md` for how it was derived. |
| `model` | `'rf' \| 'if' \| 'hybrid'` | `'hybrid'` | Which model(s) to run. `'hybrid'` runs both (RF for blocking, IF for anomaly logging — see [Decision policy](#decision-policy)). |
| `timeoutMs` | `number` | `50` | Maximum time in milliseconds to wait for the RF worker to return an inference result before failing open. See [Fail-open contract](#fail-open-contract). IF is never waited on — its result, if it arrives after the response has already been sent, patches the log entry asynchronously instead (see [Decision policy](#decision-policy)). |
| `dbPath` | `string` | `./logsguardian.db` (relative to `process.cwd()`) | Path to the SQLite database. Holds both the detection-event log and the webhook registry (separate tables, same file). Created automatically on first run. Use `':memory:'` in tests to avoid writing to disk. |
| `modelDir` | `string` | `<package>/models/` | Directory containing `rf.onnx` and `if.onnx`. Defaults to the `models/` directory shipped with the package. Override in tests or CI environments where models live elsewhere. |
| `webhookUrl` | `string` | unset | A single static HTTP(S) URL to POST a JSON `DetectionEvent` to whenever a request resolves to `'block'` or `'pass_anomaly'`. Delivery is fire-and-forget (3s timeout, silent failure) and never affects the response. Additional webhook destinations can be registered at runtime via the CLI (`logsguardian webhooks add <url>`) without restarting the app — see [`webhookUrl` and registered webhooks](#webhookurl-and-registered-webhooks). |

---

## `DetectionEvent`

Every request processed by the middleware produces one `DetectionEvent` written to the SQLite log.

```typescript
interface DetectionEvent {
  timestamp: number;         // Unix epoch ms — Date.now() at request arrival
  method: string;            // HTTP verb (GET, POST, …)
  path: string;               // req.path
  query_string: string;       // raw query string
  user_agent: string;         // req.headers['user-agent']
  client_ip: string;          // req.ip
  verdict: Verdict;
  predicted_class: AttackClass; // RF argmax class
  confidence: number;         // max(rf_probs) — probability of predicted_class
  if_score: number;           // Isolation Forest decision_function output (0 until IF replies, see note below)
  is_anomaly: boolean;
  webhook_sent: boolean;
  elapsed_ms: number;         // wall-clock time from request arrival to response
}
```

**`if_score`/`is_anomaly` may update after the row is first written.** RF resolves the HTTP response immediately and never waits for IF (IF holds no blocking authority — see [Decision policy](#decision-policy)). If IF's result arrives after the response was already sent, the same row is patched in place with the real `if_score`, and a `'pass'` verdict can flip to `'pass_anomaly'` retroactively (firing a webhook at that point, if one is configured). This means reading the event log immediately after a request may show a stale `if_score: 0` for a few milliseconds on requests where IF hadn't replied yet.

### SQLite schema

```sql
CREATE TABLE IF NOT EXISTS detection_events (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp       INTEGER NOT NULL,
  method          TEXT    NOT NULL,
  path            TEXT    NOT NULL,
  query_string    TEXT    NOT NULL DEFAULT '',
  user_agent      TEXT    NOT NULL DEFAULT '',
  client_ip       TEXT    NOT NULL DEFAULT '',
  verdict         TEXT    NOT NULL,
  predicted_class TEXT    NOT NULL,
  confidence      REAL    NOT NULL,
  if_score        REAL    NOT NULL,
  is_anomaly      INTEGER NOT NULL DEFAULT 0,
  webhook_sent    INTEGER NOT NULL DEFAULT 0,
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
| `'block'` | RF predicted an attack class with `confidence ≥ threshold` (default `0.35`). In `'block'` mode the request receives HTTP 403. In `'monitor'` mode it is logged but forwarded. |
| `'pass'` | Not blocked, and IF did not flag the request as anomalous. Normal traffic. |
| `'pass_anomaly'` | Not blocked, but IF flagged the request as statistically anomalous (`if_score < IF_THRESHOLD`). The request is **always forwarded** — IF holds no blocking authority. Useful as a signal for downstream SIEM/alerting. Can appear on a row retroactively — see the note under [`DetectionEvent`](#detectionevent). |
| `'timeout'` | The RF worker did not return an inference result within `timeoutMs`, or wasn't available. The request is forwarded (fail-open). |

---

## `AttackClass`

```typescript
type AttackClass = 'benign' | 'cmdi' | 'path_traversal' | 'sqli' | 'xss';
```

The RF always returns one of these five classes as `predicted_class`, even when the verdict is `'pass'` or `'timeout'`.

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
  threshold: 0.35,
  timeoutMs: 50,
  dbPath: './logsguardian.db',
};

export default config;
```

---

## Decision policy

The middleware applies this policy per request (full rationale and calibration history: `docs/decision-policy.md`):

```
rf_classes   = ['benign', 'cmdi', 'path_traversal', 'sqli', 'xss']
RF_THRESHOLD = 0.35     // single global threshold; overridable via options.threshold
IF_THRESHOLD = 0.002486040118540811

predicted_class = rf_classes[argmax(rf_probs)]
confidence      = max(rf_probs)
is_attack       = predicted_class != 'benign'
is_anomaly      = if_score < IF_THRESHOLD

if is_attack AND confidence >= RF_THRESHOLD  →  verdict = 'block'
else if is_anomaly                           →  verdict = 'pass_anomaly'
else                                          →  verdict = 'pass'
```

**RF is the sole blocking authority.** IF is an unsupervised anomaly detector trained only on benign traffic — it has no concept of attack classes and cannot distinguish sqli from xss from cmdi, so it never gates the response. Its score only enriches the log (see the note under [`DetectionEvent`](#detectionevent)) and can drive `pass_anomaly`/webhook notifications after the fact.

**Known limitation:** IF's `pass_anomaly` rate on ordinary benign traffic is currently much higher than its offline-calibrated target (root-caused to a User-Agent representation gap in its training data — see `docs/limitations.md`). This does not affect blocking (RF is unaffected), but it means `pass_anomaly` volume should be treated as noisy operational signal, not a precise anomaly rate, until that gap is closed.

**RF and IF see different feature slices.** Both are computed from the same underlying 73-feature vector (`@logsguardian/extractor`), but RF consumes 67 of them and IF consumes 61 (6 further features dropped for IF — confirmed zero/near-zero variance on benign traffic, dead weight for anomaly detection). This is an internal implementation detail, not something callers need to configure.

---

## `webhookUrl` and registered webhooks

Two independent ways to get notified, both active if configured:

1. **`options.webhookUrl`** — a single static URL set in `logsguardian.config.js`.
2. **CLI-registered webhooks** — `logsguardian webhooks add <url>` (see `docs/commands.md`). The registry is a SQLite table in the same `dbPath` database, queried fresh on every notifiable event — adding or removing a webhook while the server is running takes effect on the very next request, no restart needed.

Every `'block'` or `'pass_anomaly'` verdict (including one that only becomes `'pass_anomaly'` via the late IF patch described above) POSTs the `DetectionEvent` as JSON to `webhookUrl` (if set) and to every `active` registered webhook. Each delivery is independent, fire-and-forget, with a 3s timeout and silent failure — a webhook endpoint being down never affects the response to the original request.

---

## Fail-open contract

The middleware **must not become a denial-of-service vector** against the host application. The following conditions all result in the request being forwarded unconditionally and a `'timeout'` verdict being logged:

- The RF worker has not yet finished loading `rf.onnx`.
- The RF worker did not respond within `timeoutMs`.
- The RF worker crashed or encountered an unrecoverable error.
- `dist/worker.js` was not found, or a worker failed to spawn (e.g. package not built).
- The SQLite store failed to initialise (in this case, the request still gets a decision — it just isn't logged).

IF is never on this critical path — a slow, crashed, or unavailable IF worker never affects the response; only the `if_score`/`is_anomaly` fields and any late webhook may be missing.

In all fail-open cases `next()` is called and the application continues normally.

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

The middleware converts the Express `req` object to a `CanonicalRequest` (from `@logsguardian/extractor`). Feature extraction itself (`extractFeatureVector()`, 73 dimensions) runs **inside each worker thread**, not on the main thread — the middleware only ships the `CanonicalRequest` across the worker boundary, keeping the extraction cost off the Node.js Event Loop entirely. Each worker slices the 73-dim vector down to what its own model expects (67 for RF, 61 for IF) by feature name.

Request bodies are serialized the same way the query string already is (`URLSearchParams`, not `JSON.stringify`) — this avoids introducing structural characters (`{`, `}`, `:`, `"`) that ordinary form submissions don't otherwise contain and that earlier caused false positives on plain login/form POSTs.

---

## CLI

```bash
logsguardian --help
```

Command groups: `config`, `attacks`, `endpoints`, `webhooks`. Full reference: `docs/commands.md`.

All CLI commands other than `config init` require `logsguardian.config.js` to exist in `process.cwd()`. If it does not, the command exits with code 1 and prints instructions to run `logsguardian config init` first.

### Common gotcha: `dbPath` mismatch between the CLI and the running middleware

The CLI (`attacks`/`endpoints`/`webhooks` commands) reads `dbPath` from `logsguardian.config.js`. The middleware reads `dbPath` from whatever options object your app actually passes to `logsguardian(options)`. These are two independent processes with no shared state — they only stay in sync if your app does:

```js
app.use(logsguardian(require('./logsguardian.config.js')));
```

If your app instead hardcodes its own options object (a different `dbPath`, or one derived some other way), the CLI will open a **different, valid, empty** SQLite file than the one your app is actually writing detection events to. This fails silently — no error, both files are legitimate — it just looks like nothing was ever detected. `attacks list`, `attacks summary`, `endpoints top`, and `endpoints profile` all print a hint pointing at this exact possibility whenever they return zero rows.

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
