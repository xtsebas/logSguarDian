# logsguardian CLI — Commands

All commands require `logsguardian.config.js` to exist in the current directory, except `config init`.

---

## config init

Generates `logsguardian.config.js` in the current directory with default values.

```bash
logsguardian config init
```

Exits with code 1 if the file already exists — it will not overwrite an existing configuration.

**Generated file:**

```js
// logsguardian.config.js
module.exports = {
  mode: 'block',
  threshold: 0.70,
  model: 'hybrid',
  timeoutMs: 50,
  dbPath: './logsguardian.db',
};
```

---

## config show

Prints the active configuration as a formatted table.

```bash
logsguardian config show
logsguardian config show --format json
```

| Flag | Values | Default |
|---|---|---|
| `--format` | `table`, `json` | `table` |

**Example output (`table`):**

```
logSguarDian — Active Configuration

  KEY        VALUE
  ─────────────────────────────────
  mode       block
  threshold  0.7
  model      hybrid
  timeoutMs  50
  dbPath     ./logsguardian.db
```

---

## config set

Modifies a single key in the active `logsguardian.config.js`. Validates the value before writing — if invalid, the file is not modified.

```bash
logsguardian config set <key> <value>
```

**Supported keys:**

| Key | Type | Valid values | Default |
|---|---|---|---|
| `threshold` | float | `0` – `1` | `0.70` |
| `mode` | string | `block`, `monitor` | `block` |
| `model` | string | `rf`, `if`, `hybrid` | `hybrid` |

- `threshold` — RF confidence threshold. Requests with confidence ≥ threshold are treated as attacks.
- `mode` — `block` sends HTTP 403 on detected attacks; `monitor` logs only, never blocks.
- `model` — which model(s) to use: `rf` (Random Forest only), `if` (Isolation Forest only), `hybrid` (both).

**Examples:**

```bash
logsguardian config set threshold 0.85
logsguardian config set mode monitor
logsguardian config set model rf
```

Exits with code 1 on unknown key or invalid value, with a descriptive error message.

---

## config validate

Reads the active configuration and checks all fields for correctness. If `modelDir` is set, also verifies that the required `.onnx` model files exist on disk.

```bash
logsguardian config validate
```

Reports all errors found (not just the first one). Exits with code 1 if any error is detected.

**Checks performed:**

| Field | Rule |
|---|---|
| `mode` | must be `block` or `monitor` |
| `threshold` | must be a number in `[0, 1]` |
| `model` | must be `rf`, `if`, or `hybrid` |
| `timeoutMs` | must be a positive integer |
| `dbPath` | must be a non-empty string |
| `modelDir` | if set, directory must exist and contain the required `.onnx` files |

**Example — valid config:**

```
Configuration is valid.
```

**Example — invalid config:**

```
logsguardian: configuration has errors:

  - mode: must be 'block' or 'monitor', got 'log'
  - threshold: must be a number in [0, 1], got 2
  - model: must be 'rf', 'if', or 'hybrid', got 'bert'
```

---

## attacks list

Reads the SQLite event log and prints the catalog of attack types the model has classified, with total count and last-seen timestamp per type.

```bash
logsguardian attacks list
logsguardian attacks list --format json
```

| Flag | Values | Default |
|---|---|---|
| `--format` | `table`, `json` | `table` |

**What counts as an attack type:** grouped by `predicted_class` where it is not `'benign'` — this is independent of `verdict`. A request the RF classified as `sqli` at low confidence (and therefore passed through, never blocked) still counts here: this command catalogs what the model has *seen*, not what got blocked. `'benign'` is excluded since it isn't an attack type. (Contrast with `endpoints top`/`profile`/`report`, which use the incident set `verdict IN ('block', 'pass_anomaly')`.)

Sorted by `total_count` descending. `last_detected` is the event `timestamp` (ms epoch in JSON, ISO 8601 UTC string in the table).

Exits with code 1 if no database file exists at `dbPath`.

**Example output (`table`):**

```
logSguarDian — Attack Type Catalog

  TYPE      TOTAL COUNT  LAST DETECTED (UTC)
  ──────────────────────────────────────────
  sqli      12           2026-07-18T14:03:21.000Z
  xss       4            2026-07-18T09:12:05.000Z
  cmdi      1            2026-07-17T22:47:10.000Z
```

---

## attacks summary

Reads the SQLite event log and prints the distribution of attack types by endpoint, time period, and severity.

```bash
logsguardian attacks summary
logsguardian attacks summary --from 2026-07-01 --to 2026-07-18
logsguardian attacks summary --endpoint /api/login
logsguardian attacks summary --format json
```

| Flag | Values | Default |
|---|---|---|
| `--from <date>` | `YYYY-MM-DD` or ISO 8601 | no lower bound |
| `--to <date>` | `YYYY-MM-DD` or ISO 8601 | no upper bound |
| `--endpoint <route>` | exact route path | all routes |
| `--format` | `table`, `json` | `table` |

A `YYYY-MM-DD` value for `--to` is treated as inclusive of the whole day (23:59:59.999 UTC), so `--to 2026-07-18` includes everything on that date. Exits with code 1 if a date is unparseable or if `--from` is after `--to`.

**Same attack-type definition as `attacks list`:** grouped by `predicted_class != 'benign'`, independent of `verdict` — a low-confidence classification that passed through is still counted (at `low` severity, see below).

**Severity is derived from `verdict`**, reusing the existing decision policy (`docs/decision-policy.md` §3.1) instead of a new confidence-bucket scheme:

| Severity | Verdict | Meaning |
|---|---|---|
| `high` | `block` | RF confidence crossed `RF_THRESHOLD` — actually blocked |
| `medium` | `pass_anomaly` | IF flagged the request as statistically anomalous |
| `low` | `pass` | RF classified an attack type but confidence stayed under threshold |

Rows are grouped by route (path + method), then ordered `high` → `medium` → `low` within each route.

Exits with code 1 if no database file exists at `dbPath`.

**Example output (`table`):**

```
logSguarDian — Attack Summary

  /api/login (POST)
    HIGH    sqli            3
    MEDIUM  xss             1
    LOW     cmdi            1
  /api/users (GET)
    HIGH    sqli            1
```

---

## attacks inspect

Prints detail on one attack type: model detection rate, top contributing features, and example payloads seen in the SQLite event log.

```bash
logsguardian attacks inspect sqli
logsguardian attacks inspect cmdi --format json
```

| Flag | Values | Default |
|---|---|---|
| `--format` | `table`, `json` | `table` |

Requires a `<type>` positional argument — one of `sqli`, `xss`, `path_traversal`, `cmdi`. Exits with code 1 if the argument is missing or not one of these four (`benign` is not an attack type and is not accepted here, same as `attacks list`/`attacks summary`).

**Detection rate:** per-class precision/recall/F1 loaded from `training/models/class_metrics.json` (bundled into the npm package as `data/class_metrics.json`, refreshed by the `postbuild` script). These are the official **locked test-set** numbers (R2 one-time read, 2026-06-20) from `docs/decision-policy.md` §2.1 — `eval_set` and the accompanying `eval_note` are always shown alongside the score.

**Top features:** the 5 highest-ranked entries from `training/models/feature_importance.json` (also bundled as `data/feature_importance.json`), by mean impurity decrease. This is the **overall Random Forest importance**, not per-class — per-class importance hasn't been extracted from `rf_v2.pkl` (present on local disk but git-ignored, not committed). The same top-5 list is shown for every attack type, with a visible note clarifying this.

**Payload examples:** up to 3 most recent examples of this `predicted_class` from `detection_events` where `verdict IN ('block', 'pass_anomaly')`, most recent first. These come from the **live SQLite event log** (real traffic the middleware has seen), not from the training JSONL files in `training/data_clean/` — those are not shipped with the npm package. If `dbPath` doesn't exist, or no matching events exist yet, the command does not fail — it shows the detection rate and top features, and prints "No examples in store yet — run the middleware against real traffic first" in place of examples.

**Example output (`table`):**

```
logSguarDian — Attack Inspect: SQLI

  DETECTION RATE
  ────────────────────────────────────────
  F1 Score (test set): 99.5%
  Precision: 99.5%  Recall: 99.5%
  Note: Official locked test-set numbers (R2 one-time read, 2026-06-20) — docs/decision-policy.md §2.1. Test set read exactly once; no retraining after observing these numbers.

  TOP FEATURES (overall RF importance)
  ────────────────────────────────────────
  RANK  FEATURE                       IMPORTANCE
  ──────────────────────────────────────────────
  1     ua_length                     0.0786
  2     special_char_ratio            0.0633
  3     path_length                   0.0551
  4     path_depth                    0.0511
  5     traversal_sequence_count      0.0496
  (Overall RF feature importance — per-class importance not available (pkl not persisted). Displayed for all attack classes.)

  PAYLOAD EXAMPLES (from detection store)
  ────────────────────────────────────────
  No examples in store yet — run the middleware against real traffic first
```

---

## endpoints top

Reads the SQLite event log (`dbPath`) and prints a ranking of routes by detected-attack frequency.

```bash
logsguardian endpoints top
logsguardian endpoints top --limit 5
logsguardian endpoints top --format json
```

| Flag | Values | Default |
|---|---|---|
| `--limit` | positive integer | `10` |
| `--format` | `table`, `json` | `table` |

**What counts as an incident:** any request with `verdict = 'block'` or `verdict = 'pass_anomaly'` — the same set that triggers webhooks (`docs/decision-policy.md` §3.1). `verdict = 'pass'` is not an attack and is excluded.

**Risk score:** `incident_count * avg_confidence` for that route+method, rounded to 2 decimals. Combines frequency (how often the route is hit) with severity (how confident the RF model was on those hits) into one comparable number — it is a simple heuristic, not a statistically validated risk model.

Routes are ranked by `incident_count` descending (ties keep insertion order).

Exits with code 1 if no database file exists at `dbPath`.

**Example output (`table`):**

```
logSguarDian — Top Endpoints by Attack Frequency

  METHOD  ROUTE           INCIDENTS  RISK SCORE
  ──────────────────────────────────────────────
  POST    /api/login      3          2.85
  GET     /api/users      2          1.60
```

---

## endpoints profile

Reads the SQLite event log and prints a detailed profile of a single route: attack-type breakdown, hourly distribution of incidents (UTC, 0–23), and source IPs / `/24` ranges.

```bash
logsguardian endpoints profile <route>
logsguardian endpoints profile /api/login --method POST
logsguardian endpoints profile /api/login --format json
```

| Flag | Values | Default |
|---|---|---|
| `--method` | HTTP method, case-insensitive | all methods for the route |
| `--format` | `table`, `json` | `table` |

Uses the same incident definition as `endpoints top` (`verdict = 'block'` or `'pass_anomaly'`). Source IPs come from `client_ip` on `DetectionEvent`, captured from Express's `req.ip` in the middleware — events logged before this field existed will show an empty `client_ip` and are excluded from the IP/range sections (but still counted in totals and attack types). `/24` ranges are computed by zeroing the last IPv4 octet; non-IPv4 values (e.g. IPv6) pass through as-is, ungrouped.

Exits with code 1 if no route argument is given, or if no database file exists at `dbPath`.

**Example output (`table`):**

```
logSguarDian — Route Profile: /api/login

  Total incidents: 3 (block: 3, pass_anomaly: 0)
  Methods: POST (3)

  Attack types:
    sqli            3

  Hourly distribution (UTC):
    03:00           2
    14:00           1

  Top source IPs:
    203.0.113.5         2
    198.51.100.20       1

  Source ranges (/24):
    203.0.113.0/24       2
    198.51.100.0/24      1
```

---

## endpoints report

Exports the full endpoint analysis — every route+method with at least one incident — as JSON or CSV. Meant for scripting/spreadsheets, not terminal reading (no `table` format).

```bash
logsguardian endpoints report
logsguardian endpoints report --format csv
logsguardian endpoints report --format csv --output routes.csv
```

| Flag | Values | Default |
|---|---|---|
| `--format` | `json`, `csv` | `json` |
| `--output <path>` | file path | stdout |

Uses the same incident definition as `endpoints top`/`endpoints profile` (`verdict = 'block'` or `'pass_anomaly'`). Unlike `endpoints top`, this is not truncated — every route with incidents is included.

**JSON** gives one object per route+method with the full breakdown (`attack_types` as an array, `top_source_ip` as the single most frequent IP for that route).

**CSV** flattens the same data to one row per route+method — arrays don't fit a table, so `attack_types` is serialized as `class:count` pairs joined by `;` (e.g. `sqli:3;xss:1`), and only the single most frequent source IP is kept (`top_source_ip`), not the full IP list.

| CSV column | Meaning |
|---|---|
| `path`, `method` | route identity |
| `incident_count` | total block + pass_anomaly events |
| `block_count`, `pass_anomaly_count` | breakdown by verdict |
| `risk_score` | same formula as `endpoints top` |
| `top_attack_class` | most frequent `predicted_class` for this route |
| `attack_types` | `class:count` pairs, semicolon-separated |
| `top_source_ip` | most frequent `client_ip` (empty if none recorded) |

With `--output`, the report is written to that file and stdout only prints a confirmation line (`Wrote N route(s) to <path>`) — it does not also dump the report to the terminal.

Exits with code 1 if `--format` is anything other than `json`/`csv`, or if no database file exists at `dbPath`.

**Example output (`csv`, no `--output`):**

```
path,method,incident_count,block_count,pass_anomaly_count,risk_score,top_attack_class,attack_types,top_source_ip
/api/login,POST,3,3,0,2.85,sqli,sqli:2;xss:1,203.0.113.5
/api/users,GET,2,2,0,1.60,cmdi,cmdi:2,9.9.9.9
```

---

## webhooks add

Registers a webhook destination in the SQLite store. The URL must be HTTPS.

```bash
logsguardian webhooks add <url>
```

Validates the URL in two steps: first that it's syntactically valid, then that its scheme is `https:`. On success, stores `id` (auto-generated), `url`, `created_at` (epoch ms), and `status` (`active`) in a `webhooks` table, and prints the assigned id.

**Unlike the read commands** (`endpoints top/profile/report`, `attacks list/summary`), this command does not require `dbPath` to already exist — it creates the database file (and the `webhooks` table) on first use, the same way `config init` gets a project going from nothing.

Exits with code 1 if no URL is given, if the URL is not parseable, or if its scheme is not `https:`.

**Example:**

```
$ logsguardian webhooks add https://hooks.slack.com/services/T00/B00/XXX
Registered webhook #1: https://hooks.slack.com/services/T00/B00/XXX
```

---

## webhooks remove

Removes a webhook by ID from the SQLite store.

```bash
logsguardian webhooks remove <id>
```

`<id>` must be a plain integer (no decimals, no non-numeric characters). Exits with code 1 with a clear error if the ID doesn't exist, or if the argument isn't a valid integer.

**Example:**

```
$ logsguardian webhooks remove 1
Removed webhook #1

$ logsguardian webhooks remove 1
logsguardian: webhook #1 not found
```
