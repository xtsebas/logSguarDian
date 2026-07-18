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
