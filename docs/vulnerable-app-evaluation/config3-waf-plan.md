# Config 3b — WAF + logSguarDian (Layered)

## Purpose

Determine whether attacks that bypass ModSecurity+CRS (PL1) are still
caught by logSguarDian's ML-based detection — testing defense-in-depth,
not a WAF-vs-library comparison.

## Stack

```
Nginx+ModSecurity v3+CRS (PL1, blocking mode) -> Express+logSguarDian (rf_v10/if_v9) -> Postgres
```

- `waf` — `owasp/modsecurity-crs:nginx-alpine`, reverse-proxying to `app:3000`.
  Only publicly-published port (`3000:8080` on the host).
- `app` — internal-only, no host port. Reachable exclusively through `waf`
  so the attack corpus can't accidentally bypass ModSecurity.
- `db` — Postgres, unchanged from Config 1/2.

CRS paranoia level: PL1 (`PARANOIA=1`, `BLOCKING_PARANOIA=1`), the realistic
default for the target audience (SMEs/startups without a dedicated security
team to hand-tune CRS false positives at PL2+). `MODSEC_RULE_ENGINE=On`
(blocking, not detection-only).

## Distinguishing from Config 3a

- **Config 3a** (branch `feat/waf-modsecurity-crs`) — WAF-only baseline, no
  logSguarDian, for direct WAF-vs-library comparison against Config 1/2's
  numbers.
- **Config 3b** (branch `feat/config3-waf-plus-logsguardian`, this doc) —
  layered stack, answers "does logSguarDian catch what ModSecurity misses."

## Disambiguating which layer acted

Both layers can return a blocking response, so HTTP status alone can't tell
you which one acted. `waf`'s ModSecurity audit log (`waf/audit/`, JSON,
`RelevantOnly`) is the ground truth for "WAF blocked this request" vs.
"request reached the app" — cross-reference against logSguarDian's own
detection log to attribute each blocked/flagged request to a layer.
