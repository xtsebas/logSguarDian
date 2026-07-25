# Known Limitations — logSguarDian

This document collects the technical limitations identified during development
and validation. It corresponds to Section 8.3 of the thesis (Threats to Validity).

---

## 1. Command Injection Detection (cmdi)

### Feature Space Separability Problem

The cmdi class has the lowest model performance (F1 = 0.902 with the final
configuration) and was the only class that prevented reducing model size without
losing quality. The root cause is structural: command injection patterns (shell
separators such as `|`, `;`, `` ` ``; binary names like `/bin/sh`, `/etc/passwd`;
redirection operators `>`, `>>`) share features with benign traffic (legitimate
filesystem paths) and with path traversal attacks. In the 66-dimensional feature
space produced by the extractor, cmdi is not linearly separable from these classes
at moderate tree depths.

### SMOTE Experiment — Negative Result

SMOTE was applied to the training set to augment the cmdi class from 3,881 real
samples to 25,000 (3,881 real + 21,119 synthetic). The improvement was marginal:
+0.015 in F1 at max_depth=15 (0.593 → 0.608) and no improvement at max_depth=20.
SMOTE operates in feature space via linear interpolation between real vectors — it
does not generate new textual payloads. Synthetic vectors can produce feature
combinations that correspond to no real attack (e.g. `shell_command_count > 0` and
`sqli_keyword_count > 0` simultaneously), but they do not open new decision
boundaries in regions of the space that shallow trees cannot resolve. The experiment
confirmed the problem is **separability**, not **sample count**.

### Adopted Solution

The final model uses max_depth=25, which provides enough splits to isolate the
feature combinations that distinguish cmdi from benign traffic and path traversal.
At this depth, cmdi reaches F1 = 0.902.

The practical implication is that the model cannot be reduced below depth 25 without
sacrificing cmdi detection. If a lighter model is required in the future, the
alternatives are: (a) architectures with more compact representations (XGBoost,
LightGBM); (b) additional features that improve cmdi separability (e.g. shell token
sequence analysis on the raw payload).

---

## 2. ONNX Runtime Memory Expansion Factor

The `TreeEnsembleClassifier` operator in ONNX Runtime materializes the full tree
structure into native C++ memory when the session is created. The measured expansion
factor is ~1.264 KB per node: the original model (rf_v1, 367,655 nodes, 44 MB on
disk) consumed 465 MB RSS when loaded. The final model (rf_v2, 180,022 nodes,
10.8 MB on disk) consumes 122 MB RSS — a 74% reduction with a 0.005 loss in macro F1.

This behavior is inherent to the ORT implementation for Random Forests and cannot
be mitigated through session configuration. Future models should estimate memory
footprint as `n_nodes × 1.264 KB` before setting memory gates.

---

## 3. base64_like_count — Leakage Risk

The feature `base64_like_count` (#25 in the feature spec) counts character sequences
that resemble base64 encoding in the payload. In real attacks, adversaries may
encode payloads in base64 to evade detection — meaning this feature may correlate
with the attack label not only because of the payload's semantic content, but because
of the presence of base64 obfuscation in the training dataset.

Importance analysis (ONNX node splits): ranked #20 of 66 with 0.86% of all splits.
Moderate importance — the model relies on this feature but not dominantly. Limitation
documented in the Threats to Validity section: if the training corpus overrepresents
base64-encoded attacks relative to real traffic, the model may learn an encoding
heuristic rather than semantic attack patterns.

---

## 4. Data Source Coverage

The system was trained on public datasets (CAPEC, ModSecurity, OWASP, payload
corpora). Real production traffic may differ in length distribution, encoding,
User-Agent patterns, and feature combinations. The leave-one-source-out validation
(Task 3.6 in PLAN.md) is pending and will measure per-source degradation.

---

## 5. Near-Duplicate Detection Scope Gap

Near-duplicate detection (Levenshtein edit distance < 3 on the `query` field) was
implemented in `training/unify.py` and ran on the data that produced `train.parquet`.
The 213,879 rows (53.5%) with empty `query` fields were correctly excluded — for
those records, attack signal lives in `path` or `body`. Two independent gaps remain:

**(a) 100-character query cutoff — unjustified scope restriction.**
82,262 rows (20.6%) had non-empty queries longer than 100 characters and were never
evaluated for near-duplicates. The only rationale in the source code is the comment
"short queries likely duplicates" (`unify.py:118`); no performance analysis or
empirical observation supports this threshold. Long encoded payloads — URL-encoded
SQLi chains, multi-parameter XSS strings — are disproportionately in this excluded
segment: 10.7% of sqli rows, 15.2% of xss rows, and 43.7% of benign rows exceed
the cutoff. Minor payload variations in those rows were never flagged.

**(b) max_pairs=10,000 cap — near-zero pairwise coverage within the scanned window.**
Even among the 103,501 rows within the 1–100 char window, the scan is capped at
10,000 comparisons per label bucket. For sqli, this covers under 0.002% of possible
within-label pairs (~976M total). The cap is the more significant gap: it means even
the "scanned" segment provides no statistical confidence that near-duplicates were
detected for any class with more than a few hundred items.

Near-duplicate removal was not performed in any case — the pipeline flags pairs but
retains all records. The 211 flagged pairs from the most recent run (Jun 14 2026)
remain in the training data.

Se evaluó corregir esta limitación re-ejecutando la detección de near-duplicates sin
el límite de 100 caracteres y sin el cap de max_pairs. Se decidió no hacerlo en esta
etapa del proyecto: cualquier cambio al dataset unificado invalidaría los modelos
finales ya entrenados y validados (rf_v2.pkl, if_v1.pkl), requiriendo repetir la
cadena completa de re-entrenamiento y re-verificación de paridad ONNX (Fases 4.2–4.4),
ya ejecutada dos veces durante el proyecto por razones similares de deriva de datos.
Se documenta como limitación reconocida y línea de trabajo futuro, en lugar de
remediarse retroactivamente.

See `training/DEDUP_METHODOLOGY.md` for full methodology detail and gap quantification.

---

## 6. Blank `method`/`path` Training Artifact (found via F5.7 E2E suite) — RESOLVED

**Status: fixed in the rf_v3/if_v2 retrain.** `training/parsers/parse_modsec_learn.py`
now emits `method="GET"`, `path="/"` instead of blank strings (both files
regenerated, full retrain pipeline re-run). The E2E benign false-positive rate
dropped from 21.0% to 2.0% as a direct result — see `docs/results.md` §F5.7
Update. The remainder of this section is kept as the historical record of the
original finding.

Several training data sources (`modsec_learn.jsonl`, `payload_full.jsonl`,
`payloads_csv.jsonl`) captured only the query string or body of a request,
leaving `method` and `path` as empty strings (`""`). This is not possible for
a real HTTP request — a live client always sends a method and a path (Express
reports `"GET"`/`"/"` at minimum). When the F5.7 end-to-end suite
(`e2e/detection.test.ts`) reconstructed these payloads as genuine HTTP
requests, the model's behavior changed sharply relative to the blank-field
training representation: the identical query `v=1651145922` scores 99.9%
benign with `method="", path=""` but 80.7% xss with `method="GET", path="/"`
(see `docs/results.md` §F5.7 for the full breakdown by class).

This means the model may be relying, in part, on the blank-field pattern
itself as a (spurious) signal correlated with certain sources/classes rather
than on the semantic content of the payload. It also means the official
offline test-set metrics in `docs/decision-policy.md` §2 — computed from
feature vectors that plausibly share this same blank-field distribution — may
not fully represent production behavior, where `method`/`path` are always
populated. Remediation would require normalizing `method`/`path` across all
training sources (e.g. synthesizing a plausible method/path for query-only
records) and re-running the full F3–F4 retrain/re-export pipeline; not done
in this PR for the same R2 reasons documented in `docs/decision-policy.md`
§2.3.

## 7. XSS Detection Gap on HTML-Entity-Encoded Payloads — PARTIALLY RESOLVED

**Status: mitigated, not eliminated, by two changes.** `packages/extractor`
now decodes HTML entities before XSS pattern matching
(`normalizers.ts::decodeHtmlEntities`, wired into `computeXssFeatures`), and
`RF_THRESHOLD` was recalibrated from 0.70 to 0.35 (`decision-policy.md`
§2.2.1). E2E xss detection moved 77% → 94% overall (see `docs/results.md`
§F5.7 Update). Notably, the entity-decode fix **alone was not sufficient** —
an intermediate run with rf_v3 retrained but `RF_THRESHOLD` still at 0.70
regressed to 70%, because the retrain shifted rf_v3's confidence calibration
broadly (not specific to entity-encoded payloads). The threshold
recalibration, not the decode fix, closed most of the remaining gap. The
historical finding below (original 68.9% on well-formed HTTP xss, pre-fix) is
kept as the record of what motivated the entity-decode change; the confidence
distributions cited are from rf_v2/if_v1 and are no longer current.

Among xss payloads with well-formed `method`/`path` (i.e. excluding the
artifact in §6), the F5.7 E2E suite detected only 51/74 (68.9%). Every missed
payload inspected used **HTML-entity encoding** (`&lt;script&gt;`,
`&quot;...&quot;`) rather than URL/percent-encoding (`%3Cscript%3E`) or raw
markup (`<script>`) — both of which are reliably detected. RF confidence on
these misses is 0.50–0.67 (below the 0.70 block threshold but still leaning
xss, not confidently benign), suggesting the extractor's pattern features do
not currently recognize HTML-entity encoding as an XSS obfuscation technique.
This is an evasion gap in the feature set, not a model capacity problem.

### 7.1 Recursive decode for double-encoded and unicode-escaped XSS — RESOLVED (unicode-escape, double-percent); HTML-entity confirmed not a real gap

The single-pass decode above (§7) only resolves one layer of encoding.
Investigation into three candidate evasion patterns — double HTML-entity
(`&amp;lt;script&amp;gt;`), double percent (`%253Cscript%253E`), and
JavaScript unicode escapes (`<script>`) — found the practical picture
is not "three equal gaps," once each is tested with genuinely full-string
obfuscation rather than the tag-delimiters-only obfuscation an earlier
synthetic fixture used by mistake (which inflated two categories to a
false 100% baseline):

- **Unicode-escape: a genuine, now-closed gap.** `\uXXXX` sequences are
  interpreted by the JS engine itself at parse time, so an attacker can
  legitimately unicode-escape an entire payload — including the callable
  (`alert(1)`) — and it still executes once decoded. Baseline detection on
  a corrected 120-record fixture (every character escaped): **0% → 100%**
  after adding `decodeUnicodeEscapes` to a bounded recursive wrapper
  (`normalizeForXssDetection`, `packages/extractor/src/normalizers.ts`).
- **Double-percent: real, and resolved better than expected.** RFC 3986's
  unreserved character set (letters, digits, `. - _ ~`) is never
  percent-encoded, so any trigger substring made purely of those characters
  (`document.cookie`) survives percent-encoding at any depth — a structural
  ceiling, not a fixture flaw. Baseline **50% → 100%** after the fix:
  recursive percent-decoding resolves the *other* half too (payloads whose
  trigger relies on `<`, `>`, `(`, `)`, `=`, `:`, which do get encoded).
- **Double HTML-entity: confirmed not a practical gap.** HTML-entity
  decoding only happens during HTML *parsing* — never inside JS execution
  context — so an attacker who entity-encodes the callable itself
  (`alert(1)` → `&#97;&#108;...`) breaks their own exploit; it no longer
  executes as valid JavaScript. Realistic entity-based evasion can therefore
  only ever obscure the tag delimiters (`<`, `>`), never the payload
  content, and that content (`alert(`, `onerror=`) remains a separately
  matched signal regardless of whether the surrounding tag is decoded. A
  synthetic fixture that fully obfuscated every character still measured
  **100% → 100%** (no fixture-level movement) — not because the fix doesn't
  work, but because this category isn't a real gap once the model already
  matches on the callable independent of the tag. The one genuine narrow
  case — a payload with *no* separately-exposed keyword at all (e.g.
  `<script>x()</script>` entity-encoded) — did move, **0/0 → 2/2**,
  confirming the fix is still correct and harmless to include.

**Scope discipline preserved**: the recursive decode applies only inside
`computeXssFeatures` — `html_entity_density` and `url_encoded_ratio` still
measure the raw, undecoded payload (the obfuscation-density signal these
features exist for would be destroyed if they read the decoded string).
Bounded to `maxDepth=5`; measured at 2.12ms for a 110KB pathological input,
well inside the 50ms fail-open timeout — no DoS risk from the depth cap.
FEATURE_NAMES count is unchanged at 73 (this changes what string feeds
`computeXssFeatures`, not the feature schema).

**Train/serve skew — flagged, not yet retrained.** 187/29,897 real xss
corpus rows (0.625%) show a different `xss_marker_count` under the new
decode logic versus what rf_v8/if_v7 were trained on (mostly real
double-percent-encoded payloads already present in `owasp_logs`). Small,
but consistent with this project's established practice of retraining after
any extractor change that shifts feature values. Not retrained yet —
intentionally batched into a planned v9 cycle alongside other pending
changes (MinHash near-duplicate dedup, real cmdi data) rather than
retraining per isolated change.
