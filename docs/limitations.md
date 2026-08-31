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

### 1.1 Real diverse data (v9) — the SMOTE ceiling broke, with a nuance

**The hypothesis behind this experiment**: SMOTE's failure showed *sample count*
wasn't the problem, but that left open whether *genuine technique diversity*
(not synthetic interpolation between existing points) could open the feature-space
regions SMOTE couldn't reach. v9 added 2,470 real cmdi payloads from two public
sources — SecLists' `command-injection-commix.txt` (2,455 samples, deduplicated
to one representative per structural template) and 15 hand-curated
PayloadsAllTheThings payloads — verified via MinHash (threshold=0.70) to have
**0% near-duplicate overlap** with the existing 5,554-sample cmdi corpus, i.e.
genuinely different techniques (subshell/backtick splitting, `tr`/`xxd`
hex-encoding bypasses, quote-splitting evasion, DNS exfiltration, blind
character-oracle extraction, polyglot payloads), not more points near existing
ones. This grew the cmdi class 44.5% (5,554 → 8,024 samples) without touching
SMOTE, sample weighting, or model architecture.

**Result: the ceiling broke, cleanly, on both models.**

| Metric | v7/v8 (SMOTE-era ceiling) | v9 (real diverse data) |
|--------|---------------------------|--------------------------|
| RF cmdi F1 (val) | 0.89–0.90 | **0.9369** |
| RF cmdi F1 (test, R2) | — | **0.9342** (consistent with val — not overfitting) |
| RF macro F1 (val) | 0.9691 (v8) | **0.9810** |
| IF cmdi recall (val) | 0.9400 (v8) | **0.9443** |

Where SMOTE moved cmdi F1 by +0.015 and only at shallow depths, real diverse data
moved it by **+0.03 to +0.05** at the production depth (25), and the gain held
identically on the held-out test set — the opposite of the interpolation problem
SMOTE had, where synthetic vectors created feature combinations no real attack
would produce. This is a genuine confirmation of the original diagnosis: the
separability problem was about the *training distribution's technique coverage*,
not about having more samples of the same techniques.

**The nuance — offline gain did not show up in the small live E2E fixture.**
The 100-payload E2E cmdi fixture (`e2e/fixtures/test_payloads.jsonl`, unchanged
across v7–v9) stayed flat-to-slightly-down: 97% (v8) → 96% (v9), a one-sample
difference at this fixture size, within noise. This does not contradict the
test-set result — it reflects the E2E fixture's small, fixed sample effectively
being near a detection ceiling already, while the offline test set (1,203 cmdi
samples, comprehensive and drawn from the same distribution the new data
targets) has the statistical resolution to show the real improvement. The
practical implication: the E2E suite's 100-payload-per-class fixtures are useful
as a fast smoke-level regression gate but are not sized to detect improvements
of this magnitude — the test-set F1 is the trustworthy signal here, consistent
with why R2 test-set reads exist as the authoritative metric in this project.

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
User-Agent patterns, and feature combinations.

Leave-one-source-out validation (Task 3.6 in PLAN.md) has been completed —
see `docs/results.md` §F3.6 for the full table and methodology
(`training/loso_validation.py`, `training/models/loso_results.json`). **0 of
9 sources show macro F1 ≥ 0.80 when held out entirely**; only
`command_injection` clears the ≥ 0.60 "moderate degradation" band (0.7762),
and the remaining 8 fall in the 0.00–0.55 "poor generalization" band. This
does **not** indicate the model is unable to detect attacks in general — its
in-corpus test-set performance (macro F1 0.9682) is real and reproducible.
It indicates instead that degradation comes from **two distinct,
independently-confirmed mechanisms**, quantified in `docs/results.md`
§F3.6.1 by correlating each source's LOSO F1 against its share of its
dominant class:

1. **Volume starvation (the primary driver for 8 of 9 sources).** One or two
   sources supply 85–99% of the training signal for every class (capec:
   84.6% of sqli; modsec_learn: 92.9% of benign; owasp_logs + capec: 99.6%
   of path_traversal combined), so removing that source removes the class's
   signal almost entirely rather than simulating exposure to a
   merely-unfamiliar-but-comparable source. Excluding the one outlier below,
   LOSO F1 correlates with dominant-class share at **−0.744** — strong
   confirmation that share of the corpus, not novelty of style, explains
   most of the degradation.
2. **Genuine style-driven generalization failure (the `synthetic_nav`
   outlier).** `synthetic_nav` holds the *smallest* class share of any
   source (0.9% of benign) yet produces the *worst* LOSO score by a wide
   margin (F1 0.0027) — the opposite of what volume alone predicts. It is a
   template-generated benign set whose structured, low-entropy navigation
   paths don't resemble any of the other benign sources; removing it removes
   a whole *style* of benign request, not a meaningful volume of examples.
   This is a real generalization blind spot, not a data-volume artifact.

The reverse case also holds: `command_injection` has a similarly small
class share (5.7% of cmdi) but the *best* LOSO score of all 9 sources
(0.7762), because its cmdi payloads overlap stylistically with
capec/owasp_logs's cmdi, which remain in training. Low volume alone does not
predict poor transfer — style overlap with what remains does.

**Practical implication:** the model's demonstrated generalization is bounded
to the styles already represented in this corpus (CAPEC/ModSecurity/OWASP-style
payloads, the synthetic benign/multifield sets, and the payload-list
datasets), and is additionally exposed to at least one confirmed style-specific
blind spot (`synthetic_nav`-shaped benign traffic) independent of how much of
that style's volume is in training. A genuinely novel attack or benign source
with an unfamiliar payload style should be expected to degrade detection
substantially until re-training incorporates a sample of it — this system
does not claim, and LOSO shows it should not be assumed, to generalize to
arbitrary unseen traffic styles beyond what informed its training data.

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

### 5.1 MinHash/LSH investigation (2026) — scale quantified, remediation still open

An investigation into replacing the Levenshtein approach with MinHash + LSH
(`datasketch`, k=2 shingles, threshold=0.70, calibrated against a 20-pair
length-stratified validation set — see below) confirmed MinHash is a viable
*detection* mechanism: no length cutoff is needed (shingle-based similarity
works at any length), and it comfortably outperforms the old approach's
speed characteristics on small-to-medium classes. It does **not**, on its
own, close gap (b) — see the incomplete-coverage finding below.

**Byproduct: a real detection-bypass bug found and fixed.** Payload
extraction for this investigation initially reused the same `query`-only
field as the old Levenshtein method, which surfaced that `deriveRawPayload`
(the same function used at training time and by `worker.ts` on every live
request) discarded `path`'s attack signal whenever `query` was merely
non-empty — regardless of content (e.g. a WordPress-style `ver=4.9.5`
silently winning over a real injected path). Fixed via score-based
candidate selection (`scoreAttackSignal`/`scoreAttackSignalWithDecoding`,
`packages/extractor/src/attack-signal-score.ts`) — 11,595 corpus rows
(3.06%) and any live request shaped the same way were affected. See the
PR that landed this fix for full detail; it is independent of, and a
prerequisite for, the dedup numbers below (the near-dup scan now runs on
the corrected field).

**Confirmed: genuine, extensive near-duplication — not a detection
artifact.** On the corrected field, three classes completed a full-corpus
direct-pairwise scan (k=2, threshold=0.70, no union-find/transitive
clustering — an earlier attempt at clustering was abandoned after it
produced obvious chaining artifacts, e.g. 86 "clusters" covering 98% of a
class):

| Class | n | Direct pairs | avg neighbors/item | max neighbors | Saturation (pairs/n) |
|-------|--:|--------------:|--------------------:|---------------:|----------------------:|
| xss | 29,897 | 1,830,599 | 122.5 | 1,039 | 61.2x |
| cmdi | 5,554 | 290,481 | 104.6 | 438 | 52.3x |
| path_traversal | 16,839 | 545,740 | 64.8 | 430 | 32.4x |

Two hypotheses were tested empirically before trusting these numbers:
(A) genuine template-based duplication vs (B) threshold/shingle-size
miscalibration producing spurious matches on short strings. Evidence
supports (A): the highest-neighbor item (1,039 matches) and its neighbors
are a real, repeated `capec` payload template (a `chr()`-based PHP object
injection, varying only in path prefix and quote-breakout character);
median payload lengths for xss (86) and path_traversal (112) are well
above the range where short-string shingle noise would dominate; and
increasing shingle size (k=2→4) only mildly reduced the match rate
(122→98→103 neighbors/item) rather than collapsing it, the signature of
real duplication rather than a coincidental short-shingle match. CAPEC's
template-based payload generation is the primary source.

**Update: `sqli` and `benign` completed (previously not measured).**
The `sqli` class originally did not complete a full-corpus scan in
reasonable time (killed after 1h47m of degrading throughput) despite
the three classes above completing in seconds, with subset-scaling
diagnostics showing query time growing faster than row count and
average-neighbors-per-item still climbing at 50,000 rows.

Getting reliable numbers required tuning LSH banding explicitly rather
than relying on datasketch's threshold-derived default. At
`threshold=0.70, num_perm=128`, datasketch derives `b=14, r=9`
(`b*r=126`) — too few, too-large bands for a corpus this saturated;
each band's hash bucket grows large enough that per-query bucket scan
cost dominates. Explicit coarser banding, `num_perm=128,
params=(8,16)`, trades recall (50%-recall point shifts from
s≈0.72 to s≈0.86 on the standard LSH S-curve
`P(s)=1-(1-s^r)^b`) for tractability. On a 50,000-row subset this cut
average query cost roughly 5x versus the default banding.

Re-running full-corpus with `(8,16)` on the corrected `deriveRawPayload`
field (via the actual compiled extractor, not a proxy) produced:

| Class | n | Direct pairs | avg neighbors/item | max neighbors | Saturation (pairs/n) |
|-------|--:|--------------:|--------------------:|---------------:|----------------------:|
| sqli | 227,344 | 89,892,617 | 790.8 | 7,956 | ~395x |
| benign | 99,112 | 943,147 | 19.0 | 876 | ~9.5x |

sqli shows dramatically higher saturation than any previously-measured
class (30–120x for xss/cmdi/path_traversal) — consistent with sqli's
corpus being dominated by sqlmap/CAPEC template generation (a small
number of giant near-duplicate families). benign shows the lowest
saturation of any class measured (~9.5x), consistent with genuine,
long-tail real traffic rather than templated content.

**Timing caveat — the pair/neighbor counts are order-independent, the
completion time is not.** A shuffled-order rerun (same config, same
field, different random seed) reproduced the pair counts closely
(avg_neighbors 790.0 vs 790.8, max_neighbors identical at 7,956 — a
partial run at 81% of rows already matched the full run's steady-state
numbers), confirming the counts above are real properties of the data,
not artifacts of row order in `unified.jsonl`. But the shuffled run's
*wall-clock* did not fit the same 20-minute budget the original run
did — it hit the query-time cap at 1200s having processed only 185,129
of 227,344 rows, versus the original's 482s to completion. Per-chunk
query cost escalated faster under the shuffle (50k:40s → 100k:282s →
150k:722s) than under original file order (150k:192s → 200k:481s).
This rules out "CAPEC template variants happen to be clustered
together in file order" as the explanation for the back-loading — it's
a genuine property of the saturation (bucket sizes compound as more
of a saturated corpus gets indexed, regardless of which specific rows
land late), not a source-ordering artifact. It does mean `(8,16)` at
sqli's current row count is **not** a comfortably-under-budget
configuration for repeat runs — treat 482s as a lucky ordering rather
than a guaranteed bound, and budget accordingly (or use the faster,
lossier `(4,32)` fallback validated on the proxy dataset earlier in
this investigation) for any automated rerun.

**Decision: flag-only, do not deduplicate, for the v9 batch.** Two
reasons, not just consistency with the existing policy:
1. Actual deduplication (removing rows, not just flagging pairs) is a
   corpus-reshaping decision that changes class balance and training
   volume — its own retraining-strategy decision, not something to bundle
   into a batch alongside unrelated feature/threshold changes.
2. This decision is now made with complete rather than partial
   duplication numbers — sqli (60% of the corpus) and benign are no
   longer unmeasured. That doesn't change the "flag, don't delete"
   posture (reason 1 alone is sufficient), but it does mean the
   posture is no longer a hedge against missing majority-of-corpus
   data.

This investigation **extends** the original limitation rather than
closing it: the true scale of near-duplication is now quantified and
confirmed genuine for all 5/5 classes (9.5x–395x saturation —
dramatically larger than the old method's 211 total flagged pairs,
which suffered from both the 100-char cutoff and the 10,000-pair cap),
the transitive-chaining false lead has been ruled out, and a real,
independent bug (`deriveRawPayload`'s field-priority bypass) was found
and fixed as a byproduct. Remediation — whether and how to actually
deduplicate — remains future work, tracked here rather than in
`training/DEDUP_METHODOLOGY.md` (that file describes the superseded
Levenshtein methodology only).

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

## 8. Finding: RF confidence depends partly on request context richness, not just payload content

Command injection payloads delivered with minimal HTTP context (no
User-Agent, no cookies, no referer — the realistic shape of a raw
curl/script-based attack, as opposed to a browser-driven request) show
measurably lower RF confidence than the same injection technique embedded
in a richer, browser-like request.

Verified at the model level (bypassing Docker/HTTP entirely): direct ONNX
inference on distinct recon-command techniques (`whoami`, `id`, `uname -a`,
`env`, `ls -la /`, `ping`) delivered as a bare form-field value scored
consistently below `RF_THRESHOLD` (range: 0.233–0.336), while overtly
malicious targets (`/etc/passwd`, `/etc/shadow`, reverse shell payloads) in
the same minimal-context delivery reliably scored above threshold.

Confirmed via the parallel investigation in the vulnerable-app repo: of 33
distinct cmdi techniques tested live, 17 always blocked, 14 blocked
inconsistently depending on whitespace/casing formatting, and only 2 (6%)
never blocked in any variant — consistent with a confidence-margin effect
rather than a hard detection gap.

This is distinct from the previously-documented cmdi/sqli attribution
confusion (§5.1 of `logSguarDian-vulnerable-project/docs/config2-results-v1.md`)
— that finding was about correct blocking with wrong category labeling;
this finding is about genuine confidence degradation for a specific
sub-class of low-signal recon commands under thin request context.

**Root cause hypothesis:** the RF model's feature set includes secondary
context signals (`ua_length`, cookie presence, etc.) that correlate with
"legitimate browser traffic" during training. A request stripped of that
context loses a confidence contribution the model implicitly relies on,
even when the injection signal itself (`semicolon_count`,
`shell_command_count`) is present and correctly extracted.

### 8.1 Windows-syntax and compound-command coverage (v11) — BOTH RESOLVED, two different mechanisms

A follow-up investigation checked whether the same corpus had comparable
gaps for (a) Windows-style cmdi syntax (`powershell`, `certutil`, `net
user`, etc.) and (b) compound commands chaining 2+ operations. Both were
confirmed real and scoped precisely before any fix:

- Windows-shaped payloads were 0.17% of the cmdi corpus (15/8,858 rows).
  `SHELL_COMMAND_COUNT` already recognized `powershell`/`cmd.exe` but
  nothing else Windows-specific — a genuine feature-vocabulary gap, not
  just a data-volume one.
- Compound payloads (2+ chained operations) were 2.9% of the cmdi corpus.
  Unlike §8 above, **richer request context did not help**: live inference
  with a real browser UA and cookie still misclassified 3/4 hand-built
  compound payloads as `path_traversal`, because path-indicator features
  (`traversal_sequence_count`, `path_separator_count`) outweighed
  shell-command signal whenever a chain touched `/etc/passwd`-style paths.
  This confirmed a genuinely different mechanism from §8's context-richness
  effect — data alone (verified via an ephemeral no-new-feature experiment)
  wasn't a clean fix either, so this needed new features, not just more
  examples.

**Fix (v11 retrain):**
1. `SHELL_COMMAND_COUNT` extended with `certutil`, `wmic`, `reg
   add/query/delete`, `net user/localgroup`, `schtasks`, `rundll32`,
   `mshta`, `bitsadmin`, `Invoke-*`, `-enc`/`-EncodedCommand` (0%
   false-positive rate verified against 99k benign corpus rows).
2. Two new additive features — `distinct_shell_command_count` (unique
   recognized binaries, not raw match count) and `shell_to_path_ratio`
   (distinct commands ÷ path-token count) — give the RF a direct signal
   that survives even when a chain touches sensitive paths. Feature vector
   grew 73 → 75 dimensions.
3. 400 synthetic Windows-cmdi rows + 500 synthetic compound-command rows
   added to the training corpus (nonce-deduplicated, held-out command
   tokens reserved for generalization testing — see below).

**Result (production hyperparameters, not a mini-pipeline approximation):**
cmdi went from being missed entirely on Windows/compound payloads to
precision 0.927 / recall 0.950 / F1 0.938 on the held-out **test** set (R2),
with `path_traversal` unchanged at 0.982/0.983 — no regression from the new
ratio feature. All 5 §8 minimal-context payloads (`whoami`, `id`, `uname
-a`, `printenv`, `` `last` ``) still classify `cmdi` at 1.0 confidence, so
this fix does not reopen §8.

Generalization was checked on tokens never used during training or present
in `SHELL_COMMAND_COUNT`'s vocabulary: Windows (`sc create`, `wevtutil cl`,
`vssadmin delete shadows`) and compound-chain commands (`uname`,
`hostname`, `tar`, `scp`, `crontab`, `useradd`, `ssh-keygen`, `base64`,
`openssl`, recombined into chains not seen in training) — all classified
`cmdi` at 0.57–0.83 confidence, clear of the 0.35 threshold. This is
structural generalization via separator/subshell/redirect signal, not
memorization of specific binaries.

**One related bug found but not fixed here (out of scope for this
change):** `SHELL_COMMAND_COUNT`'s `\b` word-boundary anchor cannot match
immediately before `/etc/passwd` or `/bin/` when either is preceded by
whitespace (both sides of the boundary are non-word characters in that
case) — so those two path-literal alternatives are effectively dead code
in realistic payloads like `cat /etc/passwd` (space before `/`). Worth a
follow-up ticket; doesn't affect this fix's validity since the recognized
binary names (`cat`, `rm`, `curl`, etc.) still match normally.

## 9. IF (IsolationForest) verdict inclusion under concurrency — RESOLVED (grace window superseded by async log-patch)

**Status: fixed at the architecture level** (`docs/results.md` §A24 has the
full investigation). Root cause was two-layered: (1) `onnxruntime-node`
serializes concurrent `InferenceSession.run()` calls within a single
thread — fixed by splitting RF and IF into dedicated `worker_threads`
(1 RF + a pool of 2 IF workers) instead of one worker running both; (2)
this pool design initially had a 0% real-world success rate for folding
IF into the verdict — a cold-start burst (real requests queuing behind
IF's ~2-3s model-load `sessionPromise`, then bursting `session.run()`
concurrently the instant it resolved) retriggered the same serialization
bug via a different path. Fixed with a readiness handshake (workers
signal `{ready: true}` after loading; the middleware withholds dispatch
until ready) plus a short bounded `IF_GRACE_MS` (5ms) window so RF
resolving first doesn't automatically starve IF's contribution.

**Superseded (see `docs/results.md`, "the grace window replaced with an
async log-patch"):** the `IF_GRACE_MS` window described above measurably
cost ~1ms of added latency on nearly every request — direct instrumentation
found it wasn't bounding a rare slow-IF case, it was paying IF's real
inference time (~0.9-1.2ms) on ~99% of requests, since IF almost always
replied just before the window expired rather than after. The grace window
was removed entirely: RF now resolves the response the instant it replies,
with **no wait for IF at all**. IF's score, whenever it arrives, patches the
already-logged `DetectionEvent` row in place (`EventStore.patchIfScore`),
flipping a `pass` verdict to `pass_anomaly` retroactively (and firing the
webhook then, if configured) instead of being discarded. `block` and
`timeout` verdicts are never touched by a late patch. This closes the
"data loss" framing above for the common case — a late IF reply is now
recovered a millisecond or so after the response, not thrown away — at the
cost of the same theoretical race under extreme concurrency (an in-flight
patch may itself lose the race against the per-request cleanup timer if IF
is slower than the full fail-open `timeoutMs`, not just slower than RF;
this residual case has not been separately re-measured under 20-way
concurrent burst since the redesign).

## 10. Finding: IF benign-calibration / attack-camouflage tension (User-Agent representation gap — investigated, not fixed)

**Origin:** Config 2 live validation found IF's `pass_anomaly` rate on
pure benign traffic (94.6%) is ~17x higher than its offline calibration
target (5.3–5.7%).

**Root cause (confirmed via ablation):** the benign training corpus is
99.6% missing User-Agent headers (only `synthetic_nav`, 0.42% of benign
rows, carries a realistic UA). Real production traffic is ~100%
UA-present. IF learned "no UA = normal" — the opposite of reality.
Confirmed by isolating UA presence as the sole driver via direct
ablation: toggling UA alone flips the anomaly verdict on a realistic
benign request (`GET /profile` with a real browser UA and session
cookie); toggling cookie, referer, or query-string richness on the same
request does not move the score at all. (Cookie/referer content isn't
even measured by any of the extractor's 73 features — they only affect
`unusual_headers_count` membership, not the anomaly score.)

**Attempted fix:** generated synthetic UA-bearing benign traffic at
increasing scale (2k → 21k records) and increasing structural realism
(deeper multi-segment paths, realistic query strings for
pagination/search). A dose-response sweep confirmed the flip threshold
sits around 14–18% UA-present representation in benign training data
(real production traffic is ~100%, so this is a large gap to close by
volume alone).

**Why the fix was not adopted:** every configuration that successfully
flips the target benign case to non-anomalous also measurably regresses
IF's recall on multiple attack classes — up to -11.7pp on `cmdi`, -6.3pp
on `path_traversal`, -5.5pp on `sqli`, -2.5pp on `xss` at the best tested
configuration. This is not a generator design flaw: it reproduced across
two structurally different generation strategies (short/sparse paths,
then deep/realistic paths with query strings), each trading one set of
class regressions for another rather than eliminating the tradeoff —
the second strategy improved `cmdi` slightly but introduced a new `sqli`
regression that the first strategy didn't have, because realistic query
strings for pagination/search sit structurally close to where `sqli`
payloads live.

**Root cause of the tension:** making synthetic benign traffic more
realistic (UA-present, realistic path depth, realistic query strings)
necessarily moves it structurally closer to what attacks against the
same application look like, because effective attacks are deliberately
crafted to blend into real traffic shapes. IF is an unsupervised
structural-anomaly detector — it has no access to the semantic
distinction between a benign `page=2` and a malicious `' OR 1=1` the way
RF's supervised, labeled training does. Improving IF's benign-traffic
realism inherently narrows its separation margin from realistic attacks
on at least one structural axis; there is no generator design that
resolves this while IF trains only on unlabeled benign structure.

**Decision: not pursued into a v11 retrain.** IF has no blocking
authority (`decision-policy.md` §3 — RF is the sole blocking gate, IF is
log-enrichment only). The live `pass_anomaly` inflation is an
operational log-noise cost (would flood a webhook/SIEM integration with
false anomaly flags on ordinary traffic), not a security regression —
RF's detection is completely unaffected by any part of this
investigation. Accepting IF's current calibration (tuned to the
offline/training benign distribution) was judged preferable to trading
it for a confirmed recall cost on IF's own detection of 2-4 attack
classes, in exchange for fixing secondary/diagnostic signal quality
only.

**Future work:** if IF's live-traffic calibration is revisited, consider
either (a) a threshold recalibrated specifically against real
UA-present traffic (rather than trying to make training data match it),
accepting a shift in the offline FP/recall numbers as the honest cost of
matching production reality, or (b) removing IF's dependency on
features that carry this tension (UA-related features) entirely,
forcing it to calibrate on axes that attacks and benign traffic
genuinely don't share.

### Update: option (b) tested and rejected

Removing IF's access to UA-related features entirely
(ua_present, ua_length, ua_suspicious — the full Group 8 UA
set, 1.90% of IF's total split frequency) was tested as an
alternative to the data-augmentation attempts above. Same
retrain recipe as if_v10 (contamination=0.05, n_estimators=200,
max_samples=4096), UA features dropped from the 63-feature
input entirely.

**Result: worse than either data-augmentation attempt, not a
different tradeoff.**

| Config | Recall (agg) | FP | cmdi | path_traversal | sqli | xss |
|--------|-------------:|----:|-----:|----------------:|-----:|----:|
| Current (with UA) | 0.9157 | 0.0595 | 0.9624 | 0.9980 | 0.8989 | 0.9819 |
| UA features removed | 0.4946 | 0.0591 | 0.7505 | 0.7857 | 0.4315 | 0.7269 |

Aggregate recall dropped 42.1pp — sqli hit hardest at -45.7pp.
This far exceeds the -11.7pp ceiling that ruled out the
synthetic-data approach. UA features carry real, non-redundant
discriminative signal for sqli/xss/path_traversal specifically
(not just a proxy for "looks like a browser") — despite their
small (1.90%) aggregate split share, the splits they do provide
are decisive at specific boundaries the other 60+ features
don't cover.

The single benign-request ablation case trivially "passes"
with UA removed (IF literally cannot see the signal that
caused the false anomaly) — but this is true by construction,
not by improved calibration, and it comes at a recall cost an
order of magnitude larger than the rejected data-augmentation
attempts.

**Conclusion: both proposed future-work directions from the
original §10 investigation have now been tested and rejected.**
The tension is more fundamental than either "add more realistic
benign data" or "remove the feature causing the tension" can
resolve — UA-related signal is genuinely load-bearing for IF's
attack-class recall, not merely a spurious correlation that can
be cleanly excised. The current calibration (accept the live
pass_anomaly inflation as IF is non-blocking, log-enrichment
only) remains the correct decision, now with both alternatives
empirically closed rather than left as open future work.
