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
