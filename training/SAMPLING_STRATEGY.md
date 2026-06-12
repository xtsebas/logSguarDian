# Sampling Strategy
**Date:** 2026-06-10  
**Input:** 974,718 rows across 7 JSONL files (post-deduplication counts approximate until unify.py runs)

---

## 1. Raw Class Distribution Before Sampling

| Class | Raw Count | % of Total |
|-------|-----------|------------|
| benign | 563,689 | 57.8% |
| sqli | 295,770 | 30.3% |
| path_traversal | 69,176 | 7.1% |
| xss | 37,113 | 3.8% |
| cmdi | 8,970 | 0.9% |
| **Total** | **974,718** | 100% |

The distribution is severely skewed. A naive RF trained on raw counts would achieve high accuracy by over-predicting benign and sqli while systematically misclassifying cmdi (0.9% of data — any classifier that predicts "never cmdi" is 99.1% "accurate" on that class alone).

---

## 2. Target Sample Counts for the Training Set

**Goal:** Balanced dataset of ~190,000 training rows.  
**Strategy:** Undersample majority classes → apply SMOTE on cmdi only → use `class_weight='balanced'` as secondary safeguard.

After the 70/15/15 split (`split.py`), the training partition is 70% of unified data. Target counts below are for the **training partition only**.

| Class | Raw in Train (~70%) | Target After Sampling | Ratio |
|-------|--------------------|-----------------------|-------|
| benign | ~394,582 | **38,000** | undersample to 9.6% |
| sqli | ~207,039 | **38,000** | undersample to 9.6% |
| path_traversal | ~48,423 | **38,000** | undersample to 9.6% |
| xss | ~25,979 | **25,979** | keep all (too small to lose any) |
| cmdi | ~6,279 | **25,000** | SMOTE: ~6,279 real + ~18,721 synthetic |
| **Total** | ~682,302 | **~164,979** | — |

**Why these target numbers:**
- 38,000 per class for the three large classes: large enough to learn robust decision boundaries, small enough to keep total training set manageable.
- xss kept whole: 25,979 is already the smallest non-cmdi class after split. Undersampling further would hurt recall on a class that already has limited coverage.
- cmdi target 25,000: puts cmdi close to the other classes (within ~1.5× of xss), reducing the minority-class penalty without over-generating synthetic samples.
- Total ~165k rows: fits comfortably in memory for RF with 200–500 trees on Apple Silicon.

**Sampling is applied to the training partition only.** Validation and test partitions are never resampled — they must reflect the natural class distribution for unbiased metric reporting.

---

## 3. SMOTE Configuration for cmdi

**Why SMOTE on cmdi:** After split, cmdi has ~6,279 training samples. The benign:cmdi ratio is ~63:1 — well above the 10:1 threshold where `class_weight='balanced'` alone becomes insufficient (He & Garcia, 2009). SMOTE generates synthetic minority samples in feature space to reduce this ratio before the RF sees any data.

```python
from imblearn.over_sampling import SMOTE

smote = SMOTE(
    sampling_strategy={"cmdi": 25_000},
    k_neighbors=5,          # default; see justification below
    random_state=42,
)
X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
```

**k_neighbors = 5 (default):** With ~6,279 cmdi samples covering command injection patterns (shell operators, binaries, path indicators), k=5 is appropriate. Using k < 5 risks generating noisy samples from outlier cmdi records; k > 5 over-smooths toward the benign decision boundary. No justification to deviate from the Chawla et al. (2002) default.

**Citation:** Chawla, N. V., Bowyer, K. W., Hall, L. O., & Kegelmeier, W. P. (2002). SMOTE: Synthetic Minority Over-sampling Technique. *Journal of Artificial Intelligence Research, 16*, 321–357.

**Limitation to document in thesis (Section 8.3 — Threats to Validity):**  
SMOTE operates in the 66-dimensional feature space, not on raw text. Synthetic cmdi samples are linear interpolations between real feature vectors. This can produce feature combinations that correspond to no real attack payload — for example, a synthetic vector might have non-zero `shell_command_count` and `sqli_keyword_count` simultaneously, which would be unusual in real traffic. This is acknowledged as a source of potential overfitting to synthetic patterns on the cmdi class. Mitigation: the leave-one-source-out cross-validation in task 3.6 will reveal whether cmdi F1 degrades substantially on held-out sources.

---

## 4. Undersampling Strategy for benign and sqli

**Method:** `RandomUnderSampler` from imbalanced-learn with `random_state=42`.

```python
from imblearn.under_sampling import RandomUnderSampler

rus = RandomUnderSampler(
    sampling_strategy={
        "benign": 38_000,
        "sqli":   38_000,
    },
    random_state=42,
)
X_under, y_under = rus.fit_resample(X_smoted, y_smoted)
```

**Why random undersampling is acceptable here:**

1. **benign (394,582 → 38,000, retaining 9.6%):** The benign class draws from three structurally distinct sources — modsec_learn (query strings, 508k), payloads_csv (full URLs, 28k), payload_full (payload strings, 19k). At 38,000 samples, all three sources remain represented in the random draw. The probability of randomly retaining at least 500 samples from the smallest source (payloads_csv benign ≈ 19,500 in train) at 9.6% retention is effectively 1. Rare sub-patterns (unusual headers, long queries) are present in sufficient volume that random removal does not systematically eliminate them.

2. **sqli (207,039 → 38,000, retaining 18.4%):** The sqli class also draws from multiple sources: capec (250k), modsec_learn (30k), payload_full (10k), owasp (4k). Random undersampling at 18.4% retention preserves structural diversity across sources. The owasp sqli subset (4,063 real HTTP requests — the most structurally rich) will retain ~746 samples on average, which is enough to learn from that sub-distribution.

**path_traversal (48,423 → 38,000, retaining 78.5%):** Minimal loss — only 10,423 samples discarded. Random removal at 78.5% retention is safe.

**Why not cluster-based undersampling (Tomek links / ENN):** Cluster methods are computationally expensive at 400k+ samples and add non-determinism. Given the large margins within majority classes, random undersampling achieves the same effect with a fixed random seed and reproducible results. Reproducibility is a thesis requirement.

---

## 5. `class_weight='balanced'` as Secondary Safeguard

Even after SMOTE + undersampling, use `class_weight='balanced'` in the Random Forest:

```python
from sklearn.ensemble import RandomForestClassifier

rf = RandomForestClassifier(
    class_weight='balanced',
    random_state=42,
    # n_estimators, max_depth tuned in notebook 03_random_forest.ipynb
)
```

**Why both SMOTE and class_weight together (belt-and-suspenders):**

SMOTE adjusts the **data distribution** seen during training. `class_weight='balanced'` adjusts the **impurity criterion** at each tree node (Gini or entropy is weighted by class frequencies). These two mechanisms operate at different levels of the learning algorithm and are not redundant:

- SMOTE ensures the forest sees approximately equal numbers of samples per class, preventing splits that simply ignore minority classes.
- `class_weight='balanced'` further penalizes misclassifying minority samples at the node-splitting level, which matters especially for small classes where SMOTE-generated samples cluster near the real minority boundary and may still be outvoted by majority-class neighbors.

In practice, using both has been shown to outperform either alone on severely imbalanced multi-class problems (Lemaître et al., 2017). The computational overhead of `class_weight='balanced'` is negligible (one multiply per node split).

**Citation:** Lemaître, G., Nogueira, F., & Aridas, C. K. (2017). Imbalanced-learn: A Python toolbox to tackle the curse of imbalanced datasets in machine learning. *Journal of Machine Learning Research, 18*(17), 1–5.

---

## 6. Execution Order Summary

```
split.py           → train/val/test.parquet
                       ↓ (train partition only)
SMOTE on cmdi      → ~6,279 real + ~18,721 synthetic cmdi samples
RandomUnderSampler → benign: 38,000 | sqli: 38,000 | pt: 38,000
                       ↓
Final train set    → ~164,979 rows (xss: ~25,979 | others: ~38,000 | cmdi: 25,000)
                       ↓
RF training        → class_weight='balanced', random_state=42
```

Val and test sets: **never resampled**. Metrics on val/test reflect true class distribution.
