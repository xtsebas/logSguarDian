# Deduplication Methodology — logSguarDian Training Pipeline

**Audit date:** 2026-06-21  
**Script:** `training/unify.py`  
**Status:** Both deduplication stages confirmed active in the pipeline that produced `unified.jsonl` → `train.parquet` → `rf_v2.pkl`.

---

## Stage 1 — Exact Hash Deduplication

**Implementation:** `deduplicate_exact()` — `unify.py:83–98`

**Key:** `sha256(path + "|" + query + "|" + body + "|" + label)` — all four fields included so that attacks carried in path or body (e.g. path-traversal with empty query) are not collapsed into a single record.

**Effect:** Removes records where all four fields are byte-for-byte identical. Runs first; output feeds Stage 2.

---

## Stage 2 — Near-Duplicate Detection

**Implementation:** `levenshtein()` + `find_near_duplicates()` — `unify.py:31–137`

**Method:** Levenshtein edit distance on the `query` field only, within same-label buckets.

**Threshold:** Distance < 3 (pairs where queries differ by 0, 1, or 2 character edits).

**Scope restriction:**
- Only queries of 1–100 characters are compared (longer queries skipped for speed).
- Capped at 10,000 comparisons per label bucket (`max_pairs`).
- Queries are truncated at 200 chars before comparison.

**Effect: REPORT ONLY — near-duplicates are NOT removed from `unified.jsonl`.**  
This is an explicit design decision in the script docstring. The 211 flagged pairs remain in the training data.

**Output:** `training/data_clean/near_duplicates_report.txt` — last generated Jun 14 2026.

**Result from most recent run:**
- Total near-duplicate pairs flagged: **211**
- All from `capec` source
- `dist=0` pairs (identical queries, distinct path/body): majority of flagged pairs  
  — these pass exact dedup because `path` or `body` differs; they are structurally distinct HTTP records sharing the same query payload
- Labels affected: `cmdi`, `path_traversal`

---

## Why 211 dist=0 Pairs Are Not Exact Duplicates

The exact hash fingerprint is `hash(path|query|body|label)`. Two records with the same `query` but different `path` produce different fingerprints. The near-dup scan finds them because Levenshtein on `query` alone = 0. These represent the same attack payload appearing in different HTTP paths (e.g. the same CAPEC pattern replayed against multiple endpoints). Treating them as near-duplicates is conservative; treating them as distinct training samples is defensible (different request context).

---

## Coverage Gaps

The near-dup scan has two distinct, independent gaps. The 213,879 rows (53.5%) with empty `query` fields are **not** a gap — those records carry attack signal in `path` or `body`, and comparing an empty string via Levenshtein would produce noise, not signal. They are correctly out of scope.

### Gap (a) — 100-character query cutoff

**Justification status: none.** The sole rationale in the source code is the comment `# Sample: only compare short queries (likely duplicates)` (`unify.py:118`). No performance analysis, no empirical observation, and no documented design decision supports this threshold. It is an unjustified assumption.

82,262 rows (20.6% of the full dataset) had non-empty queries exceeding 100 characters and were excluded from Levenshtein comparison entirely:

| Label | Total | Query > 100 chars | % of class excluded |
|---|---|---|---|
| sqli | 227,224 | 24,421 | 10.7% |
| xss | 29,757 | 4,509 | 15.2% |
| path_traversal | 16,839 | 352 | 2.1% |
| cmdi | 5,544 | 377 | 6.8% |
| benign | 120,278 | 52,603 | 43.7% |
| **Total** | **399,642** | **82,262** | **20.6%** |

Long encoded payloads — URL-encoded SQLi chains, multi-parameter XSS strings — are disproportionately represented in the excluded segment. Any near-duplicates within that segment were not flagged.

### Gap (b) — max_pairs=10,000 cap within the scanned window

Even for the 103,501 rows that passed the length filter, the scan is capped at 10,000 comparisons per label bucket (`unify.py:103`). For sqli, the 44,208 scanned items imply ~976M possible pairs; only 10,000 were evaluated — under 0.002% coverage. This is arguably the more significant gap: it means the "scanned" segment provides no statistical confidence that near-duplicates within it were detected, for any class with more than a few hundred items.

**Conclusion:** Near-duplicate detection as implemented is a best-effort partial scan with two unjustified scope restrictions. It should not be read as a clean bill of health for the dataset. This is acknowledged as a methodological limitation (see `docs/limitations.md §5`).

---

## Relation to PLAN.md 2.4

PLAN.md 2.4 required both exact-hash dedup AND near-duplicate detection (Levenshtein-based). Both are implemented and ran on the data that produced `rf_v2.pkl`. Near-dup detection produced a flagging report; removal was not performed (by design). The 211 flagged pairs remaining in training data constitute a minor residual overlap concentrated in the `capec` source for `cmdi` and `path_traversal` classes.
