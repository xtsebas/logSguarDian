"""
Dataset unification script.

Reads all JSONL files from training/data_clean/
Merges → training/data_clean/unified.jsonl
Deduplication:
  - Exact: hash(query + "|" + label) — removes exact duplicates
  - Near-duplicate: flags pairs where Levenshtein distance < 3 on query field,
    same label — does NOT delete, only reports to near_duplicates_report.txt

Does NOT extract features. Run after TS extractor CLI exists (task 1.7).

Usage:
    python unify.py [--dry-run]
"""

import json
import hashlib
import sys
from pathlib import Path
from collections import Counter, defaultdict

ROOT = Path(__file__).parent.parent
DATA_CLEAN = ROOT / "training" / "data_clean"
OUTPUT = DATA_CLEAN / "unified.jsonl"
NEAR_DUP_REPORT = DATA_CLEAN / "near_duplicates_report.txt"

EXCLUDED = {"unified.jsonl"}  # skip self if already exists

# telemetry_curated_*.jsonl (packages/mlops's `mlops review-clusters`, Fase 4 of
# the CT/CI/CD pipeline) is feature-space (FEATURE_NAMES columns + label +
# _source + _row_hash), not raw-request canonical JSONL — collector telemetry
# never carries raw request text (Fase 1 design: vector-only, for privacy), so
# there is no path/query/body for this script's fingerprint()/dedup logic to
# operate on. Loading it here would silently collapse all curated rows sharing
# a label into one fingerprint (path/query/body all empty for every row). The
# CT orchestrator (training/ct_pipeline.py) merges this file in after the
# extractor CLI step instead, directly at the features.parquet level.
EXCLUDED_PATTERNS = ("telemetry_curated_",)


def levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance between two strings (early-exit per completed row)."""
    if abs(len(a) - len(b)) >= 3:
        return 3
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1,
                            prev[j - 1] + (0 if ca == cb else 1)))
        if min(curr) >= 3:  # row-level early exit: final distance cannot be < 3
            return 3
        prev = curr
    return prev[-1]


def fingerprint(record: dict) -> str:
    # Include path, query, and body so attacks carried in path or body
    # (e.g. owasp path-traversal with query="") are not collapsed into one record.
    key = (
        (record.get("path") or "") + "|"
        + (record.get("query") or "") + "|"
        + (record.get("body") or "") + "|"
        + (record.get("label") or "")
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def load_all_records(data_clean: Path) -> list[tuple[str, dict]]:
    """Load all JSONL files, returning list of (source_name, record)."""
    result = []
    for path in sorted(data_clean.glob("*.jsonl")):
        if path.name in EXCLUDED or path.name.startswith(EXCLUDED_PATTERNS):
            continue
        source = path.stem
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    result.append((source, rec))
                except json.JSONDecodeError:
                    pass
    return result


def deduplicate_exact(
    records: list[tuple[str, dict]]
) -> tuple[list[tuple[str, dict]], dict[str, int]]:
    seen: set[str] = set()
    kept = []
    dup_counts: dict[str, int] = Counter()

    for source, rec in records:
        fp = fingerprint(rec)
        if fp in seen:
            dup_counts[source] += 1
        else:
            seen.add(fp)
            kept.append((source, rec))

    return kept, dup_counts


def find_near_duplicates(
    records: list[tuple[str, dict]],
    max_pairs: int = 10_000,
) -> list[tuple[int, int, int]]:
    """
    Find pairs with Levenshtein(query_i, query_j) < 3 and same label.
    Returns list of (idx_i, idx_j, distance).
    Samples at most max_pairs comparisons per label bucket.
    """
    by_label: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for i, (_, rec) in enumerate(records):
        label = rec.get("label", "")
        query = (rec.get("query") or "")[:200]  # cap at 200 chars for speed
        by_label[label].append((i, query))

    near_dups = []
    for label, items in by_label.items():
        # Sample: only compare short queries (likely duplicates)
        short_items = [(i, q) for i, q in items if 1 <= len(q) <= 100]
        checked = 0
        for a in range(len(short_items)):
            if checked >= max_pairs:
                break
            qi = short_items[a][1]
            for b in range(a + 1, len(short_items)):
                if checked >= max_pairs:
                    break
                qj = short_items[b][1]
                if abs(len(qi) - len(qj)) >= 3:
                    checked += 1
                    continue
                dist = levenshtein(qi, qj)
                checked += 1
                if dist < 3:
                    near_dups.append((short_items[a][0], short_items[b][0], dist))

    return near_dups


def main(dry_run: bool = False) -> None:
    print("Loading all JSONL files...")
    all_records = load_all_records(DATA_CLEAN)
    total_raw = len(all_records)
    print(f"  Total raw records : {total_raw:,}")

    source_counts: Counter = Counter(src for src, _ in all_records)
    print("  Per-source counts:")
    for src, cnt in sorted(source_counts.items()):
        print(f"    {src:30s}: {cnt:,}")

    print("\nDeduplicating (exact)...")
    deduped, dup_counts = deduplicate_exact(all_records)
    total_exact_dups = total_raw - len(deduped)
    print(f"  Exact duplicates removed: {total_exact_dups:,}")
    if dup_counts:
        print("  Duplicates by source:")
        for src, cnt in sorted(dup_counts.items()):
            print(f"    {src:30s}: {cnt:,}")

    label_counts: Counter = Counter(rec.get("label") for _, rec in deduped)
    print(f"\nClass distribution after exact dedup ({len(deduped):,} rows):")
    for label in ["sqli", "xss", "path_traversal", "cmdi", "benign"]:
        cnt = label_counts.get(label, 0)
        pct = cnt / len(deduped) * 100 if deduped else 0
        print(f"  {label:15s}: {cnt:7,}  ({pct:.1f}%)")

    print("\nScanning for near-duplicates (Levenshtein < 3, same label)...")
    near_dups = find_near_duplicates(deduped)
    print(f"  Near-duplicate pairs found: {len(near_dups):,}")
    print(f"  (These are flagged only — not auto-deleted. Review {NEAR_DUP_REPORT.name}.)")

    if not dry_run:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        print(f"\nWriting {OUTPUT.name}...")
        with open(OUTPUT, "w", encoding="utf-8") as fout:
            for source, rec in deduped:
                rec["_source"] = source
                rec["_row_hash"] = fingerprint(rec)
                fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"  Written: {len(deduped):,} rows")

        if near_dups:
            with open(NEAR_DUP_REPORT, "w", encoding="utf-8") as f:
                f.write("Near-duplicate pairs (Levenshtein < 3, same label) — review before training\n")
                f.write(f"Total pairs: {len(near_dups)}\n\n")
                for idx_i, idx_j, dist in near_dups[:500]:
                    src_i, rec_i = deduped[idx_i]
                    src_j, rec_j = deduped[idx_j]
                    f.write(
                        f"dist={dist} label={rec_i.get('label')} "
                        f"src_i={src_i} src_j={src_j}\n"
                        f"  i: {(rec_i.get('query') or '')[:120]}\n"
                        f"  j: {(rec_j.get('query') or '')[:120]}\n\n"
                    )
            print(f"  Near-dup report: {NEAR_DUP_REPORT.name}")
    else:
        print("\n[dry-run] No files written.")

    print("\nDone.")


if __name__ == "__main__":
    dry_run = "--dry-run" in sys.argv
    main(dry_run=dry_run)
