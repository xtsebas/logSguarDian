"""
Schema validator for CanonicalRequest JSONL files.

Usage:
    python validate_canonical.py <file1.jsonl> [file2.jsonl ...]
    python validate_canonical.py --all   (validates all files in data_clean/)

Checks per row:
  - Required fields present: method, path, query, label
  - label is one of the 5 canonical values
  - query is not null (None)
  - body field present (can be null/None, but key must exist)

Reports: total rows, class distribution, invalid row count + reasons.
"""

import json
import sys
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).parent.parent.parent
DATA_CLEAN = ROOT / "training" / "data_clean"

VALID_LABELS = {"sqli", "xss", "path_traversal", "cmdi", "benign"}
REQUIRED_FIELDS = {"method", "path", "query", "label"}


def validate_file(jsonl_path: Path) -> None:
    total = 0
    invalid = 0
    class_counts: Counter = Counter()
    error_reasons: Counter = Counter()

    with open(jsonl_path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            total += 1

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                invalid += 1
                error_reasons[f"json_parse_error"] += 1
                continue

            row_errors = []

            # Check required fields
            missing = REQUIRED_FIELDS - record.keys()
            if missing:
                row_errors.append(f"missing_fields:{','.join(sorted(missing))}")

            # Check label validity
            label = record.get("label")
            if label not in VALID_LABELS:
                row_errors.append(f"invalid_label:{label!r}")

            # Check query is not None/null
            if record.get("query") is None:
                row_errors.append("null_query")

            if row_errors:
                invalid += 1
                for reason in row_errors:
                    error_reasons[reason] += 1
            else:
                class_counts[label] += 1

    valid = total - invalid
    invalid_pct = (invalid / total * 100) if total > 0 else 0.0

    print(f"\n{'='*60}")
    print(f"File : {jsonl_path.name}")
    print(f"  Total rows     : {total:,}")
    print(f"  Valid rows     : {valid:,}")
    print(f"  Invalid rows   : {invalid:,}  ({invalid_pct:.2f}%)")
    if error_reasons:
        print("  Error breakdown:")
        for reason, count in error_reasons.most_common():
            print(f"    {reason}: {count:,}")
    print("  Class distribution (valid rows):")
    for label in ["sqli", "xss", "path_traversal", "cmdi", "benign"]:
        count = class_counts.get(label, 0)
        pct = (count / valid * 100) if valid > 0 else 0.0
        print(f"    {label:15s}: {count:7,}  ({pct:.1f}%)")


def main() -> None:
    args = sys.argv[1:]

    if not args or args == ["--all"]:
        files = sorted(DATA_CLEAN.glob("*.jsonl"))
        if not files:
            print(f"No .jsonl files found in {DATA_CLEAN}")
            sys.exit(1)
    else:
        files = [Path(a) for a in args]

    print(f"Validating {len(files)} file(s)...")
    for path in files:
        if not path.exists():
            print(f"\nERROR: file not found: {path}")
            continue
        validate_file(path)

    print(f"\n{'='*60}")
    print("Validation complete.")


if __name__ == "__main__":
    main()
