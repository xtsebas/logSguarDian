"""
Parser for data/payload_full.csv → training/data_clean/payload_full.jsonl

Columns: payload (string), length (int), attack_type (norm/sqli/xss/path-traversal/cmdi), label (norm/anom)
Only attack_type column is used for label mapping.
"""

import csv
import json
import yaml
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
INPUT = ROOT / "data" / "payload_full.csv"
OUTPUT = ROOT / "training" / "data_clean" / "payload_full.jsonl"

with open(ROOT / "training" / "label_map.yaml") as _f:
    LABEL_MAP: dict[str, str] = yaml.safe_load(_f)["mappings"]["payload_full"]


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    skipped = 0

    with (
        open(INPUT, encoding="utf-8", errors="replace", newline="") as fin,
        open(OUTPUT, "w", encoding="utf-8") as fout,
    ):
        reader = csv.DictReader(fin)
        for row in reader:
            raw_type = (row.get("attack_type") or "").strip().lower()
            label = LABEL_MAP.get(raw_type)
            if label is None:
                skipped += 1
                continue

            payload = (row.get("payload") or "").strip()
            if not payload:
                skipped += 1
                continue

            record = {
                "method":       "",
                "path":         "",
                "query":        payload,
                "body":         None,
                "userAgent":    "",
                "contentType":  "",
                "referer":      "",
                "cookie":       "",
                "extraHeaders": {},
                "label":        label,
            }
            fout.write(json.dumps(record, ensure_ascii=False) + "\n")
            counts[label] = counts.get(label, 0) + 1

    total_written = sum(counts.values())
    print(f"payload_full.jsonl written to {OUTPUT}")
    print(f"  Written : {total_written:,}  |  Skipped: {skipped}")
    print("  Class distribution:")
    for label in ["sqli", "xss", "path_traversal", "cmdi", "benign"]:
        print(f"    {label:15s}: {counts.get(label, 0):,}")


if __name__ == "__main__":
    main()
