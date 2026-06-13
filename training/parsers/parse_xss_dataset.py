"""
Parser for data/XSS_dataset.csv/XSS_dataset.csv → training/data_clean/xss_dataset.jsonl

Columns: Unnamed:0 (index), Sentence (HTML/JS text), Label (0=benign, 1=xss)
These are raw HTML/JS snippets, not HTTP requests.
Mapped to CanonicalRequest with body = Sentence (the content is body-like HTML).
"""

import csv
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
INPUT = ROOT / "data" / "XSS_dataset.csv" / "XSS_dataset.csv"
OUTPUT = ROOT / "training" / "data_clean" / "xss_dataset.jsonl"

LABEL_MAP = {"0": "benign", "1": "xss"}


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
            raw_label = (row.get("Label") or "").strip()
            label = LABEL_MAP.get(raw_label)
            if label is None:
                skipped += 1
                continue

            sentence = (row.get("Sentence") or "").strip()
            if not sentence:
                skipped += 1
                continue

            record = {
                "method":       "",
                "path":         "",
                "query":        "",
                "body":         sentence,
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
    print(f"xss_dataset.jsonl written to {OUTPUT}")
    print(f"  Written : {total_written:,}  |  Skipped: {skipped}")
    print("  Class distribution:")
    for label in ["xss", "benign"]:
        print(f"    {label:15s}: {counts.get(label, 0):,}")


if __name__ == "__main__":
    main()
