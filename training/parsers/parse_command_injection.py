"""
Parser for data/command injection.csv → training/data_clean/command_injection.jsonl

Columns: sentence (payload string, HTML-entity encoded), Label (0=benign, 1=cmdi)
Payloads are raw strings, not full HTTP requests.
HTML entities decoded before output.
"""

import csv
import html
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
INPUT = ROOT / "data" / "command injection.csv"
OUTPUT = ROOT / "training" / "data_clean" / "command_injection.jsonl"

LABEL_MAP = {"0": "benign", "1": "cmdi"}


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
            label = LABEL_MAP.get(str(raw_label))
            if label is None:
                skipped += 1
                continue

            sentence = (row.get("sentence") or "").strip()
            if not sentence:
                skipped += 1
                continue

            # Decode HTML entities (&lt; → <, &quot; → ", etc.)
            decoded = html.unescape(sentence)

            record = {
                "method":       "",
                "path":         "",
                "query":        decoded,
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
    print(f"command_injection.jsonl written to {OUTPUT}")
    print(f"  Written : {total_written:,}  |  Skipped: {skipped}")
    print("  Class distribution:")
    for label in ["cmdi", "benign"]:
        print(f"    {label:15s}: {counts.get(label, 0):,}")


if __name__ == "__main__":
    main()
