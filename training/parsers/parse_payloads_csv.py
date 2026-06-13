"""
Parser for data/Payloads.csv → training/data_clean/payloads_csv.jsonl

Columns: Payloads (full URL string), Class (Benign / Malicious)
Malicious rows contain XSS payloads embedded in URLs.
Label map: Benign → benign, Malicious → xss
Encoding: latin-1
"""

import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
INPUT = ROOT / "data" / "Payloads.csv"
OUTPUT = ROOT / "training" / "data_clean" / "payloads_csv.jsonl"

LABEL_MAP = {"Benign": "benign", "Malicious": "xss"}


def parse_url(raw: str) -> tuple[str, str, str]:
    """Extract (method, path, query) from a full URL or path string."""
    raw = raw.strip()
    # Remove HTML artifacts injected into the URL strings
    raw = re.sub(r"<br\s*/?>", "", raw, flags=re.IGNORECASE)
    raw = raw.strip()

    # Strip scheme+host if present
    m = re.match(r"https?://[^/]+(/.*)$", raw, re.IGNORECASE)
    path_and_query = m.group(1) if m else raw

    if "?" in path_and_query:
        path, query = path_and_query.split("?", 1)
    else:
        path, query = path_and_query, ""

    return "GET", path.strip(), query.strip()


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    skipped = 0

    with (
        open(INPUT, encoding="latin-1", newline="") as fin,
        open(OUTPUT, "w", encoding="utf-8") as fout,
    ):
        reader = csv.DictReader(fin)
        for row in reader:
            raw_class = (row.get("Class") or "").strip()
            label = LABEL_MAP.get(raw_class)
            if label is None:
                skipped += 1
                continue

            raw_payload = (row.get("Payloads") or "").strip()
            if not raw_payload:
                skipped += 1
                continue

            method, path, query = parse_url(raw_payload)

            record = {
                "method":       method,
                "path":         path,
                "query":        query,
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
    print(f"payloads_csv.jsonl written to {OUTPUT}")
    print(f"  Written : {total_written:,}  |  Skipped: {skipped}")
    print("  Class distribution:")
    for label in ["xss", "benign"]:
        print(f"    {label:15s}: {counts.get(label, 0):,}")


if __name__ == "__main__":
    main()
