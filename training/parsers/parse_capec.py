"""
Parser for data_capec_multilabel.csv → training/data_clean/capec.jsonl

Each output line: CanonicalRequest JSON + label.
Label priority (first match wins): sqli > path_traversal > cmdi > xss.
Rows with no target-class label are discarded.
"""

import csv
import json
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).parent.parent.parent
INPUT = ROOT / "data" / "data_capec_multilabel.csv"
OUTPUT = ROOT / "training" / "data_clean" / "capec.jsonl"

LABEL_PRIORITY = [
    ("sqli",           {"66 - SQL Injection"}),
    ("path_traversal", {"126 - Path Traversal"}),
    ("cmdi",           {"88 - OS Command Injection", "248 - Command Injection"}),
    ("xss",            {"242 - Code Injection"}),
]


def resolve_label(row: dict) -> str | None:
    for label, cols in LABEL_PRIORITY:
        if any(row.get(col, "0") == "1" for col in cols):
            return label
    return None


def split_request_line(request_line: str) -> tuple[str, str]:
    """Split '/path?query' → (path, query). Returns ('', '') for empty input."""
    if not request_line:
        return "", ""
    if "?" in request_line:
        path, query = request_line.split("?", 1)
    else:
        path, query = request_line, ""
    return path.strip(), query.strip()


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    counts: dict[str, int] = {}
    null_query_count = 0
    discarded = 0
    total_read = 0

    with (
        open(INPUT, encoding="utf-8", errors="replace", newline="") as fin,
        open(OUTPUT, "w", encoding="utf-8") as fout,
    ):
        reader = csv.DictReader(fin)
        for row in reader:
            total_read += 1
            label = resolve_label(row)
            if label is None:
                discarded += 1
                continue

            method = (row.get("request_http_method") or "GET").strip().upper() or "GET"
            path, query = split_request_line(row.get("request_http_request", ""))
            body = row.get("request_body", "").strip() or None

            if query is None:
                null_query_count += 1

            extra: dict[str, str] = {}
            for csv_col, header_name in [
                ("request_accept",          "accept"),
                ("request_host",            "host"),
                ("request_accept_language", "accept-language"),
                ("request_accept_encoding", "accept-encoding"),
                ("request_do_not_track",    "dnt"),
                ("request_connection",      "connection"),
                ("request_origin",          "origin"),
            ]:
                val = row.get(csv_col, "") or ""
                if val:
                    extra[header_name] = val

            record = {
                "method":       method,
                "path":         path,
                "query":        query,
                "body":         body,
                "userAgent":    row.get("request_user_agent", "") or "",
                "contentType":  row.get("request_content_type", "") or "",
                "referer":      row.get("request_referer", "") or "",
                "cookie":       row.get("request_cookie", "") or "",
                "extraHeaders": extra,
                "label":        label,
            }
            fout.write(json.dumps(record, ensure_ascii=False) + "\n")
            counts[label] = counts.get(label, 0) + 1

    total_written = sum(counts.values())
    print(f"capec.jsonl written to {OUTPUT}")
    print(f"  Total rows read    : {total_read:,}")
    print(f"  Discarded (no match): {discarded:,}")
    print(f"  Written            : {total_written:,}")
    print(f"  Null query fields  : {null_query_count}")
    print("  Class distribution:")
    for label in ["sqli", "xss", "path_traversal", "cmdi"]:
        print(f"    {label:15s}: {counts.get(label, 0):,}")


if __name__ == "__main__":
    main()
