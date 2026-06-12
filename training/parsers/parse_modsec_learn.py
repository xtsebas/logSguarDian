"""
Parser for data/modsec-learn/*.json → training/data_clean/modsec_learn.jsonl

Both files are JSON arrays of URL-encoded query strings (flat strings, no HTTP structure).
  legitimate_dataset.json → benign
  malicious_dataset.json  → sqli (all malicious records are SQLi payloads)
"""

import json
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
LEGIT_FILE = ROOT / "data" / "modsec-learn" / "legitimate_dataset.json"
MAL_FILE = ROOT / "data" / "modsec-learn" / "malicious_dataset.json"
OUTPUT = ROOT / "training" / "data_clean" / "modsec_learn.jsonl"


def emit_records(fout, path: Path, label: str) -> int:
    with open(path, encoding="utf-8", errors="replace") as f:
        records = json.load(f)
    count = 0
    for item in records:
        query = str(item).strip() if item else ""
        if not query:
            continue
        record = {
            "method":       "",
            "path":         "",
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
        count += 1
    return count


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as fout:
        benign_count = emit_records(fout, LEGIT_FILE, "benign")
        sqli_count = emit_records(fout, MAL_FILE, "sqli")

    total = benign_count + sqli_count
    print(f"modsec_learn.jsonl written to {OUTPUT}")
    print(f"  Written : {total:,}")
    print("  Class distribution:")
    print(f"    {'sqli':15s}: {sqli_count:,}")
    print(f"    {'benign':15s}: {benign_count:,}")
    print("  NOTE: malicious_dataset has no per-record type labels;")
    print("        all assigned 'sqli' based on payload inspection (UNION SELECT patterns).")


if __name__ == "__main__":
    main()
