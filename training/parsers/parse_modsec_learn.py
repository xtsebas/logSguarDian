"""
Parser for data/modsec-learn/*.json → training/data_clean/modsec_learn.jsonl

Both files are JSON arrays of URL-encoded query strings (flat strings, no HTTP structure).
  legitimate_dataset.json → benign
  malicious_dataset.json  → sqli (all malicious records are SQLi payloads)
"""

import json
import yaml
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
LEGIT_FILE = ROOT / "data" / "modsec-learn" / "legitimate_dataset.json"
MAL_FILE = ROOT / "data" / "modsec-learn" / "malicious_dataset.json"
OUTPUT = ROOT / "training" / "data_clean" / "modsec_learn.jsonl"

with open(ROOT / "training" / "label_map.yaml") as _f:
    _modsec_labels: dict[str, str] = yaml.safe_load(_f)["mappings"]["modsec_learn"]


def emit_records(fout, path: Path, label: str) -> int:
    with open(path, encoding="utf-8", errors="replace") as f:
        records = json.load(f)
    count = 0
    for item in records:
        query = str(item).strip() if item else ""
        if not query:
            continue
        record = {
            # ModSecurity logs only capture the query string, not the full
            # request line. A live HTTP client always sends a real method and
            # path (Express reports "GET"/"/" at minimum), so blank defaults
            # here would train the model on a request shape that never
            # actually occurs at inference time.
            "method":       "GET",
            "path":         "/",
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
        benign_count = emit_records(fout, LEGIT_FILE, _modsec_labels["legitimate_dataset"])
        sqli_count = emit_records(fout, MAL_FILE, _modsec_labels["malicious_dataset"])

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
