"""
Parser for SecLists' Fuzzing/command-injection-commix.txt ->
training/data_clean/seclists_cmdi.jsonl

Source: https://github.com/danielmiessler/SecLists
        Fuzzing/command-injection-commix.txt (Commix's own generated
        fuzzing payload set: shell separators x quote-contexts x blind
        detection templates, each instantiated with a random 6-letter
        canary and random arithmetic operands).

Raw file is one payload per line, already percent-encoded, 8,262 lines.
Payloads are field-agnostic strings (no key=value structure of their
own) - same placement convention as command_injection.jsonl: the whole
payload goes into `query`, method/path empty, body null.

Deduplication: the raw file instantiates each structural template with
a fresh random canary (6 uppercase letters) and random arithmetic
operands for every line, so most of the 8,262 lines are canary/number
reshuffles of the same ~2,455 underlying templates (verified during the
investigation this parser follows). Keeping only one representative per
template avoids reintroducing the near-duplication problem already
found in capec - see docs/limitations.md §5.
"""

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent.parent
INPUT = ROOT / "data" / "seclists_command-injection-commix.txt"
OUTPUT = ROOT / "training" / "data_clean" / "seclists_cmdi.jsonl"

with open(ROOT / "training" / "label_map.yaml") as _f:
    _LABEL_MAP = yaml.safe_load(_f)["mappings"]
LABEL = _LABEL_MAP["seclists_cmdi"]["cmdi"]

# 6 consecutive uppercase letters = the random canary; runs of digits =
# random arithmetic operands. Both are stripped to detect the underlying
# structural template.
_CANARY_RE = re.compile(r"[A-Z]{6}")
_DIGIT_RE = re.compile(r"\d+")


def template_shape(line: str) -> str:
    shape = _CANARY_RE.sub("CANARY", line)
    shape = _DIGIT_RE.sub("N", shape)
    return shape


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    seen_shapes: set[str] = set()
    written = 0
    skipped_blank = 0
    skipped_duplicate_template = 0

    with open(INPUT, encoding="utf-8", errors="replace") as fin, \
         open(OUTPUT, "w", encoding="utf-8") as fout:
        for raw_line in fin:
            line = raw_line.strip()
            if not line:
                skipped_blank += 1
                continue

            shape = template_shape(line)
            if shape in seen_shapes:
                skipped_duplicate_template += 1
                continue
            seen_shapes.add(shape)

            record = {
                "method": "",
                "path": "",
                "query": line,
                "body": None,
                "userAgent": "",
                "contentType": "",
                "referer": "",
                "cookie": "",
                "extraHeaders": {},
                "label": LABEL,
                "_source": "seclists_cmdi",
            }
            fout.write(json.dumps(record, ensure_ascii=False) + "\n")
            written += 1

    print(f"seclists_cmdi.jsonl written to {OUTPUT}")
    print(f"  Written (unique templates): {written:,}")
    print(f"  Skipped (duplicate template): {skipped_duplicate_template:,}")
    print(f"  Skipped (blank line): {skipped_blank:,}")


if __name__ == "__main__":
    main()
