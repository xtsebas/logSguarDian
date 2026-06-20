"""
Parser for data/owasp/*/modsec_audit.anon.log → training/data_clean/owasp_logs.jsonl

ModSecurity audit log format (sections per request):
  --ID-A-- : timestamp + IDs
  --ID-B-- : HTTP request line + headers [+ body if present]
  --ID-F-- : HTTP response status line
  --ID-H-- : ModSecurity messages (rule matches)
  --ID-Z-- : end marker

Label derivation (priority order):
  sqli           ← tag "attack-sqli" or OWASP_CRS/WEB_ATTACK/SQL_INJECTION
  path_traversal ← tag "attack-lfi" or DIR_TRAVERSAL or FILE_INJECTION
  cmdi           ← tag "attack-rce" or COMMAND_INJECTION or PHP_INJECTION or language-shell
  xss            ← tag "attack-xss" or OWASP_CRS/WEB_ATTACK/XSS
  benign         ← no Message: line in H section (un-flagged request)

Blocks matching only policy/protocol/scanner/bot rules (no WEB_ATTACK/attack-* tag)
are skipped — not classifiable into target categories.

NOTE: All 29 log files contain only flagged requests (ModSecurity only audits rule triggers).
Zero benign blocks are present in the source. This is documented.
"""

import json
import os
import re
import yaml
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
DATA_DIR = ROOT / "data" / "owasp"
OUTPUT = ROOT / "training" / "data_clean" / "owasp_logs.jsonl"

with open(ROOT / "training" / "label_map.yaml") as _f:
    _owasp_cfg = yaml.safe_load(_f)["mappings"]["owasp_logs"]["priority"]

LABEL_PRIORITY: list[tuple[str, re.Pattern[str]]] = [
    (entry["label"], re.compile("|".join(entry["patterns"]), re.IGNORECASE))
    for entry in _owasp_cfg
]

SECTION_RE = re.compile(r'--[0-9a-f]+-([A-Z])--\n?')


def resolve_label_from_h(h_text: str) -> str | None:
    if not h_text.strip() or "Message:" not in h_text:
        return "benign"
    for label, pattern in LABEL_PRIORITY:
        if pattern.search(h_text):
            return label
    return None  # policy/bot/scanner — skip


def parse_request_line(request_line: str) -> tuple[str, str, str]:
    """Parse 'GET /path?query HTTP/1.1' → (method, path, query)."""
    parts = request_line.split(" ", 2)
    if len(parts) < 2:
        return "GET", "", ""
    method = parts[0].upper()
    url_part = parts[1]
    if "?" in url_part:
        path, query = url_part.split("?", 1)
    else:
        path, query = url_part, ""
    return method, path.strip(), query.strip()


def parse_headers(header_lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in header_lines:
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()
    return headers


def parse_block(block: str) -> dict | None:
    """Parse one ModSecurity audit block into a CanonicalRequest dict or None."""
    sections: dict[str, str] = {}
    current_letter = None
    current_lines: list[str] = []

    for line in block.splitlines():
        m = SECTION_RE.match(line)
        if m:
            if current_letter is not None:
                sections[current_letter] = "\n".join(current_lines)
            current_letter = m.group(1)
            current_lines = []
        else:
            current_lines.append(line)
    if current_letter is not None:
        sections[current_letter] = "\n".join(current_lines)

    h_text = sections.get("H", "")
    label = resolve_label_from_h(h_text)
    if label is None:
        return None

    b_text = sections.get("B", "")
    b_lines = b_text.strip().splitlines()
    if not b_lines:
        return None

    method, path, query = parse_request_line(b_lines[0])
    raw_headers = parse_headers(b_lines[1:])

    body_lines: list[str] = []
    in_body = False
    for line in b_lines[1:]:
        if in_body:
            body_lines.append(line)
        elif line == "":
            in_body = True

    body = "\n".join(body_lines).strip() or None

    primary_keys = {"user-agent", "content-type", "referer", "cookie"}
    extra = {k: v for k, v in raw_headers.items() if k not in primary_keys}

    return {
        "method":       method,
        "path":         path,
        "query":        query,
        "body":         body,
        "userAgent":    raw_headers.get("user-agent", ""),
        "contentType":  raw_headers.get("content-type", ""),
        "referer":      raw_headers.get("referer", ""),
        "cookie":       raw_headers.get("cookie", ""),
        "extraHeaders": extra,
        "label":        label,
    }


def parse_log_file(path: str) -> list[dict]:
    with open(path, encoding="utf-8", errors="replace") as f:
        raw = f.read()
    blocks = re.split(r'\n(?=--[0-9a-f]+-A--\n)', raw)
    results = []
    for block in blocks:
        parsed = parse_block(block)
        if parsed is not None:
            results.append(parsed)
    return results


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    skipped = 0
    total_blocks = 0

    with open(OUTPUT, "w", encoding="utf-8") as fout:
        for date_dir in sorted(os.listdir(DATA_DIR)):
            log_path = DATA_DIR / date_dir / "modsec_audit.anon.log"
            if not log_path.exists():
                continue
            records = parse_log_file(str(log_path))
            for rec in records:
                total_blocks += 1
                fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                counts[rec["label"]] = counts.get(rec["label"], 0) + 1

    total_written = sum(counts.values())
    print(f"owasp_logs.jsonl written to {OUTPUT}")
    print(f"  Total blocks parsed : {total_blocks:,}")
    print(f"  Written             : {total_written:,}")
    print("  Class distribution:")
    for label in ["sqli", "xss", "path_traversal", "cmdi", "benign"]:
        print(f"    {label:15s}: {counts.get(label, 0):,}")
    if counts.get("benign", 0) == 0:
        print("  NOTE: Zero benign rows — ModSecurity honeypot logs only flagged requests.")
        print("        Un-flagged (benign) traffic was not recorded in this source.")


if __name__ == "__main__":
    main()
