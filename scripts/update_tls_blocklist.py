#!/usr/bin/env python3
"""
Load a JA3/JA4 blocklist into SOC-RULE-055 (roadmap F74).

    python scripts/update_tls_blocklist.py --ja3-csv sslbl_ja3.csv [--ja4-file ja4.txt] [--dry-run]

``--ja3-csv``: a CSV whose first column is a JA3 MD5 (32 hex), e.g. the abuse.ch SSLBL JA3
fingerprint list; lines starting with '#' are ignored. ``--ja4-file``: one JA4 fingerprint per
line. Download the list yourself and respect its licence.

The rule's lists are replaced, its version bumped (minor), its detection fingerprint in
rules/soar_mapping.yml updated and a RULE_CHANGELOG.md entry added, so the change passes the
same checks as a hand edit. Regenerate the derived files afterwards (see CONTRIBUTING.md).
"""

import argparse
import csv
import io
import os
import re
import sys
from datetime import date

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.rule_versioning import detection_fingerprint  # noqa: E402

RULE = os.path.join(ROOT, "rules", "sigma", "net_zeek_tls_fingerprint_blocklist.yml")
MAPPING = os.path.join(ROOT, "rules", "soar_mapping.yml")
CHANGELOG = os.path.join(ROOT, "rules", "RULE_CHANGELOG.md")
SOC_ID = "SOC-RULE-055"
JA3_RE = re.compile(r"^[0-9a-f]{32}$")
JA4_RE = re.compile(r"^[tqd]\d{2}[di]\d{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")


def read_ja3(text):
    out = []
    for row in csv.reader(io.StringIO(text)):
        if row and not row[0].lstrip().startswith("#") and JA3_RE.match(row[0].strip().lower()):
            out.append(row[0].strip().lower())
    return sorted(set(out))


def read_ja4(text):
    return sorted({line.strip() for line in text.splitlines() if JA4_RE.match(line.strip())})


def bump_minor(version):
    major, minor, _ = (int(x) for x in version.split("."))
    return f"{major}.{minor + 1}.0"


def apply(ja3, ja4, dry_run=False):
    with open(RULE, encoding="utf-8") as fh:
        text = fh.read()
    doc = yaml.safe_load(text)
    if ja3:
        doc["detection"]["selection_ja3"]["ja3"] = ja3
    if ja4:
        doc["detection"]["selection_ja4"]["ja4"] = ja4
    doc["modified"] = date.today().isoformat()
    with open(MAPPING, encoding="utf-8") as fh:
        mapping_text = fh.read()
    entry = re.search(rf"  {re.escape(doc['id'])}:\n(?:    .*\n)+", mapping_text)
    old_version = re.search(r"version: ([0-9.]+)", entry.group(0)).group(1)
    new_version = bump_minor(old_version)
    new_entry = re.sub(r"version: [0-9.]+", f"version: {new_version}", entry.group(0))
    new_entry = re.sub(r"detection_sha256: [0-9a-f]+", f"detection_sha256: {detection_fingerprint(doc)}", new_entry)
    summary = f"{len(ja3)} JA3 and {len(ja4)} JA4 fingerprints loaded from a supplied list"
    if dry_run:
        print(f"would set {summary}; version {old_version} -> {new_version}")
        return
    with open(RULE, "w", encoding="utf-8", newline="\n") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True, width=110, indent=4)
    with open(MAPPING, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(mapping_text.replace(entry.group(0), new_entry))
    with open(CHANGELOG, encoding="utf-8") as fh:
        log = fh.read()
    section = re.search(rf"^## {SOC_ID}:.*?(?=^## |\Z)", log, re.M | re.S)
    line = f"* **{new_version}** ({date.today().isoformat()}): Blocklist replaced: {summary}.\n"
    log = log[:section.end()].rstrip("\n") + "\n" + line + ("\n" + log[section.end():] if section.end() < len(log) else "")
    with open(CHANGELOG, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(log)
    print(f"updated {SOC_ID}: {summary}; version {new_version}")


def main():
    parser = argparse.ArgumentParser(description="Load a JA3/JA4 blocklist into SOC-RULE-055")
    parser.add_argument("--ja3-csv")
    parser.add_argument("--ja4-file")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not (args.ja3_csv or args.ja4_file):
        sys.exit("give --ja3-csv and/or --ja4-file")
    ja3 = read_ja3(open(args.ja3_csv, encoding="utf-8").read()) if args.ja3_csv else []
    ja4 = read_ja4(open(args.ja4_file, encoding="utf-8").read()) if args.ja4_file else []
    if not (ja3 or ja4):
        sys.exit("no valid fingerprints found in the input")
    apply(ja3, ja4, args.dry_run)


if __name__ == "__main__":
    main()
