#!/usr/bin/env python3
"""
Convert every Sigma rule into Splunk SPL, Elastic (Lucene), Microsoft KQL and Wazuh XML.

    python scripts/convert_rules.py            # write rules/converted/<target>/...
    python scripts/convert_rules.py --check    # exit 1 if rules/converted is stale

Generated queries are starting points: review and validate them in your SIEM.
"""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.sigma_convert import TARGETS, convert  # noqa: E402
from soar.sigma_engine import SigmaEngine  # noqa: E402

OUT_DIR = os.path.join(ROOT, "rules", "converted")
EXTENSIONS = {"splunk": ".spl", "elastic": ".lucene", "kql": ".kql", "wazuh": ".xml"}


def render_all():
    files = {}
    rules = SigmaEngine().rules
    for target in TARGETS:
        if target == "wazuh":
            body = "<group name=\"cyberpulse,sigma_generated,\">\n" + "\n".join(convert(r, "wazuh") for r in rules) + "</group>\n"
            files[os.path.join("wazuh", "cyberpulse_sigma_generated.xml")] = body
            continue
        for r in rules:
            stem = os.path.splitext(os.path.basename(r.file))[0]
            files[os.path.join(target, stem + EXTENSIONS[target])] = convert(r, target)
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = render_all()
    stale = []
    for rel, body in files.items():
        path = os.path.join(OUT_DIR, rel)
        if args.check:
            try:
                with open(path, encoding="utf-8") as fh:
                    if fh.read().replace("\r\n", "\n") != body:
                        stale.append(rel)
            except FileNotFoundError:
                stale.append(rel)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
    if args.check:
        for rel in stale:
            print(f"stale: rules/converted/{rel}")
        sys.exit(1 if stale else 0)
    print(f"wrote {len(files)} files to rules/converted/")


if __name__ == "__main__":
    main()
