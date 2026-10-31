#!/usr/bin/env python3
"""
Release helper: version consistency check and CHANGELOG section extraction.

    python scripts/release_notes.py --check 3.0.0   # exit 1 unless all versions agree
    python scripts/release_notes.py 3.0.0           # print that version's CHANGELOG section
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def project_versions():
    pyproject = re.search(r'^version = "([^"]+)"', read("pyproject.toml"), re.M).group(1)
    server = re.search(r'^__version__ = "([^"]+)"', read("server.py"), re.M).group(1)
    changelog = re.search(r"^## \[(\d+\.\d+\.\d+)\]", read("CHANGELOG.md"), re.M).group(1)
    return {"pyproject.toml": pyproject, "server.py": server, "CHANGELOG.md (latest)": changelog}


def changelog_section(version):
    text = read("CHANGELOG.md")
    match = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.M | re.S)
    return match.group(1).strip() if match else None


def check(version):
    problems = []
    if not SEMVER.match(version):
        problems.append(f"{version!r} is not MAJOR.MINOR.PATCH")
    for source, found in project_versions().items():
        if found != version:
            problems.append(f"{source} has {found}, expected {version}")
    if not changelog_section(version):
        problems.append(f"CHANGELOG.md has no section for {version}")
    return problems


def main(argv):
    if argv and argv[0] == "--check":
        problems = check(argv[1])
        for p in problems:
            print(f"ERROR {p}")
        return 1 if problems else 0
    section = changelog_section(argv[0])
    if section is None:
        print(f"No CHANGELOG section for {argv[0]}", file=sys.stderr)
        return 1
    print(section)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
