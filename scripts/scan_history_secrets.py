#!/usr/bin/env python3
"""
Scan the full git history (every commit, every branch) for leaked secrets.

A lightweight, offline complement to the gitleaks CI job: it pipes
`git log -p --all` through credential patterns plus a high-entropy check on
assigned values, and prints each hit with the commit that introduced it.

    python scripts/scan_history_secrets.py            # exit 1 if anything is found
    python scripts/scan_history_secrets.py --allow-known
"""

import argparse
import math
import re
import subprocess
import sys

PATTERNS = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-secret-key", re.compile(r"(?i)aws(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("slack-token", re.compile(r"\bxox[abpr]-[0-9A-Za-z-]{10,}")),
    ("discord-webhook", re.compile(r"discord(app)?\.com/api/webhooks/\d{17,20}/[\w-]{60,}")),
    ("slack-webhook", re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}")),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("virustotal-key", re.compile(r"(?i)virustotal\w*\s*[=:]\s*['\"]?[0-9a-f]{64}\b")),
    ("abuseipdb-key", re.compile(r"(?i)abuseipdb\w*\s*[=:]\s*['\"]?[0-9a-f]{80}\b")),
]
ASSIGNMENT = re.compile(r"(?i)(password|passwd|secret|api_key|apikey|token)\w*\s*[=:]\s*['\"]?([^\s'\"]{12,})")

# Documented, non-secret placeholders that appear in history on purpose
KNOWN_PLACEHOLDERS = {
    "cyberpulse-dev-secret-key-2026",   # former published dev default (removed, E72)
    "SecretPassword123!", "SecretWinRMPassword!",  # former sample values (removed, E72)
    "aB3dE5gH7jK9mN1p",  # invented test value, in history since c6c3f71
}
# Documentation templates such as `secret_token=<TELEGRAM_WEBHOOK_SECRET>`
TEMPLATE_VALUE = re.compile(r"^<[A-Z0-9_]+>")


def is_known(line, value):
    return any(known in line for known in KNOWN_PLACEHOLDERS) or bool(TEMPLATE_VALUE.match(value))


def entropy(s):
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def scan(allow_known):
    log = subprocess.run(["git", "log", "-p", "--all", "--no-color", "--format=commit %H"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace", check=True).stdout
    commit, findings = None, []
    for line in log.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1][:10]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for label, pattern in PATTERNS:
            if pattern.search(line):
                findings.append((commit, label, line[1:].strip()[:120]))
        m = ASSIGNMENT.search(line)
        if m and entropy(m.group(2)) > 4.0 and "environ" not in line and "${" not in line:
            if allow_known and is_known(line, m.group(2)):
                continue
            findings.append((commit, "high-entropy-assignment", line[1:].strip()[:120]))
    return findings


def main():
    parser = argparse.ArgumentParser(description="Scan git history for leaked secrets")
    parser.add_argument("--allow-known", action="store_true", help="ignore documented placeholders")
    args = parser.parse_args()
    findings = scan(args.allow_known)
    for commit, label, text in findings:
        print(f"{commit}  {label:<24} {text}")
    print(f"{len(findings)} finding(s)")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
