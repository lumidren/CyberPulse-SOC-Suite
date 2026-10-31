"""
Honest-Claims Guard for the CyberPulse SOC Lab

Fails the build if user-facing text reintroduces marketing or efficacy claims
that the project cannot back with a reproducible script. Each banned pattern
names the roadmap item that removed it.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SCANNED_EXTENSIONS = (".md", ".py", ".html", ".js", ".json", ".yml", ".yaml")
EXCLUDED_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}
EXCLUDED_FILES = {
    os.path.join("docs", "ROADMAP.md"),          # quotes the banned phrases as roadmap items
    os.path.join("tests", "test_honest_claims.py"),
    "CHANGELOG.md",                              # history may quote removed wording
}

# (roadmap id, compiled pattern, explanation)
BANNED_CLAIMS = [
    ("E1", re.compile(r"enterprise[- ]grade", re.I), "It's a lab, not an enterprise-grade product."),
    ("E1", re.compile(r"\bENTERPRISE SOC\b|Enterprise (SOC|Operations) Platform", re.I),
     "Lab console must not be branded as an enterprise platform."),
]


def iter_scanned_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for name in filenames:
            if not name.endswith(SCANNED_EXTENSIONS):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ROOT)
            if rel in EXCLUDED_FILES:
                continue
            yield rel, path


class TestHonestClaims(unittest.TestCase):

    def test_no_banned_claims(self):
        violations = []
        for rel, path in iter_scanned_files():
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    for item_id, pattern, why in BANNED_CLAIMS:
                        if pattern.search(line):
                            violations.append(f"{rel}:{lineno} [{item_id}] {why} -> {line.strip()[:100]}")
        self.assertEqual(violations, [], "Banned claims found:\n" + "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
