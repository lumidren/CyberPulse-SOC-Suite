"""No credentials or well-known default keys in the working tree (roadmap E72)."""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}
SKIP_FILES = {os.path.join("tests", "test_secret_hygiene.py"), os.path.join("tests", "test_dashboard_auth.py"),
              "CHANGELOG.md", os.path.join("docs", "ROADMAP.md"),
              # These name the historical placeholders on purpose (allowlist / scan record / scanner)
              ".gitleaks.toml", os.path.join("docs", "SECRET_SCAN.md"), os.path.join("scripts", "scan_history_secrets.py")}

SECRET_PATTERNS = [
    ("old dev default key", re.compile(r"cyberpulse-dev-secret-key")),
    ("sample password", re.compile(r"Secret(WinRM)?Password\d*!?")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abpr]-[0-9A-Za-z-]{10,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("assigned secret", re.compile(r"(?i)^(\w*(PASSWORD|API_KEY|SECRET|TOKEN))=(?!change-me|$|your_|https?://)\S{6,}", re.M)),
]


class TestSecretHygiene(unittest.TestCase):

    def test_no_secrets_in_working_tree(self):
        hits = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, ROOT)
                if rel in SKIP_FILES or name.endswith((".pyc", ".png", ".jpg", ".gif", ".ico")):
                    continue
                try:
                    with open(path, encoding="utf-8") as fh:
                        text = fh.read()
                except (UnicodeDecodeError, OSError):
                    continue
                for label, pattern in SECRET_PATTERNS:
                    for m in pattern.finditer(text):
                        hits.append(f"{rel}: {label}: {m.group(0)[:40]}")
        self.assertEqual(hits, [], "Possible secrets committed:\n" + "\n".join(hits))


if __name__ == "__main__":
    unittest.main()
