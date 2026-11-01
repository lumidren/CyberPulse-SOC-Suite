"""Relative links in the README and docs point at files that exist."""

import glob
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINK_RE = re.compile(r"\]\(([^)\s#]+)(?:#[^)]*)?\)")


class TestDocLinks(unittest.TestCase):

    def test_relative_links_resolve(self):
        files = [os.path.join(ROOT, "README.md"), os.path.join(ROOT, "CONTRIBUTING.md"),
                 os.path.join(ROOT, "CODE_OF_CONDUCT.md")] + glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True)
        broken = []
        for path in files:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            for target in LINK_RE.findall(text):
                if re.match(r"^[a-z]+:", target):  # http:, https:, mailto:
                    continue
                if not os.path.exists(os.path.normpath(os.path.join(os.path.dirname(path), target))):
                    broken.append(f"{os.path.relpath(path, ROOT)} -> {target}")
        self.assertEqual(broken, [])


if __name__ == "__main__":
    unittest.main()
