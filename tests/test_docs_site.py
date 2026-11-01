"""MkDocs site configuration stays consistent with docs/ (roadmap F81)."""

import os
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _paths(nav):
    for item in nav:
        for value in item.values():
            if isinstance(value, list):
                yield from _paths(value)
            else:
                yield value


class TestDocsSite(unittest.TestCase):

    def test_every_nav_page_exists(self):
        with open(os.path.join(ROOT, "mkdocs.yml"), encoding="utf-8") as fh:
            config = yaml.safe_load(fh)
        missing = [p for p in _paths(config["nav"]) if not os.path.exists(os.path.join(ROOT, "docs", p))]
        self.assertEqual(missing, [])
        self.assertEqual(config["docs_dir"], "docs")


if __name__ == "__main__":
    unittest.main()
