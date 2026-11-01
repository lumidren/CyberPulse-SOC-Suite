"""Generated per-rule documentation stays current (roadmap E94, E95, F78, F83)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.rule_docs import OUTPUTS, all_rules  # noqa: E402


class TestRuleDocs(unittest.TestCase):

    def test_every_rule_documents_false_positives(self):
        for rule in all_rules():
            self.assertTrue(rule.doc.get("falsepositives"), rule.file)

    def test_generated_docs_are_current(self):
        for path, render in OUTPUTS.items():
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read().replace("\r\n", "\n"), render(), f"stale {path}: run scripts/rule_docs.py")


if __name__ == "__main__":
    unittest.main()
