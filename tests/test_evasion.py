"""Evasion tests: documented bypasses must match engine behaviour (roadmap F29)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.evasion_cases import CASES  # noqa: E402
from scripts.evasion_report import REPORT, render, results  # noqa: E402
from soar.sigma_engine import SigmaEngine  # noqa: E402


class TestEvasion(unittest.TestCase):

    def test_every_case_behaves_as_documented(self):
        wrong = [(r["id"], r["expect"], r["actual"]) for r in results() if r["expect"] != r["actual"]]
        self.assertEqual(wrong, [], "update `expect` in scripts/evasion_cases.py and regenerate docs/EVASION.md")

    def test_cases_target_real_rules_and_have_unique_ids(self):
        soc_ids = {r.soar.get("soc_rule_id") for r in SigmaEngine().rules}
        self.assertEqual(len({c["id"] for c in CASES}), len(CASES))
        for case in CASES:
            self.assertIn(case["rule"], soc_ids, case["id"])
            self.assertIn(case["expect"], {"detected", "bypass"})
            self.assertTrue(case["note"], case["id"])

    def test_committed_report_is_current(self):
        with open(REPORT, encoding="utf-8") as fh:
            self.assertEqual(fh.read().replace("\r\n", "\n"), render(), "run: python scripts/evasion_report.py")


if __name__ == "__main__":
    unittest.main()
