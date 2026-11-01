"""Detection quality leaderboard: generated, complete and ordered (roadmap F98)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.leaderboard import REPORT, render, rows  # noqa: E402
from soar.sigma_engine import SigmaEngine  # noqa: E402


class TestLeaderboard(unittest.TestCase):

    def test_every_rule_is_ranked_once_in_order(self):
        ranked = rows()
        ids = [r["rule"] for r in ranked]
        self.assertEqual(sorted(ids), sorted(r.soar.get("soc_rule_id", r.id) for r in SigmaEngine().rules))
        keys = [(-r["quality"], len(r["missing"]), r["baseline"], r["rule"]) for r in ranked]
        self.assertEqual(keys, sorted(keys))

    def test_untested_or_bypassed_rules_list_what_is_missing(self):
        for r in rows():
            if r["evasion"] == "not tested":
                self.assertIn("evasion tests", r["missing"])
            if r["bypasses"]:
                self.assertTrue(any("known bypass" in m for m in r["missing"]), r["rule"])

    def test_committed_page_is_current(self):
        with open(REPORT, encoding="utf-8") as fh:
            self.assertEqual(fh.read().replace("\r\n", "\n"), render(),
                             "run: CYBERPULSE_LAB_MODE=true python scripts/leaderboard.py")


if __name__ == "__main__":
    unittest.main()
