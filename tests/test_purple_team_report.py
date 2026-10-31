"""Generated purple-team report stays current (roadmap F23)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.purple_team_report import REPORT, build, render  # noqa: E402


class TestPurpleTeamReport(unittest.TestCase):

    def test_committed_report_is_current(self):
        with open(REPORT, encoding="utf-8") as fh:
            self.assertEqual(fh.read().replace("\r\n", "\n"), render(),
                             "run: CYBERPULSE_LAB_MODE=true python scripts/purple_team_report.py")

    def test_default_policy_never_auto_executes(self):
        for _, _, rows in build():
            for row in rows:
                self.assertNotIn(row["status"], {"SUCCESS", "EXECUTED", "CONTAINED"}, row)


if __name__ == "__main__":
    unittest.main()
