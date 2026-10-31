"""Generated coverage reports stay current and consistent (roadmap F8, F10, F11)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.coverage_report import OUT, REPORTS, data_sources  # noqa: E402
from soar.sigma_engine import SigmaEngine  # noqa: E402


class TestCoverageReports(unittest.TestCase):

    def test_committed_reports_are_current(self):
        for name, render in REPORTS.items():
            with open(os.path.join(OUT, name), encoding="utf-8") as fh:
                self.assertEqual(fh.read().replace("\r\n", "\n"), render(), f"stale {name}: run scripts/coverage_report.py")

    def test_every_rule_has_a_known_data_source(self):
        table = data_sources()
        self.assertEqual(sum(len(e["rules"]) for e in table.values()), len(SigmaEngine().rules))
        self.assertFalse(any("/" in source and "(" not in source for source in table), "unmapped logsource")


if __name__ == "__main__":
    unittest.main()
