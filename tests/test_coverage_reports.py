"""Generated coverage reports stay current and consistent (roadmap F8, F10, F11)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.coverage_report import OUT, REPORTS, data_sources, detection_rules, gaps, load_targets, rule_quality, simulated_techniques  # noqa: E402
from soar.sigma_engine import SigmaEngine  # noqa: E402


class TestCoverageReports(unittest.TestCase):

    def test_committed_reports_are_current(self):
        for name, render in REPORTS.items():
            with open(os.path.join(OUT, name), encoding="utf-8") as fh:
                self.assertEqual(fh.read().replace("\r\n", "\n"), render(), f"stale {name}: run scripts/coverage_report.py")

    def test_every_rule_has_a_known_data_source(self):
        table = data_sources()
        self.assertEqual(sum(len(e["rules"]) for e in table.values()), len(detection_rules()))
        self.assertFalse(any("/" in source and "(" not in source for source in table), "unmapped logsource")

    def test_gap_report_has_no_open_gaps(self):
        # Every uncovered target must carry a recorded blocker; anything else is an oversight.
        _, uncovered = gaps()
        self.assertEqual([t for t, e in uncovered.items() if not e.get("blocker")], [])

    def test_simulated_techniques_are_all_detected(self):
        covered = {tid.split(".")[0] for r in SigmaEngine().rules for tid in r.technique_ids}
        covered |= {tid for r in SigmaEngine().rules for tid in r.technique_ids}
        self.assertEqual(simulated_techniques() - covered, set())

    def test_targets_are_valid_technique_ids(self):
        for tid, entry in load_targets().items():
            self.assertRegex(tid, r"^T\d{4}(\.\d{3})?$")
            self.assertTrue(entry.get("name") and entry.get("tactic") and entry.get("why"), tid)

    def test_quality_scores_are_bounded_and_explained(self):
        rows = rule_quality()
        self.assertEqual(len(rows), len(SigmaEngine().rules))
        for row in rows:
            self.assertEqual(row["score"], sum(row["parts"].values()))
            self.assertTrue(0 <= row["score"] <= 100, row)

    def test_noisy_rule_loses_fp_points(self):
        by_rule = {r["rule"]: r for r in rule_quality()}
        self.assertGreater(by_rule["SOC-RULE-004"]["baseline_fp"], 5)
        self.assertEqual(by_rule["SOC-RULE-004"]["parts"]["baseline_fp"], 0)


if __name__ == "__main__":
    unittest.main()
