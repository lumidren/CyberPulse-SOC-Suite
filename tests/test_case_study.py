"""The case study quotes only figures that the generated reports currently show (roadmap F100)."""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DOCS = os.path.join(ROOT, "docs")
STUDY = os.path.join(DOCS, "CASE_STUDY.md")
# Generated pages the case study may quote from
SOURCES = ["METRICS.md", "EVASION.md", "coverage/GAPS.md", "BEHAVIORAL_BASELINE.md", "SCENARIO_RESULTS.md",
           "THRESHOLD_TUNING.md", "WHAT_I_MISSED.md"]
FIGURE = re.compile(r"(?<![\w./-])(\d+/\d+|\d+\.\d+)(?![\w/])")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class TestCaseStudy(unittest.TestCase):

    def test_every_ratio_and_decimal_appears_in_a_generated_report(self):
        sources = "\n".join(read(os.path.join(DOCS, p)) for p in SOURCES)
        study = read(STUDY)
        figures = set(FIGURE.findall(study))
        self.assertTrue({"60/60", "11/16", "27/36", "0.335", "0/600"} <= figures)
        missing = sorted(f for f in figures if f not in sources)
        self.assertEqual(missing, [], "case study quotes figures no generated report shows")

    def test_rule_counts_and_suppressions_match_metrics(self):
        metrics, study = read(os.path.join(DOCS, "METRICS.md")), read(STUDY)
        singles = re.search(r"\| Single-event Sigma rules \| (\d+) \|", metrics).group(1)
        correlations = re.search(r"\| Correlation rules \| (\d+) \|", metrics).group(1)
        suppressed = re.search(r"(\d+) matches suppressed", metrics).group(1)
        self.assertIn(f"{singles} single-event rules and {correlations} correlation rules", study)
        self.assertIn(f"{suppressed} of 600 benign baseline events", study)

    def test_every_linked_page_exists(self):
        for link in re.findall(r"\]\(([^)#]+)\)", read(STUDY)):
            self.assertTrue(os.path.exists(os.path.join(DOCS, link)), link)


if __name__ == "__main__":
    unittest.main()
