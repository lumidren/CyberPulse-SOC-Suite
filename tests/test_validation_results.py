"""Keeps docs/VALIDATION_RESULTS.md in sync with scripts/validate_detections.py.

If a rule or generator changes, the published counts must be regenerated
(python scripts/validate_detections.py --write) rather than going stale.
"""

import os
os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")  # tests run in a declared lab
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.validate_detections import RESULTS_PATH, build_report, run_baseline  # noqa: E402


class TestValidationResults(unittest.TestCase):

    def test_published_results_match_script_output(self):
        with open(RESULTS_PATH, "r", encoding="utf-8") as fh:
            published = fh.read().replace("\r\n", "\n")
        self.assertEqual(
            published, build_report(),
            "docs/VALIDATION_RESULTS.md is stale: run `python scripts/validate_detections.py --write`",
        )

    def test_baseline_counts_are_deterministic(self):
        self.assertEqual(run_baseline(), run_baseline())


if __name__ == "__main__":
    unittest.main()
