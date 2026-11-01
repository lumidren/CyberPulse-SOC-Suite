"""Confusion matrix over labelled synthetic events (roadmap F25)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.validate_detections import SCRIPTED_RUNS, run_confusion  # noqa: E402
from simulator.attack_simulator import SCRIPTED_GENERATORS  # noqa: E402


class TestConfusionMatrix(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.conf = run_confusion(runs=2, count=60)

    def test_overall_counts_add_up(self):
        o = self.conf["overall"]
        self.assertEqual(sum(o.values()), self.conf["events"])
        self.assertEqual(o["tp"] + o["fn"], 2 * len(SCRIPTED_GENERATORS))
        self.assertEqual(o["fp"] + o["tn"], 60)

    def test_per_rule_rows_partition_every_event(self):
        for rule, c in self.conf["per_rule"].items():
            self.assertEqual(sum(c.values()), self.conf["events"], rule)

    def test_default_run_size(self):
        self.assertGreaterEqual(SCRIPTED_RUNS, 5)


if __name__ == "__main__":
    unittest.main()
