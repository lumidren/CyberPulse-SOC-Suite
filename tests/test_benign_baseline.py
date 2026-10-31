"""Tests for the deterministic benign baseline generator (FP test data)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.benign_baseline import BASELINE_CATEGORIES, generate_baseline


class TestBenignBaseline(unittest.TestCase):

    def test_deterministic_for_seed(self):
        self.assertEqual(generate_baseline(60, seed=7), generate_baseline(60, seed=7))
        self.assertNotEqual(generate_baseline(60, seed=7), generate_baseline(60, seed=8))

    def test_all_categories_present_evenly(self):
        events = generate_baseline(len(BASELINE_CATEGORIES) * 10)
        counts = {}
        for e in events:
            counts[e["baseline_category"]] = counts.get(e["baseline_category"], 0) + 1
        self.assertEqual(set(counts), {name for name, _ in BASELINE_CATEGORIES})
        self.assertEqual(set(counts.values()), {10})

    def test_events_use_lab_identifiers_only(self):
        for e in generate_baseline(120):
            self.assertEqual(e["technique_id"], "BENIGN")
            self.assertTrue(e["source_ip"].startswith("10."), e["source_ip"])


if __name__ == "__main__":
    unittest.main()
