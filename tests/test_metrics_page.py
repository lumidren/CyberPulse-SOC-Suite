"""Metrics page: every number generated and current (roadmap F85)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.metrics_page import REPORT, metrics, render  # noqa: E402


class TestMetricsPage(unittest.TestCase):

    def test_every_metric_has_a_reproduce_command(self):
        for _, rows in metrics():
            for name, value, source, _ in rows:
                self.assertTrue(source.startswith("`"), name)
                self.assertNotEqual(str(value), "", name)

    def test_committed_page_is_current(self):
        with open(REPORT, encoding="utf-8") as fh:
            self.assertEqual(fh.read().replace("\r\n", "\n"), render(),
                             "run: CYBERPULSE_LAB_MODE=true python scripts/metrics_page.py")


if __name__ == "__main__":
    unittest.main()
