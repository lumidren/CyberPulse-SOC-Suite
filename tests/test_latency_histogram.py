"""Detection-latency histogram per technique (roadmap F24)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.benchmark_pipeline import BUCKETS_US, HISTOGRAM_PATH, bucket_labels, histogram, render_histogram  # noqa: E402


class TestLatencyHistogram(unittest.TestCase):

    def test_bucketing(self):
        self.assertEqual(len(bucket_labels()), len(BUCKETS_US) + 1)
        self.assertEqual(histogram([0, 99, 100, 249, 2500, 10_000]), [2, 2, 0, 0, 0, 2])

    def test_render_marks_numbers_as_lab_measured(self):
        fake = {"runs_per_generator": 2, "platform": "test-os", "python": "3.x", "measured_at": "2026-11-01T00:00:00",
                "detection_us_by_technique": {"T1003.001": [120.0, 130.0], "T1078": [50.0, 60.0]}}
        body = render_histogram(fake)
        self.assertIn("Lab-measured", body)
        self.assertIn("| T1003.001 | 2 |", body)
        self.assertIn("| T1078 | 2 |", body)

    def test_committed_histogram_says_how_it_was_measured(self):
        with open(HISTOGRAM_PATH, encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("benchmark_pipeline.py", body)
        self.assertIn("Lab-measured", body)


if __name__ == "__main__":
    unittest.main()
