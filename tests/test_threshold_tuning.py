"""Threshold tuning sweep (roadmap F14)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.tune_thresholds import REPORT, analyse, suggest, synthetic_report  # noqa: E402


def failed(ip, user, second, count=None):
    details = {"LogonType": 3, "TargetUserName": user, "SubStatus": "0xc000006a"}
    if count is not None:
        details["FailedAttemptsCount"] = count
    return {"event_id": 4625, "event_source": "Security", "source_ip": ip,
            "timestamp": f"2026-11-01T10:00:{second:02d}Z", "details": details}


class TestThresholdTuning(unittest.TestCase):

    def test_suggestion_is_most_sensitive_within_budget(self):
        rows = [(1, 9, None), (5, 1, None), (10, 0, None)]
        self.assertEqual(suggest(rows, "gte", 0), 10)
        self.assertEqual(suggest(rows, "gte", 1), 5)
        self.assertIsNone(suggest([(1, 0, None), (5, 0, None)], "gte", 0), "no data, no suggestion")

    def test_field_threshold_sweep_counts_benign_and_malicious(self):
        benign = [failed("10.0.0.5", "a", 0, count=4)]
        malicious = [failed("198.51.100.7", "a", 0, count=25)]
        result = next(r for r in analyse(benign, malicious, 0) if r["rule"] == "SOC-RULE-002")
        rows = {t: (fp, tp) for t, fp, tp in result["rows"]}
        self.assertEqual(rows[3], (1, 1))
        self.assertEqual(rows[5], (0, 1))
        self.assertEqual(rows[30], (0, 0))
        self.assertEqual(result["suggested"], 5)

    def test_correlation_sweep_replays_in_time_order(self):
        burst = [failed("198.51.100.7", "admin", s) for s in reversed(range(6))]
        result = next(r for r in analyse(burst, [], 0) if r["rule"] == "SOC-RULE-043")
        rows = {t: fp for t, fp, _ in result["rows"]}
        self.assertEqual(rows[5], 1)
        self.assertEqual(rows[10], 0)
        self.assertEqual(result["suggested"], 10)

    def test_committed_report_is_current(self):
        with open(REPORT, encoding="utf-8") as fh:
            self.assertEqual(fh.read().replace("\r\n", "\n"), synthetic_report(), "run: python scripts/tune_thresholds.py")


if __name__ == "__main__":
    unittest.main()
