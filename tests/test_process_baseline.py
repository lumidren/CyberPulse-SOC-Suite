"""Parent -> child process baselining (roadmap F13)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.rare_process_pairs import REPORT, render  # noqa: E402
from soar.process_baseline import ProcessPairBaseline, process_pair  # noqa: E402


def proc(parent, child, event_id=1):
    return {"event_id": event_id, "details": {"ParentImage": f"C:\\Windows\\System32\\{parent}",
                                               "Image": f"C:\\Windows\\System32\\{child}"}}


class TestProcessBaseline(unittest.TestCase):

    def trained(self):
        return ProcessPairBaseline(min_training_events=10).learn_many(
            [proc("services.exe", "svchost.exe")] * 20 + [proc("explorer.exe", "notepad.exe")])

    def test_pairs_are_case_insensitive_basenames(self):
        self.assertEqual(process_pair(proc("Explorer.EXE", "CMD.exe")), ("explorer.exe", "cmd.exe"))
        self.assertIsNone(process_pair({"event_id": 4625, "details": {}}))

    def test_verdicts(self):
        baseline = self.trained()
        self.assertEqual(baseline.score(proc("services.exe", "svchost.exe"))["verdict"], "COMMON")
        self.assertEqual(baseline.score(proc("explorer.exe", "notepad.exe"))["verdict"], "RARE")
        self.assertEqual(baseline.score(proc("winword.exe", "powershell.exe"))["verdict"], "NEVER_SEEN")
        self.assertEqual(baseline.score({"event_id": 11})["verdict"], "NOT_APPLICABLE")

    def test_refuses_to_judge_without_enough_training(self):
        baseline = ProcessPairBaseline(min_training_events=50).learn(proc("a.exe", "b.exe")) and ProcessPairBaseline()
        self.assertEqual(baseline.score(proc("x.exe", "y.exe"))["verdict"], "INSUFFICIENT_BASELINE")

    def test_round_trip_holds_no_hosts_or_users(self):
        baseline = self.trained()
        text = baseline.to_json()
        self.assertNotIn("System32", text)
        restored = ProcessPairBaseline.from_json(text)
        self.assertEqual(restored.counts, baseline.counts)

    def test_security_4688_fields(self):
        event = {"event_id": 4688, "details": {"ParentProcessName": "C:\\a\\cmd.exe", "NewProcessName": "C:\\b\\whoami.exe"}}
        self.assertEqual(process_pair(event), ("cmd.exe", "whoami.exe"))

    def test_committed_report_is_current(self):
        with open(REPORT, encoding="utf-8") as fh:
            self.assertEqual(fh.read().replace("\r\n", "\n"), render(), "run: python scripts/rare_process_pairs.py")


if __name__ == "__main__":
    unittest.main()
