"""Hunting workbench: event store, pivots, stacks, templates (roadmap F66-F75)."""

import os
import re
import sys
import unittest
from datetime import datetime, timedelta, timezone

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.validate_detections import BASELINE_SEED  # noqa: E402
from simulator.attack_chain import run_chain  # noqa: E402
from simulator.benign_baseline import generate_baseline  # noqa: E402
from soar import views  # noqa: E402
from soar.event_store import EventStore  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


class HuntBase(unittest.TestCase):

    def setUp(self):
        self.orchestrator = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        for event in generate_baseline(120, BASELINE_SEED):
            self.orchestrator.process_event(event)
        run_chain(self.orchestrator, start=datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc))


class TestEventStoreAndPivot(HuntBase):

    def test_store_keeps_non_alerting_events(self):
        events = self.orchestrator.event_store.snapshot()
        self.assertGreaterEqual(len(events), 130)
        self.assertTrue(any(e["_rule"] is None for e in events), "benign events are kept for hunting")

    def test_pivot_on_host_finds_related_entities(self):
        result = views.pivot(self.orchestrator, "host", "corp-finance-02")
        self.assertGreater(result["events"], 0)
        self.assertGreater(result["alerted"], 0)
        self.assertIn("process", result["related"])
        self.assertIn("rclone.exe", " ".join(r["value"] for r in result["related"]["process"]))
        self.assertIn("error", views.pivot(self.orchestrator, "bogus", "x"))

    def test_bounded_and_purged(self):
        store = EventStore(maxlen=3)
        for i in range(5):
            store.add({"event_id": i})
        self.assertEqual([e["event_id"] for e in store.snapshot()], [2, 3, 4])
        self.assertEqual(store.purge_older_than(datetime.now(timezone.utc) + timedelta(seconds=1)), 3)


class TestStack(HuntBase):

    def test_rarest_first_with_long_tail(self):
        result = views.stack(self.orchestrator, "process")
        counts = [r["count"] for r in result["rows"]]
        self.assertEqual(counts, sorted(counts))
        tail = {r["value"] for r in result["rows"] if r["tail"]}
        self.assertTrue(any("rclone" in v for v in tail), "attacker tooling sits in the long tail")
        self.assertFalse(any(v.endswith("powershell.exe") and r["tail"] for r in result["rows"] for v in [r["value"]]),
                         "common admin tooling is not in the tail")

    def test_filtered_stack(self):
        result = views.stack(self.orchestrator, "process", "host", "CORP-FINANCE-02")
        self.assertEqual(result["where"], {"host": "CORP-FINANCE-02"})
        self.assertLess(result["events"], len(self.orchestrator.event_store.snapshot()))
        self.assertIn("error", views.stack(self.orchestrator, "nope"))


class TestHuntPages(unittest.TestCase):

    def test_hunt_page_text_only(self):
        with open(os.path.join(ROOT, "web", "hunt.js"), encoding="utf-8") as fh:
            self.assertIsNone(re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", fh.read()))


if __name__ == "__main__":
    unittest.main()
