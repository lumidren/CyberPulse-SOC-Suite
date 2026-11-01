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


class TestTemplates(HuntBase):

    def test_templates_load_validate_and_run(self):
        from soar.hunt_templates import load_templates, run_template
        templates = load_templates()
        self.assertGreaterEqual(len(templates), 5)
        result = run_template(self.orchestrator, templates["cloud_exfil_tools"])
        self.assertGreater(result["steps"][0]["result"]["total"], 0, "rclone is found in the lab chain")
        for template in templates.values():
            run_template(self.orchestrator, template)

    def test_invalid_template_rejected(self):
        from soar.hunt_templates import validate
        self.assertTrue(validate({"name": "x", "attack": ["X1"], "steps": [{"type": "delete"}]}))


class TestBeaconing(unittest.TestCase):

    def conn(self, t, dst="203.0.113.80", src="10.0.2.15"):
        return {"event_source": "zeek:conn", "source_ip": src,
                "timestamp": datetime.fromtimestamp(1793500000 + t, timezone.utc).isoformat(),
                "details": {"id.resp_h": dst, "id.resp_p": 443}}

    def test_regular_series_flagged_irregular_not(self):
        from soar.beaconing import find_beacons
        regular = [self.conn(60 * i + (i % 3)) for i in range(12)]
        irregular = [self.conn(t, dst="198.51.100.9") for t in (0, 5, 90, 91, 400, 1200, 1210, 3000, 3500, 7000)]
        few = [self.conn(60 * i, dst="192.0.2.1") for i in range(4)]
        found = find_beacons(regular + irregular + few)
        self.assertEqual([b["destination"] for b in found], ["203.0.113.80"])
        self.assertAlmostEqual(found[0]["mean_interval_sec"], 60, delta=1)
        self.assertEqual(find_beacons(regular, allow_destinations=("203.0.113.80",)), [])


class TestHuntToRule(HuntBase):

    def test_draft_from_pivot_loads_and_matches_its_samples(self):
        import yaml
        from soar.hunt_to_rule import draft_rule
        from soar.sigma_engine import SigmaRule
        result = draft_rule("process", "C:\\Users\\Public\\rclone.exe", self.orchestrator.event_store.snapshot())
        self.assertNotIn("error", result)
        doc = yaml.safe_load(result["rule_yaml"])
        self.assertEqual(doc["logsource"], {"product": "windows", "category": "process_creation"})
        self.assertIn("attack.t1567.002", doc["tags"])
        self.assertEqual(doc["status"], "experimental")
        self.assertGreaterEqual(result["matches_own_samples"], 1)
        samples = yaml.safe_load(result["samples_yaml"])
        rule = SigmaRule("rules/sigma/x.yml", doc, {})
        self.assertTrue(all(rule.matches(p["event"]) for p in samples["positive"]))
        self.assertIn("Draft only", result["note"])

    def test_draft_refusals(self):
        from soar.hunt_to_rule import draft_rule
        self.assertIn("error", draft_rule("event_id", "1", self.orchestrator.event_store.snapshot()))
        self.assertIn("error", draft_rule("process", "nothing.exe", self.orchestrator.event_store.snapshot()))


class TestHuntPages(unittest.TestCase):

    def test_hunt_page_text_only(self):
        with open(os.path.join(ROOT, "web", "hunt.js"), encoding="utf-8") as fh:
            self.assertIsNone(re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", fh.read()))


if __name__ == "__main__":
    unittest.main()
