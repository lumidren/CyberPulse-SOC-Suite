"""Triage workspace views (roadmap F51-F64)."""

import os
import re
import sys
import unittest
from datetime import datetime, timezone

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_chain import run_chain  # noqa: E402
from soar import views  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


class ViewsTestBase(unittest.TestCase):

    def setUp(self):
        # Fresh per test: some tests change case status or assignees
        self.orchestrator = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        run_chain(self.orchestrator, start=datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc))
        self.case_ids = list(self.orchestrator.case_manager.cases)


class TestTimeline(ViewsTestBase):

    def test_case_timeline_is_in_event_time_order(self):
        timelines = [views.case_timeline(self.orchestrator, cid) for cid in self.case_ids]
        foothold = max(timelines, key=lambda t: len(t["entries"]))
        times = [e["at"] for e in foothold["entries"]]
        self.assertEqual(times, sorted(times))
        self.assertGreater(foothold["span_sec"], 0)
        self.assertTrue(all(e["detection_delay_sec"] is not None for e in foothold["entries"]))
        self.assertIsNone(views.case_timeline(self.orchestrator, "CASE-missing"))


class TestConsolePages(unittest.TestCase):

    def test_workspace_scripts_never_inject_html(self):
        for name in ("session.js", "triage.js"):
            with open(os.path.join(ROOT, "web", name), encoding="utf-8") as fh:
                self.assertIsNone(re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", fh.read()), name)


if __name__ == "__main__":
    unittest.main()


class TestQueue(ViewsTestBase):

    def test_queue_orders_open_work_by_severity(self):
        queue = views.triage_queue(self.orchestrator)
        self.assertEqual(len(queue), len(self.case_ids))
        ranks = [(views.STATUS_ORDER[c["status"]], views.SEVERITY_ORDER[c["severity"]]) for c in queue]
        self.assertEqual(ranks, sorted(ranks))

    def test_closed_cases_and_assignee_filter(self):
        cases = self.orchestrator.case_manager
        first, second = self.case_ids[0], self.case_ids[-1]
        cases.update(first, "alice", assignee="alice")
        cases.update(second, "bob", status="Closed")
        self.assertEqual([c["case_id"] for c in views.triage_queue(self.orchestrator, assignee="alice")], [first])
        self.assertNotIn(second, [c["case_id"] for c in views.triage_queue(self.orchestrator)])
        self.assertIn(second, [c["case_id"] for c in views.triage_queue(self.orchestrator, include_closed=True)])


class TestProcessTree(ViewsTestBase):

    def test_tree_links_parents_children_and_access(self):
        trees = [views.process_tree(self.orchestrator, cid) for cid in self.case_ids]
        flat = []

        def walk(node, parent=None):
            flat.append((parent, node["name"], node["relation"], bool([a for a in node["alerts"] if a])))
            for child in node["children"]:
                walk(child, node["name"])
        for tree in trees:
            for host in tree["hosts"]:
                for root in host["roots"]:
                    walk(root)
        self.assertIn(("WINWORD.EXE", "powershell.exe", "spawned", True), flat)
        self.assertTrue(any(name == "lsass.exe" and rel == "accessed" for _, name, rel, _ in flat))
        self.assertTrue(any(parent == "PSEXESVC.exe" and name == "cmd.exe" for parent, name, _, _ in flat))
        self.assertIsNone(views.process_tree(self.orchestrator, "CASE-missing"))


class TestNetworkGraph(ViewsTestBase):

    def test_edges_connect_sources_to_hosts(self):
        graph = views.network_graph(self.orchestrator)
        ids = {n["id"]: n for n in graph["nodes"]}
        for edge in graph["edges"]:
            self.assertEqual(ids[edge["source"]]["type"], "source")
            self.assertEqual(ids[edge["target"]]["type"], "host")
            self.assertGreaterEqual(edge["count"], 1)
        self.assertEqual(ids["10.0.2.15"]["kind"], "internal")
        self.assertEqual(views._ip_kind("198.51.100.33"), "external")
        self.assertEqual(sum(e["count"] for e in graph["edges"]), len(self.orchestrator.dfir_engine.incident_list))


class TestTrend(ViewsTestBase):

    def test_mttd_measured_mttr_only_after_resolution(self):
        trend = views.mttd_mttr_trend(self.orchestrator)
        self.assertTrue(trend["points"])
        self.assertTrue(all(p["mttd_sec"] is not None and p["mttd_sec"] >= 0 for p in trend["points"] if p["incidents"]))
        self.assertTrue(all(p["mttr_sec"] is None for p in trend["points"]), "nothing resolved yet")
        self.orchestrator.case_manager.update(self.case_ids[0], "alice", status="Resolved")
        trend = views.mttd_mttr_trend(self.orchestrator)
        self.assertEqual(sum(p["resolved_cases"] for p in trend["points"]), 1)
