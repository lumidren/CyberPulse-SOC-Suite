"""Plugin architecture for enrichers and responders (roadmap F92)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")  # tests run in a declared lab
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar import plugins  # noqa: E402
from soar.resilient_containment import ResilientContainmentEngine  # noqa: E402


class TestPlugins(unittest.TestCase):

    def test_only_plugins_package_modules_load(self):
        self.assertEqual(plugins.load_plugins("lab_allowlist_enricher, notify_only_responder"),
                         ["lab_allowlist_enricher", "notify_only_responder"])
        self.assertEqual(plugins.load_plugins("../server,os.path,soar.safety"), [])

    def test_enricher_results_reach_the_pipeline(self):
        plugins.load_plugins("lab_allowlist_enricher")
        from simulator.attack_simulator import simulate_t1003_lsass_dump
        from soar.soar_engine import SOAROrchestrator
        incident = SOAROrchestrator().process_event(simulate_t1003_lsass_dump())
        self.assertIn("lab_allowlist", incident["threat_intel"]["plugins"])

    def test_failing_enricher_is_isolated(self):
        @plugins.register_enricher("broken_test_enricher")
        def broken(event):
            raise RuntimeError("feed down")
        try:
            self.assertEqual(plugins.run_enrichers({})["broken_test_enricher"]["status"], "ERROR")
        finally:
            plugins.ENRICHERS.pop("broken_test_enricher")

    def test_plugin_responder_still_needs_approval_and_honours_kill_switch(self):
        plugins.load_plugins("notify_only_responder")
        from soar.action_tiers import requires_approval
        self.assertTrue(requires_approval("NOTIFY_ASSET_OWNER"))
        engine = ResilientContainmentEngine()
        staged = engine.execute_containment(
            action_type="NOTIFY_ASSET_OWNER", target_host="WIN-WORKSTATION09", target_ip="10.0.0.45",
            target_user="CORP\j.doe", pid=None, process_name=None, execution_intent="PENDING_APPROVAL")
        engine.safety.engage_kill_switch("lead", "test")
        self.assertEqual(engine.approve_action(staged["action_id"], approver="a")["status"], "ERROR")
        engine.safety.release_kill_switch("lead", "test")
        engine.approve_action(staged["action_id"], approver="a")
        self.assertIn("Would notify the owner", staged["execution_log"])


if __name__ == "__main__":
    unittest.main()
