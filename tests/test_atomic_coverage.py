"""Atomic Red Team mapping, reference-only (roadmap F21)."""

import json
import os
import shutil
import sys
import tempfile
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import yaml  # noqa: E402

from scripts.atomic_coverage import build, load_atomics, load_manifests  # noqa: E402
from simulator import attack_simulator  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402

MARKER = "this-command-text-must-never-be-copied"


class TestAtomicCoverage(unittest.TestCase):

    def setUp(self):
        # Minimal fixture in the upstream layout: atomics/<T>/<T>.yaml
        self.dir = tempfile.mkdtemp()
        for tid, platforms in (("T1059.001", ["windows"]), ("T1218.011", ["windows"]), ("T1543.002", ["linux"])):
            os.makedirs(os.path.join(self.dir, tid))
            with open(os.path.join(self.dir, tid, f"{tid}.yaml"), "w", encoding="utf-8") as fh:
                yaml.safe_dump({"attack_technique": tid, "display_name": "fixture", "atomic_tests": [
                    {"name": f"fixture test for {tid}", "auto_generated_guid": "00000000-0000-0000-0000-000000000000",
                     "supported_platforms": platforms, "executor": {"name": "command_prompt", "command": MARKER}}]}, fh)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_maps_rules_and_emulations_without_commands(self):
        rows = {r["technique"]: r for r in build(load_atomics(self.dir, "windows"))}
        self.assertNotIn("T1543.002", rows, "platform filter")
        self.assertIn("SOC-RULE-004", rows["T1059.001"]["rules"])
        self.assertTrue(rows["T1059.001"]["emulated_by"])
        self.assertIn("SOC-RULE-017", rows["T1218.011"]["rules"])
        self.assertIsNone(rows["T1218.011"]["emulated_by"])
        self.assertNotIn(MARKER, json.dumps(rows))

    def test_every_manifest_emulation_fires_its_expected_rule(self):
        orchestrator = SOAROrchestrator(policy_mode="DRY_RUN")
        for tid, manifest in load_manifests().items():
            generator = getattr(attack_simulator, manifest["emulated_by"].split("::")[1])
            event = generator()
            self.assertEqual(event["technique_id"], tid)
            match = orchestrator.evaluate_detection(event)
            self.assertIsNotNone(match, tid)
            self.assertEqual(match["rule_id"], manifest["expected_rule"], tid)


if __name__ == "__main__":
    unittest.main()
