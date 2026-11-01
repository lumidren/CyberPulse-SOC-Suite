"""Red vs blue scenario pack: safe to load, replays as expected, report current (roadmap F99)."""

import copy
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import yaml

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.run_scenarios import REPORT, render, results  # noqa: E402
from simulator.lab_guard import LabModeRequired  # noqa: E402
from simulator.scenario_pack import DEFAULT_PACK, ScenarioError, load, load_pack, run  # noqa: E402


def scenario(name="rvb-01.yml"):
    with open(os.path.join(DEFAULT_PACK, name), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


class TestScenarioPack(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, doc):
        path = os.path.join(self.tmp, "custom.yml")
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh)
        return path

    def test_every_step_ends_as_its_scenario_expects(self):
        runs = results()
        self.assertGreaterEqual(len(runs), 4)
        for r in runs:
            for s in r["steps"]:
                self.assertTrue(s["as_expected"], f"{s['id']}: expected {s['expected']}, got {s['outcome']}")
        # The pack is honest about known gaps: at least one scenario is a red win
        self.assertTrue(any(r["red"] > r["blue"] for r in runs))

    def test_committed_report_is_current(self):
        with open(REPORT, encoding="utf-8") as fh:
            self.assertEqual(fh.read().replace("\r\n", "\n"), render(results()),
                             "run: CYBERPULSE_LAB_MODE=true python scripts/run_scenarios.py")

    def test_refuses_without_lab_mode(self):
        with mock.patch.dict(os.environ, {"CYBERPULSE_LAB_MODE": "false"}):
            with self.assertRaises(LabModeRequired):
                run(load_pack()[0])

    def test_refuses_hosts_and_addresses_outside_the_lab(self):
        cases = {
            "unknown host": lambda e: e.update(computer_name="PROD-SQL-01"),
            "public address": lambda e: e.update(source_ip="8.8.8.8"),
            "public address in details": lambda e: e.setdefault("details", {}).update(DestinationIp="8.8.8.8"),
            "missing event_id": lambda e: e.pop("event_id"),
        }
        for label, change in cases.items():
            with self.subTest(label):
                doc = copy.deepcopy(scenario())
                change(doc["steps"][0]["events"][0])
                with self.assertRaises(ScenarioError):
                    load(self.write(doc))

    def test_refuses_real_accounts_and_password_material_in_credential_attacks(self):
        for change in ({"TargetUserName": "j.smith"}, {"CredentialMaterial": "placeholder-not-a-password"}):
            with self.subTest(change):
                doc = copy.deepcopy(scenario("rvb-02.yml"))
                event = doc["steps"][0]["events"][0]
                event["details"].update(change)
                if "TargetUserName" in change:
                    event["user"] = "CORP\\j.smith"
                with self.assertRaises(ScenarioError):
                    load(self.write(doc))

    def test_requires_synthetic_flag_and_blue_expectation(self):
        doc = copy.deepcopy(scenario())
        doc["synthetic"] = False
        with self.assertRaises(ScenarioError):
            load(self.write(doc))
        doc = copy.deepcopy(scenario())
        doc["steps"][0]["blue"]["expect"] = "maybe"
        with self.assertRaises(ScenarioError):
            load(self.write(doc))

    def test_replay_opens_no_incident(self):
        from soar.soar_engine import SOAROrchestrator
        made = []

        def factory():
            made.append(SOAROrchestrator(policy_mode="DRY_RUN"))
            return made[-1]
        run(load_pack()[0], orchestrator_factory=factory)
        self.assertEqual(made[0].dfir_engine.incidents, {})
        self.assertEqual(made[0].containment_engine.action_registry, {})


if __name__ == "__main__":
    unittest.main()
