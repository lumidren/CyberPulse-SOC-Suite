"""Injection-safe responder command construction (roadmap E70/E71)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar import command_builder as cmd  # noqa: E402
from soar.resilient_containment import ResilientContainmentEngine  # noqa: E402

HOSTILE = ["10.0.0.5; rm -rf /", "j.doe' -Enabled $true; Remove-ADUser x '", "$(whoami)", "a b", "x`y", "\\Task & calc"]


class TestValidators(unittest.TestCase):

    def test_hostile_values_rejected(self):
        for value in HOSTILE:
            for validator in (cmd.valid_ip, cmd.valid_hostname, cmd.valid_account, cmd.valid_task_name):
                with self.assertRaises(cmd.CommandValidationError, msg=f"{validator.__name__}({value!r})"):
                    validator(value)

    def test_legitimate_values_accepted(self):
        self.assertEqual(cmd.valid_ip("203.0.113.7"), "203.0.113.7")
        self.assertEqual(cmd.valid_account("CORP\\j.doe"), "CORP\\j.doe")
        self.assertEqual(cmd.valid_task_name("\\Microsoft\\Windows\\SystemHealthUpdate"),
                         "\\Microsoft\\Windows\\SystemHealthUpdate")
        self.assertEqual(cmd.valid_pid(4812), 4812)

    def test_builders_return_argv_lists(self):
        argv = cmd.iptables_drop("203.0.113.7")
        self.assertIsInstance(argv, list)
        self.assertIn("203.0.113.7/32", argv)
        self.assertEqual(cmd.aws_delete_deny_policy("CORP\\contractor_temp")[4], "contractor_temp")
        self.assertEqual(cmd.schtasks("disable", "\\Vendor\\Update")[-1], "/DISABLE")


class TestEngineRefusesInvalidTargets(unittest.TestCase):

    def test_hostile_ip_flags_action_instead_of_building_command(self):
        engine = ResilientContainmentEngine()
        act = engine.execute_containment(
            action_type="BLOCK_SOURCE_IP_FIREWALL", target_host="CORP-RDP-GW01", target_ip="1.2.3.4; reboot",
            target_user="lab.admin", pid=None, process_name=None)
        self.assertEqual(act["status"], "FLAGGED_FOR_MANUAL_REVIEW")
        self.assertIn("Refused to build responder command", act["execution_log"])
        self.assertEqual(engine.blocked_ips, set())

    def test_valid_block_records_argv(self):
        engine = ResilientContainmentEngine()
        act = engine.execute_containment(
            action_type="BLOCK_SOURCE_IP_FIREWALL", target_host="CORP-RDP-GW01", target_ip="203.0.113.7",
            target_user="lab.admin", pid=None, process_name=None)
        self.assertEqual(act["execution_argv"][0], "iptables")
        self.assertIsInstance(act["rollback_plan"]["argv"], list)


if __name__ == "__main__":
    unittest.main()
