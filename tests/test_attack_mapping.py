"""ATT&CK technique IDs must match what the rules detect (roadmap F17)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")  # tests run in a declared lab
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar.sigma_engine import SigmaEngine  # noqa: E402

# Rules whose technique is easy to get wrong
EXPECTED = {
    "win_kerberoasting.yml": "T1558.003",   # Kerberoasting (T1558.001 is Golden Ticket)
    "win_dcsync.yml": "T1003.006",
    "win_lsass_dumping.yml": "T1003.001",
}


class TestAttackMapping(unittest.TestCase):

    def test_known_rules_map_to_the_right_technique(self):
        rules = {os.path.basename(r.file): r for r in SigmaEngine().rules}
        for name, technique in EXPECTED.items():
            self.assertIn(technique, rules[name].technique_ids, name)

    def test_kerberoasting_scenario_uses_t1558_003(self):
        from simulator.attack_simulator import simulate_t1558_kerberoasting
        self.assertEqual(simulate_t1558_kerberoasting()["technique_id"], "T1558.003")


if __name__ == "__main__":
    unittest.main()
