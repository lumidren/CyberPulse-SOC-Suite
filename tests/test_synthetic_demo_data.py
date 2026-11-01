"""Demo data must be synthetic: no real public IPs or real companies labelled malicious (E54)."""

import ipaddress
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")  # tests run in a declared lab

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def is_synthetic(ip):
    addr = ipaddress.ip_address(ip)
    return not addr.is_global or any(addr in n for n in DOC_NETS)


class TestSyntheticDemoData(unittest.TestCase):

    def test_threat_intel_fixture_uses_documentation_ips(self):
        from soar.soar_engine import THREAT_INTEL_CACHE
        for key, entry in THREAT_INTEL_CACHE.items():
            if re.match(r"^[0-9.]+$", key):
                self.assertTrue(is_synthetic(key), key)
                self.assertIn("Fictional", entry["isp"], key)

    def test_attack_scenarios_use_synthetic_source_ips(self):
        from simulator.attack_simulator import SCRIPTED_GENERATORS
        for name, gen in SCRIPTED_GENERATORS:
            self.assertTrue(is_synthetic(gen()["source_ip"]), name)

    def test_no_real_public_ips_in_demo_files(self):
        ip_re = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
        allowed_public = {"8.8.8.8"}  # well-known resolver used only as an example/probe target
        offenders = []
        for folder in ("simulator", "soar", "web", "docs", "integrations", "scenarios"):
            for dirpath, _dirs, files in os.walk(os.path.join(ROOT, folder)):
                for name in files:
                    if not name.endswith((".py", ".md", ".json", ".html", ".js", ".yml")):
                        continue
                    with open(os.path.join(dirpath, name), encoding="utf-8", errors="ignore") as fh:
                        for ip in ip_re.findall(fh.read()):
                            try:
                                if not is_synthetic(ip) and ip not in allowed_public:
                                    offenders.append(f"{name}: {ip}")
                            except ValueError:
                                pass
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
