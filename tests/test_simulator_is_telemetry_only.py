"""
The attack simulator must only *describe* attacks, never perform them.

Static checks (AST) prove the simulator modules cannot spawn processes, open
other processes' memory, touch the registry, load native code or open network
connections. A runtime check confirms the LSASS scenario returns a plain
telemetry record.
"""

import ast
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")  # tests run in a declared lab

SIMULATOR_MODULES = [
    "simulator/attack_simulator.py",
    "simulator/benign_baseline.py",
    "simulator/lab_guard.py",
    "simulator/purple_team_runner.py",
]

FORBIDDEN_IMPORTS = {
    "subprocess", "ctypes", "socket", "winreg", "_winapi", "multiprocessing",
    "win32api", "win32con", "win32process", "win32security", "pywintypes",
    "urllib", "http", "requests", "paramiko", "winrm", "pypsexec", "impacket",
}
FORBIDDEN_CALLS = {"system", "popen", "spawnl", "spawnv", "execv", "execl", "startfile", "ReadProcessMemory", "OpenProcess"}


class TestSimulatorIsTelemetryOnly(unittest.TestCase):

    def _tree(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return ast.parse(fh.read(), filename=rel)

    def test_no_dangerous_imports(self):
        for rel in SIMULATOR_MODULES:
            for node in ast.walk(self._tree(rel)):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split(".")[0]]
                for name in names:
                    self.assertNotIn(name, FORBIDDEN_IMPORTS, f"{rel} imports {name}")

    def test_no_process_or_memory_calls(self):
        for rel in SIMULATOR_MODULES:
            for node in ast.walk(self._tree(rel)):
                if isinstance(node, ast.Call):
                    fn = node.func
                    name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                    self.assertNotIn(name, FORBIDDEN_CALLS, f"{rel} calls {name}()")

    def test_lsass_scenario_returns_plain_telemetry(self):
        from simulator.attack_simulator import simulate_t1003_lsass_dump
        event = simulate_t1003_lsass_dump()
        self.assertIsInstance(event, dict)
        self.assertEqual(event["event_id"], 10)  # a Sysmon ProcessAccess *record*, nothing more
        self.assertTrue(event["details"]["TargetImage"].endswith("lsass.exe"))
        # No credential material is ever produced
        flat = str(event).lower()
        for marker in ["password", "ntlm", "hash:", "sekurlsa", "logonpasswords"]:
            self.assertNotIn(marker, flat)


class TestNoShippedAttackTooling(unittest.TestCase):

    def test_atomic_manifests_are_reference_only(self):
        import yaml
        folder = os.path.join(ROOT, "simulator", "atomic_tests")
        for name in os.listdir(folder):
            with open(os.path.join(folder, name), encoding="utf-8") as fh:
                manifest = yaml.safe_load(fh)
            self.assertEqual(manifest["execution"], "none", name)
            self.assertNotIn("atomic_tests", manifest, name)   # no runnable test definitions
            self.assertNotIn("executor", str(manifest), name)
            self.assertIn("emulated_by", manifest, name)


if __name__ == "__main__":
    unittest.main()
