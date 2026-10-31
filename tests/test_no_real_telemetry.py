"""Real telemetry, captures, dumps and logs must never be tracked in git (roadmap E46)."""

import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORBIDDEN = re.compile(r"(?i)\.(evtx|etl|pcap|pcapng|dmp|mdmp|log)$|(^|/)(logs|telemetry|captures)/|dossier_INC-")


class TestNoRealTelemetry(unittest.TestCase):

    def test_no_telemetry_files_tracked(self):
        try:
            tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")
        offenders = [f for f in tracked.splitlines() if FORBIDDEN.search(f)]
        self.assertEqual(offenders, [], f"Real telemetry/log files are tracked: {offenders}")

    def test_gitignore_blocks_telemetry_formats(self):
        with open(os.path.join(ROOT, ".gitignore"), encoding="utf-8") as fh:
            ignore = fh.read()
        for pattern in ["*.evtx", "*.pcap", "*.pcapng", "*.dmp", "*.log", "logs/"]:
            self.assertIn(pattern, ignore)


if __name__ == "__main__":
    unittest.main()
