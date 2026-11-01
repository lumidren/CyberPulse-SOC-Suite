"""'What I missed' report stays current (roadmap F30)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.what_i_missed import NOT_VERIFIED, REPORT, render  # noqa: E402


class TestWhatIMissed(unittest.TestCase):

    def test_committed_report_is_current(self):
        with open(REPORT, encoding="utf-8") as fh:
            self.assertEqual(fh.read().replace("\r\n", "\n"), render(), "run: python scripts/what_i_missed.py")

    def test_lists_every_section(self):
        body = render()
        for heading in ("## 1. Bypasses", "## 2. Techniques with no rule", "## 3. Attacks reported",
                        "## 4. Signals that do not work yet", "## 5. Never verified"):
            self.assertIn(heading, body)
        self.assertGreater(len(NOT_VERIFIED), 0)


if __name__ == "__main__":
    unittest.main()
