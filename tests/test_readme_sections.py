"""README must keep the sections that frame what the lab can and cannot show."""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def readme():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        return fh.read()


class TestReadmeSections(unittest.TestCase):

    def test_limitations_section_present(self):
        text = readme()
        self.assertIn("## ⚠️ Limitations", text)
        self.assertIn("Responders are simulated", text)
        self.assertIn("Telemetry is synthetic", text)


if __name__ == "__main__":
    unittest.main()
