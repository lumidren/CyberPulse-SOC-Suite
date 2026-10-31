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

    def test_lab_only_warning_present(self):
        self.assertIn("**⚠️ LAB USE ONLY.**", readme())
        for rel in ["simulator/attack_simulator.py", "simulator/attack_chain.py", "simulator/purple_team_runner.py"]:
            with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
                self.assertIn("*** LAB USE ONLY ***", fh.read(), rel)

    def test_human_oversight_section_present(self):
        text = readme()
        self.assertIn("## 🧑‍⚖️ Human Oversight", text)
        self.assertIn("not to replace them", text)


class TestDashboardLabelsSimulatedData(unittest.TestCase):

    def test_incident_views_render_simulated_badge(self):
        with open(os.path.join(ROOT, "web", "app.js"), encoding="utf-8") as fh:
            js = fh.read()
        self.assertIn("function simulatedBadge(inc)", js)
        self.assertIn("inc.simulated", js)
        self.assertGreaterEqual(js.count("simulatedBadge("), 3)  # definition + table row + dossier


class TestSimulatedIncidentLabels(unittest.TestCase):

    def test_incident_and_triage_docs_are_marked_simulated(self):
        paths = [
            "docs/INCIDENT_REPORT_T1003.md",
            "docs/INCIDENT_REPORT_T1110.md",
            "docs/triage/TRIAGE_CASE_STUDY_01_LSASS_FALSE_ALARM.md",
            "docs/triage/TRIAGE_CASE_STUDY_02_STEALTH_DEFENDER_TAMPER.md",
        ]
        for rel in paths:
            with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("SIMULATED INCIDENT", text, rel)
            self.assertIn("(SIMULATED)", text, rel)


if __name__ == "__main__":
    unittest.main()
