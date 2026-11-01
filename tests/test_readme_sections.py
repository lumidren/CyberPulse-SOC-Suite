"""README must keep the sections that frame what the lab can and cannot show."""

import os
import re
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

    def test_privacy_section_present(self):
        self.assertIn("## 🔏 Privacy", readme())
        with open(os.path.join(ROOT, "docs", "PRIVACY.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("## What is stored", text)
        self.assertIn("## What leaves the machine", text)
        self.assertIn("## External threat-intel enrichment: what leaves your environment", text)

    def test_third_party_credits_and_map_attribution(self):
        self.assertIn("docs/THIRD_PARTY_NOTICES.md", readme())
        with open(os.path.join(ROOT, "docs", "THIRD_PARTY_NOTICES.md"), encoding="utf-8") as fh:
            notices = fh.read()
        for name in ["Wazuh", "Sysmon", "Sigma", "pfSense", "Leaflet", "OpenStreetMap"]:
            self.assertIn(name, notices)
        with open(os.path.join(ROOT, "web", "app.js"), encoding="utf-8") as fh:
            js = fh.read()
        self.assertIn("attributionControl: true", js)
        self.assertIn("OpenStreetMap", js)

    def test_at_a_glance_figures_match_the_metrics_page(self):
        glance = readme().split("<!-- glance:start -->")[1].split("<!-- glance:end -->")[0]
        with open(os.path.join(ROOT, "docs", "METRICS.md"), encoding="utf-8") as fh:
            metrics = fh.read()
        figures = re.findall(r"(?<![\w./-])(\d+/\d+|\d+\.\d+)(?![\w/])", glance)
        self.assertTrue({"60/60", "0/600", "0.335", "11/16", "27/36"} <= set(figures))
        self.assertEqual([f for f in figures if f not in metrics], [])
        singles = re.search(r"\| Single-event Sigma rules \| (\d+) \|", metrics).group(1)
        correlations = re.search(r"\| Correlation rules \| (\d+) \|", metrics).group(1)
        suppressed = re.search(r"(\d+) matches suppressed", metrics).group(1)
        self.assertIn(f"{singles} single-event rules + {correlations} correlations", glance)
        self.assertIn(f"({suppressed} suppressed by exceptions)", glance)

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
