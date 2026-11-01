"""Post-incident review templates (roadmap F77)."""

import os
import sys
import unittest
from datetime import datetime, timezone

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_chain import run_chain  # noqa: E402
from soar.post_incident import review_markdown  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


class TestPostIncidentReview(unittest.TestCase):

    def test_review_is_prefilled_from_records(self):
        orchestrator = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        run_chain(orchestrator, start=datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc))
        case_id = max(orchestrator.case_manager.cases.values(), key=lambda c: len(c["incidents"]))["case_id"]
        incident = orchestrator.dfir_engine.incidents[orchestrator.case_manager.cases[case_id]["incidents"][0]]
        action_id = incident["containment_action"]["action_id"]
        orchestrator.containment_engine.reject_action(action_id, approver="lead_a", reason="contained manually")
        orchestrator.appeals.open(incident, "alice", "wrong_action", "isolation would have stopped payroll")
        md = review_markdown(orchestrator, case_id)
        for expected in ("# Post-incident review", "SIMULATED", "## Timeline", "Credential Access",
                         "lead_a", "containment.reject", "isolation would have stopped payroll", "## Actions"):
            self.assertIn(expected, md)
        self.assertIsNone(review_markdown(orchestrator, "CASE-missing"))

    def test_blank_template_exists(self):
        with open(os.path.join(ROOT, "docs", "templates", "POST_INCIDENT_REVIEW.md"), encoding="utf-8") as fh:
            self.assertIn("Blameless review", fh.read())


if __name__ == "__main__":
    unittest.main()
