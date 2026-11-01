"""Shuffle / n8n hand-off via a signed webhook (roadmap F40)."""

import hashlib
import hmac
import json
import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_simulator import simulate_t1003_lsass_dump  # noqa: E402
from soar.orchestrator_hook import OrchestratorWebhook  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


class Capture:
    def __init__(self):
        self.calls = []

    def __call__(self, url, body, headers, timeout=10):
        self.calls.append((url, body, headers))
        return 200


class TestOrchestratorHook(unittest.TestCase):

    def setUp(self):
        self.incident = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED").process_event(simulate_t1003_lsass_dump())

    def test_off_by_default(self):
        self.assertEqual(self.incident["orchestrator_dispatch"]["status"], "DISABLED")

    def test_lab_webhook_gets_signed_internal_payload(self):
        cap = Capture()
        hook = OrchestratorWebhook(url="http://10.0.1.40:5678/webhook/cp", secret="s3", post=cap)
        self.assertEqual(hook.send(self.incident)["scope"], "internal")
        url, body, headers = cap.calls[0]
        expected = "sha256=" + hmac.new(b"s3", headers["X-CyberPulse-Timestamp"].encode() + b"." + body,
                                        hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-CyberPulse-Signature"], expected)
        payload = json.loads(body)
        self.assertTrue(payload["incident"]["approve_url"].endswith("/approve"))

    def test_external_webhook_gets_no_internal_identifiers(self):
        cap = Capture()
        hook = OrchestratorWebhook(url="https://example.app.n8n.cloud/webhook/cp", secret="s3", post=cap)
        result = hook.send(self.incident)
        self.assertEqual(result["scope"], "external")
        body = cap.calls[0][1].decode()
        for secret in ("WIN-WORKSTATION09", "j.doe", "finance_admin"):
            self.assertNotIn(secret, body)

    def test_errors_never_break_the_pipeline(self):
        def boom(*a, **k):
            raise TimeoutError("slow")
        self.assertEqual(OrchestratorWebhook(url="http://10.0.1.40/x", secret="s", post=boom).send(self.incident)["status"],
                         "ERROR")


if __name__ == "__main__":
    unittest.main()
