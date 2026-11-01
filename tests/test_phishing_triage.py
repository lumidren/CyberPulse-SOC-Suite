"""Phishing triage: header and URL analysis (roadmap F46)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.phishing_triage import defang, lookalike_of, triage  # noqa: E402

ORG = ["corp.example"]


class TestPhishingTriage(unittest.TestCase):

    def test_clean_internal_mail_scores_low(self):
        r = triage({"SenderFromAddress": "it@corp.example", "AuthenticationResults": "spf=pass dkim=pass dmarc=pass",
                    "Urls": ["https://intranet.corp.example/news"]}, ORG, [])
        self.assertEqual((r["score"], r["verdict"]), (0, "no strong indicators"))

    def test_classic_phish_scores_high_with_reasons(self):
        r = triage({"SenderFromAddress": "ceo@c0rp.example", "SenderDisplayName": "Jane Boss",
                    "ReplyToAddress": "jane.boss@gmail.example", "AuthenticationResults": "spf=fail dkim=none dmarc=fail",
                    "Urls": ["http://198.51.100.23/login", "https://bit.ly/x1"]}, ORG, ["jane boss"])
        reasons = " | ".join(f["reason"] for f in r["findings"])
        for expected in ("DMARC fail", "Reply-To", "imitates corp.example", "watched person", "raw IP host", "URL shortener"):
            self.assertIn(expected, reasons)
        self.assertEqual(r["verdict"], "likely phishing")
        self.assertTrue(all("[.]" in u["url"] for u in r["urls"]), "URLs are defanged")

    def test_lookalikes(self):
        self.assertEqual(lookalike_of("corp-example.com", ORG), "corp.example")
        self.assertEqual(lookalike_of("c0rp.example", ORG), "corp.example")
        self.assertEqual(lookalike_of("corrp.example", ORG), "corp.example")
        self.assertEqual(lookalike_of("xn--crp-qma.example", ORG), "corp.example")
        self.assertIsNone(lookalike_of("corp.example", ORG))
        self.assertIsNone(lookalike_of("github.com", ORG))

    def test_display_name_with_foreign_address(self):
        r = triage({"SenderFromAddress": "x@mailer.example.net",
                    "SenderDisplayName": "payroll@corp.example via Mailer"}, ORG, [])
        self.assertIn("display name shows another address", r["findings"][0]["reason"])

    def test_defang(self):
        self.assertEqual(defang("https://evil.example/a.b"), "hxxps://evil[.]example/a[.]b")

    def test_pipeline_attaches_triage_to_email_incidents(self):
        import yaml
        from soar.soar_engine import SOAROrchestrator
        with open(os.path.join(ROOT, "rules", "tests", "email_phishing_reported_or_auth_fail.yml"), encoding="utf-8") as fh:
            event = yaml.safe_load(fh)["positive"][1]["event"]
        incident = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED").process_event(event)
        self.assertIn("DMARC fail", " ".join(f["reason"] for f in incident["phishing_triage"]["findings"]))


if __name__ == "__main__":
    unittest.main()
