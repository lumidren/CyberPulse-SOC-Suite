"""Credential redaction in stored telemetry and logs (roadmap E44)."""

import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar.redaction import REDACTED, RedactingFilter, redact  # noqa: E402

FAKE_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"  # assembled at runtime so secret scanners don't flag the fixture

SECRET_CASES = [
    (r"net use \\fs01\share Winter2026! /user:CORP\j.doe", "Winter2026!"),
    ("net user svc_sql N3wPassw0rd /add", "N3wPassw0rd"),
    ("sqlcmd -S db01 -U sa -P Sup3rS3cret", "Sup3rS3cret"),
    ("runas.exe /user:x cmd --password=hunter22", "hunter22"),
    ("curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc' https://api", "eyJhbGciOiJIUzI1NiJ9.abc"),
    ("Server=db;User Id=sa;Password=P@ssw0rd123;", "P@ssw0rd123"),
    ("git clone https://deploy:ghtoken123abc@git.example/repo", "ghtoken123abc"),
    ("Administrator:Password123!", "Password123!"),
    ("aws configure set aws_access_key_id " + FAKE_AWS_KEY, FAKE_AWS_KEY),
]

SAFE_CASES = [
    r"powershell.exe -NoProfile -File C:\Scripts\inventory.ps1",
    r"reg query HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "MSSQLSvc/sql01.corp.local:1433",
    "Invoke-WebRequest https://updates.example.com/agent.msi",
    "2026-10-31T12:00:00Z",
]


class TestRedaction(unittest.TestCase):

    def test_secrets_are_redacted(self):
        for text, secret in SECRET_CASES:
            out = redact(text)
            self.assertNotIn(secret, out, text)
            self.assertIn(REDACTED, out, text)

    def test_ordinary_command_lines_untouched(self):
        for text in SAFE_CASES:
            self.assertEqual(redact(text), text)

    def test_log_filter_redacts(self):
        record = logging.LogRecord("t", logging.INFO, __file__, 1, "cmd=%s", ("net user bob S3cretPass1",), None)
        RedactingFilter().filter(record)
        self.assertNotIn("S3cretPass1", record.getMessage())

    def test_ingested_command_line_stored_redacted(self):
        from soar.syslog_receiver import WebhookIngestionHandler
        res = WebhookIngestionHandler().handle_ingest({
            "event_id": 1, "computer_name": "WIN-WORKSTATION09", "source_ip": "10.0.0.45",
            "details": {"CommandLine": r"net use \\fs01\c$ Winter2026! /user:CORP\j.doe"}})
        self.assertNotIn("Winter2026!", res["normalized_event"]["details"]["CommandLine"])

    def test_evidence_memory_strings_redacted(self):
        from soar.evidence_collector import VolatileEvidenceCollector
        pkg = VolatileEvidenceCollector().collect_volatile_evidence({"host": "x"}, None)
        self.assertFalse(any("Password123!" in s for s in pkg["memory_strings"]))


if __name__ == "__main__":
    unittest.main()
