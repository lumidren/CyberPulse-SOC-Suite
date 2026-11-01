"""PDF export for incident reports (roadmap F65)."""

import os
import re
import sys
import threading
import unittest
import urllib.request

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_simulator import simulate_t1003_lsass_dump  # noqa: E402
from soar.pdf_report import build_pdf, incident_pdf  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


def check_structure(test, pdf):
    test.assertTrue(pdf.startswith(b"%PDF-1.4"))
    test.assertTrue(pdf.rstrip().endswith(b"%%EOF"))
    startxref = int(re.search(rb"startxref\n(\d+)", pdf).group(1))
    test.assertTrue(pdf[startxref:].startswith(b"xref"))
    count = int(re.search(rb"xref\n0 (\d+)", pdf).group(1))
    offsets = [int(m) for m in re.findall(rb"(\d{10}) 00000 n ", pdf)]
    test.assertEqual(len(offsets), count - 1)
    for number, offset in enumerate(offsets, 1):
        test.assertTrue(pdf[offset:].startswith(f"{number} 0 obj".encode()), f"object {number} offset")
    for m in re.finditer(rb"/Length (\d+) >>\nstream\n", pdf):
        body = pdf[m.end():m.end() + int(m.group(1))]
        test.assertTrue(pdf[m.end() + int(m.group(1)):].startswith(b"\nendstream"))
        test.assertTrue(body)


class TestPdfReport(unittest.TestCase):

    def test_writer_structure_escaping_and_paging(self):
        blocks = [("title", "Test (with) parens \\ backslash")] + [("body", f"line {i} " + "word " * 30) for i in range(200)]
        pdf = build_pdf(blocks, title="t")
        check_structure(self, pdf)
        self.assertIn(b"Test \\(with\\) parens", pdf)
        self.assertGreater(pdf.count(b"/Type /Page "), 3, "long reports span several pages")

    def test_incident_pdf_is_masked_and_marked_simulated(self):
        orchestrator = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        incident = orchestrator.process_event(simulate_t1003_lsass_dump())
        pdf = incident_pdf(incident, custody=orchestrator.custody.logs[incident["incident_id"]])
        check_structure(self, pdf)
        self.assertIn(b"SIMULATED", pdf)
        self.assertIn(b"Chain of custody", pdf)
        self.assertNotIn(b"Administrator", pdf, "account names are masked")
        self.assertNotIn(b"/JavaScript", pdf)

    def test_endpoint(self):
        import server
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            inc_id = server.orchestrator.process_event(simulate_t1003_lsass_dump())["incident_id"]
            req = urllib.request.Request(f"http://127.0.0.1:{httpd.server_address[1]}/api/incidents/{inc_id}/report.pdf",
                                         headers={"X-API-Key": server.API_KEY})
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.assertEqual(resp.headers["Content-Type"], "application/pdf")
                check_structure(self, resp.read())
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
