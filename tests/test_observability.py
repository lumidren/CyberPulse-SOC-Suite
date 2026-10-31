"""Structured logging and Prometheus metrics (roadmap F91)."""

import json
import logging
import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")  # tests run in a declared lab
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.observability import JsonLogFormatter, render_prometheus  # noqa: E402


class TestObservability(unittest.TestCase):

    def test_json_log_lines(self):
        record = logging.LogRecord("cyberpulse.audit", logging.INFO, __file__, 1, "LOGIN client=%s", ("127.0.0.1",), None)
        line = json.loads(JsonLogFormatter().format(record))
        self.assertEqual(line["logger"], "cyberpulse.audit")
        self.assertEqual(line["message"], "LOGIN client=127.0.0.1")

    def test_prometheus_exposition(self):
        from simulator.attack_simulator import simulate_t1003_lsass_dump
        from soar.soar_engine import SOAROrchestrator
        orch = SOAROrchestrator()
        orch.process_event(simulate_t1003_lsass_dump())
        text = render_prometheus(orch)
        self.assertIn("# TYPE cyberpulse_incidents gauge", text)
        self.assertIn('cyberpulse_pending_approvals 1', text)
        self.assertIn('cyberpulse_pipeline_latency_ms_bucket{le="+Inf"} 1', text)
        self.assertIn("cyberpulse_kill_switch_engaged 0", text)

    def test_metrics_endpoint_requires_auth(self):
        import threading
        import urllib.error
        import urllib.request
        import server
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{httpd.server_address[1]}/metrics"
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(url, timeout=15)
            self.assertEqual(ctx.exception.code, 401)
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {server.API_KEY}"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                self.assertIn("text/plain", resp.headers["Content-Type"])
                self.assertIn(b"cyberpulse_containment_actions", resp.read())
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_monitoring_examples_parse(self):
        import yaml
        with open(os.path.join(ROOT, "deploy", "monitoring", "prometheus.yml"), encoding="utf-8") as fh:
            self.assertEqual(yaml.safe_load(fh)["scrape_configs"][0]["metrics_path"], "/metrics")
        with open(os.path.join(ROOT, "deploy", "monitoring", "grafana", "cyberpulse-dashboard.json"), encoding="utf-8") as fh:
            exprs = " ".join(t["expr"] for p in json.load(fh)["panels"] for t in p["targets"])
        self.assertIn("cyberpulse_pending_approvals", exprs)


if __name__ == "__main__":
    unittest.main()
