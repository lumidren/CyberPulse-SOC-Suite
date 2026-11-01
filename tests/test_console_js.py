"""Static checks on the console script (web/app.js)."""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestConsoleScript(unittest.TestCase):

    def test_safe_json_parses_the_response_instead_of_calling_itself(self):
        # Regression: a bulk rename once turned `res.json()` inside safeJson into `safeJson(res)`,
        # recursing forever and breaking every panel of the console.
        with open(os.path.join(ROOT, "web", "app.js"), encoding="utf-8") as fh:
            script = fh.read()
        body = re.search(r"async function safeJson\(res\) \{(.*?)\n\}", script, re.S).group(1)
        self.assertNotIn("safeJson(", body)
        self.assertIn("res.json()", body)


class TestCacheHeaders(unittest.TestCase):

    def test_console_files_revalidate_and_api_is_not_stored(self):
        import sys
        import threading
        import urllib.request
        sys.path.insert(0, ROOT)
        from server import create_server
        httpd = create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            with urllib.request.urlopen(base + "/login.js", timeout=10) as resp:
                self.assertEqual(resp.headers["Cache-Control"], "no-cache")
            with urllib.request.urlopen(base + "/healthz", timeout=10) as resp:
                self.assertEqual(resp.headers["Cache-Control"], "no-cache")
            from server import API_KEY
            req = urllib.request.Request(base + "/api/version", headers={"X-API-Key": API_KEY})
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.assertEqual(resp.headers["Cache-Control"], "no-store")
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
