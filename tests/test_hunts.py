"""Saved hunts and queries (roadmap F60)."""

import json
import os
import sys
import tempfile
import threading
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.hunts import HuntStore  # noqa: E402


class TestHuntStore(unittest.TestCase):

    def test_add_validate_persist_delete(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "hunts.json")
            store = HuntStore(path)
            hunt = store.add("Rclone exfil", "rclone", "alice")["hunt"]
            self.assertEqual(store.add("rclone exfil", "x y", "bob")["status"], "ERROR", "names are unique")
            self.assertEqual(store.add("bad<name>", "query", "bob")["status"], "ERROR")
            self.assertEqual(store.add("ok", "q", "bob")["status"], "ERROR", "query too short")
            self.assertEqual(store.add("ok", "query", "")["status"], "ERROR", "owner required")
            self.assertEqual([h["name"] for h in HuntStore(path).list()], ["Rclone exfil"], "survives restart")
            store.mark_run(hunt["id"])
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)[0]["runs"], 1)
            self.assertEqual(store.delete(hunt["id"], "alice")["status"], "SUCCESS")
            self.assertEqual(HuntStore(path).list(), [])


class TestHuntApi(unittest.TestCase):

    def test_save_and_run(self):
        import server
        from simulator.attack_simulator import simulate_t1003_lsass_dump
        from tests.test_server_api import _request
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            server.orchestrator.process_event(simulate_t1003_lsass_dump())
            status, body = _request(base, "/api/hunts", method="POST",
                                    body={"name": "LSASS access api test", "query": "lsass", "analyst": "alice"})
            self.assertEqual(status, 200)
            status, run = _request(base, f"/api/hunts/{body['hunt']['id']}/run")
            self.assertEqual(status, 200)
            self.assertGreaterEqual(run["total"], 1)
            status, _ = _request(base, f"/api/hunts/{body['hunt']['id']}/delete", method="POST", body={"analyst": "alice"})
            self.assertEqual(status, 200)
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
