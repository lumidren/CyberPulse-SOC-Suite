"""
Lightweight Backend & API Server for SOC SIEM/SOAR Laboratory
Runs with 0 external dependencies (uses standard library http.server)
"""

import http.server
import json
import os
import sys
import socketserver

# Ensure project root in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simulator.attack_simulator import (
    simulate_t1003_lsass_dump,
    simulate_t1110_brute_force,
    simulate_t1053_scheduled_task,
    simulate_t1059_powershell_execution,
    generate_random_attack
)
from soar.soar_engine import SOAROrchestrator

orchestrator = SOAROrchestrator()
PORT = 5000
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

class SOCHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_POST(self):
        if self.path == "/api/simulate":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else "{}"
            try:
                data = json.loads(body)
            except:
                data = {}

            attack_type = data.get("type", "random")

            if attack_type == "t1003":
                evt = simulate_t1003_lsass_dump()
            elif attack_type == "t1110":
                evt = simulate_t1110_brute_force()
            elif attack_type == "t1053":
                evt = simulate_t1053_scheduled_task()
            elif attack_type == "t1059":
                evt = simulate_t1059_powershell_execution()
            else:
                evt = generate_random_attack()

            processed_alert = orchestrator.process_event(evt)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "SUCCESS", "alert": processed_alert}).encode('utf-8'))
        else:
            self.send_error(404, "Endpoint Not Found")

    def do_GET(self):
        if self.path == "/api/alerts":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"alerts": orchestrator.alert_history}).encode('utf-8'))
        else:
            super().do_GET()

def run_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), SOCHttpRequestHandler) as httpd:
        print(f"[*] AEGIS SOC Laboratory Dashboard Running at http://localhost:{PORT}")
        print(f"[*] Serving web UI from {WEB_DIR}")
        print("[*] Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down SOC Server.")

if __name__ == "__main__":
    run_server()
