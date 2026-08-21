"""
Enterprise Backend & REST API Server for CyberPulse SOC Operations Platform
Provides endpoints for Incident Triage, DFIR Timelines, SOAR Rollbacks, 
Performance Metrics, Integration Health, Detection Catalogue, and Purple Team Scenarios.
"""

import http.server
import json
import os
import sys
import socketserver
from urllib.parse import urlparse, parse_qs

# Ensure project root in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simulator.attack_simulator import (
    simulate_t1003_lsass_dump,
    simulate_t1110_brute_force,
    simulate_t1053_scheduled_task,
    simulate_t1059_powershell_execution,
    simulate_t1562_defender_tamper,
    simulate_t1486_ransomware_canary,
    generate_random_attack
)
from simulator.purple_team_runner import PurpleTeamRunner, SCENARIOS
from soar.soar_engine import SOAROrchestrator

orchestrator = SOAROrchestrator()
purple_runner = PurpleTeamRunner(orchestrator)
PORT = 5000
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

DETECTION_CATALOGUE = [
    {
        "detection_id": "SOC-RULE-001",
        "title": "LSASS Process Access & Memory Scraping",
        "technique_id": "T1003.001",
        "tactic": "Credential Access",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "data_source": "Sysmon Event ID 10 (ProcessAccess)",
        "sigma_rule": "rules/sigma/win_lsass_dumping.yml",
        "wazuh_rule_id": 100010,
        "automated_response": "WinRM Emergency WFP Host Isolation + PID Termination",
        "delc_document": "docs/lifecycle/DELC-001_LSASS_Memory_Access.md",
        "validation_status": "PASS (100% True-Positive)"
    },
    {
        "detection_id": "SOC-RULE-002",
        "title": "High-Volume RDP Password Brute Force & Spraying",
        "technique_id": "T1110.001",
        "tactic": "Credential Access",
        "severity": "HIGH",
        "confidence": "HIGH",
        "data_source": "Security Event ID 4625 (LogonType 10)",
        "sigma_rule": "rules/sigma/win_brute_force_auth.yml",
        "wazuh_rule_id": 100011,
        "automated_response": "pfSense REST API Perimeter IP Drop",
        "delc_document": "docs/lifecycle/DELC-002_RDP_Authentication_Spraying.md",
        "validation_status": "PASS (100% True-Positive)"
    },
    {
        "detection_id": "SOC-RULE-003",
        "title": "Suspicious Scheduled Task Creation for Persistence",
        "technique_id": "T1053.005",
        "tactic": "Persistence",
        "severity": "HIGH",
        "confidence": "HIGH",
        "data_source": "Security Event ID 4698 (Task Scheduled)",
        "sigma_rule": "rules/sigma/win_scheduled_task_persistence.yml",
        "wazuh_rule_id": 100012,
        "automated_response": "Remote Scheduled Task De-registration",
        "delc_document": "docs/MITRE_COVERAGE_AND_GAPS.md",
        "validation_status": "PASS (100% True-Positive)"
    },
    {
        "detection_id": "SOC-RULE-004",
        "title": "Obfuscated PowerShell Execution Cradle",
        "technique_id": "T1059.001",
        "tactic": "Execution",
        "severity": "HIGH",
        "confidence": "MEDIUM-HIGH",
        "data_source": "Sysmon Event ID 1 (Process Create)",
        "sigma_rule": "rules/sigma/win_powershell_obfuscation.yml",
        "wazuh_rule_id": 100015,
        "automated_response": "Process Tree Kill + AD Account Lockout",
        "delc_document": "docs/MITRE_COVERAGE_AND_GAPS.md",
        "validation_status": "PASS (100% True-Positive)"
    },
    {
        "detection_id": "SOC-RULE-005",
        "title": "Defense Evasion: Windows Defender Real-Time Disabled",
        "technique_id": "T1562.001",
        "tactic": "Defense Evasion",
        "severity": "CRITICAL",
        "confidence": "CRITICAL",
        "data_source": "Sysmon Event ID 1 (Set-MpPreference)",
        "sigma_rule": "rules/sigma/win_defender_tamper.yml",
        "wazuh_rule_id": 100013,
        "automated_response": "Revert Defender Policy + Host Isolation",
        "delc_document": "docs/lifecycle/DELC-003_Windows_Defender_Tampering.md",
        "validation_status": "PASS (100% True-Positive)"
    },
    {
        "detection_id": "SOC-RULE-006",
        "title": "Impact: Rapid Ransomware Canary File Encryption",
        "technique_id": "T1486",
        "tactic": "Impact",
        "severity": "CRITICAL",
        "confidence": "CRITICAL",
        "data_source": "Sysmon Event ID 11 (FileCreate in Canary)",
        "sigma_rule": "rules/sigma/win_ransomware_canary.yml",
        "wazuh_rule_id": 100014,
        "automated_response": "PID Kill + Volume Shadow Copy (VSS) Recovery",
        "delc_document": "docs/MITRE_COVERAGE_AND_GAPS.md",
        "validation_status": "PASS (100% True-Positive)"
    }
]

class SOCHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def _send_json(self, status_code, payload):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode('utf-8'))

    def do_OPTIONS(self):
        self._send_json(200, {"status": "OK"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/incidents" or path == "/api/alerts":
            self._send_json(200, {
                "total": len(orchestrator.dfir_engine.incident_list),
                "incidents": orchestrator.dfir_engine.incident_list,
                "alerts": orchestrator.dfir_engine.incident_list
            })

        elif path.startswith("/api/incidents/"):
            inc_id = path.split("/")[-1]
            if inc_id in orchestrator.dfir_engine.incidents:
                self._send_json(200, {"incident": orchestrator.dfir_engine.incidents[inc_id]})
            else:
                self._send_json(404, {"error": "Incident not found"})

        elif path == "/api/metrics":
            metrics = orchestrator.metrics_engine.get_soc_metrics()
            self._send_json(200, metrics)

        elif path == "/api/health":
            health = orchestrator.health_monitor.check_all_integrations()
            self._send_json(200, health)

        elif path == "/api/detections":
            self._send_json(200, {
                "total_rules": len(DETECTION_CATALOGUE),
                "rules": DETECTION_CATALOGUE
            })

        elif path == "/api/purple-team/scenarios":
            self._send_json(200, {"scenarios": list(SCENARIOS.keys())})

        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        if path == "/api/simulate":
            attack_type = data.get("type", "random")
            webhook_url = data.get("webhook_url", None)
            intent = data.get("intent", None) # DRY_RUN_SIMULATION, EXECUTE_IMMEDIATE

            if attack_type == "t1003":
                evt = simulate_t1003_lsass_dump()
            elif attack_type == "t1110":
                evt = simulate_t1110_brute_force()
            elif attack_type == "t1053":
                evt = simulate_t1053_scheduled_task()
            elif attack_type == "t1059":
                evt = simulate_t1059_powershell_execution()
            elif attack_type == "t1562":
                evt = simulate_t1562_defender_tamper()
            elif attack_type == "t1486":
                evt = simulate_t1486_ransomware_canary()
            else:
                evt = generate_random_attack()

            incident = orchestrator.process_event(evt, custom_webhook_url=webhook_url, execution_intent=intent)
            self._send_json(200, {"status": "SUCCESS", "incident": incident, "alert": incident})

        elif path == "/api/purple-team/run":
            scenario_key = data.get("scenario", "APT29_COZY_BEAR")
            webhook_url = data.get("webhook_url", None)
            res = purple_runner.run_scenario(scenario_key, custom_webhook_url=webhook_url)
            self._send_json(200, res)

        elif path.startswith("/api/incidents/") and path.endswith("/rollback"):
            inc_id = path.split("/")[3]
            if inc_id in orchestrator.dfir_engine.incidents:
                inc = orchestrator.dfir_engine.incidents[inc_id]
                action_id = inc.get("containment_action", {}).get("action_id")
                actor = data.get("actor", "analyst_lumidren")
                rb_res = orchestrator.containment_engine.rollback_containment(action_id, actor=actor)
                inc["status"] = "ROLLED_BACK"
                self._send_json(200, {"status": "SUCCESS", "rollback": rb_res})
            else:
                self._send_json(404, {"error": "Incident not found"})

        elif path.startswith("/api/incidents/") and path.endswith("/notes"):
            inc_id = path.split("/")[3]
            note_text = data.get("note", "")
            author = data.get("author", "analyst_lumidren")
            res = orchestrator.dfir_engine.add_analyst_note(inc_id, note_text, author=author)
            self._send_json(200, res)

        elif path == "/api/policy/config":
            new_mode = data.get("mode", "AUTOMATIC")
            if new_mode in ["AUTOMATIC", "APPROVAL_REQUIRED", "DRY_RUN"]:
                orchestrator.risk_engine.policy_mode = new_mode
                self._send_json(200, {"status": "SUCCESS", "active_policy_mode": new_mode})
            else:
                self._send_json(400, {"error": "Invalid mode. Choose AUTOMATIC, APPROVAL_REQUIRED, or DRY_RUN."})

        else:
            self._send_json(404, {"error": "Endpoint Not Found"})

def run_server(port=PORT):
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", port), SOCHttpRequestHandler) as httpd:
        print(f"[*] CyberPulse SOC Enterprise Operations Platform running at http://localhost:{port}")
        print(f"[*] Serving web console from {WEB_DIR}")
        print("[*] Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down SOC Server.")

if __name__ == "__main__":
    run_server()
