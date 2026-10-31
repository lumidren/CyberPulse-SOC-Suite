"""
Lab Backend & REST API Server for the CyberPulse SOC Lab
Provides endpoints for Incident Triage, DFIR Timelines, SOAR Rollbacks, 
Performance Metrics, Integration Health, Detection Catalogue, and Purple Team Scenarios.
"""

import hmac
import http.server
import json
import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict, deque
from http.server import ThreadingHTTPServer
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
    simulate_t1558_kerberoasting,
    simulate_t1003_dcsync,
    simulate_cloud_aws_assumerole,
    simulate_cloud_entra_impossible_travel,
    generate_random_attack
)
from simulator.purple_team_runner import PurpleTeamRunner, SCENARIOS
from soar.soar_engine import SOAROrchestrator
from soar.bloodhound_exporter import BloodHoundExporter
from soar.report_generator import IncidentReportGenerator
from scripts.validate_detections import run_scripted, scripted_status

__version__ = "2.5.0"

# ------------------------------------------------------------------------------
# Logging: structured operational log + dedicated audit trail for state-changing
# SOC actions (simulations, rollbacks, policy changes, ingestion).
# ------------------------------------------------------------------------------
LOG_LEVEL = os.environ.get("CYBERPULSE_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
logger = logging.getLogger("cyberpulse.server")
audit_logger = logging.getLogger("cyberpulse.audit")

orchestrator = SOAROrchestrator()
purple_runner = PurpleTeamRunner(orchestrator)
bloodhound_exporter = BloodHoundExporter()
report_generator = IncidentReportGenerator()

# ------------------------------------------------------------------------------
# Environment-driven configuration (see .env.example)
# ------------------------------------------------------------------------------
ENV = os.environ.get("CYBERPULSE_ENV", "development").strip().lower()
PORT = int(os.environ.get("PORT", "5000"))
HOST = os.environ.get("HOST", "0.0.0.0")
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(1024 * 1024)))  # 1 MiB
MAX_DRAIN_BYTES = 8 * 1024 * 1024  # upper bound read-and-discarded for oversized bodies
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "240"))
AUTH_FAILURE_LIMIT_PER_MINUTE = int(os.environ.get("AUTH_FAILURE_LIMIT_PER_MINUTE", "10"))
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

# Pagination guardrails for list endpoints
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500

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
        "validation_status": "pending"
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
        "validation_status": "pending"
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
        "validation_status": "pending"
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
        "validation_status": "pending"
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
        "validation_status": "pending"
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
        "validation_status": "pending"
    },
    {
        "detection_id": "SOC-RULE-007",
        "title": "Kerberoasting TGS Ticket Request with RC4 Encryption",
        "technique_id": "T1558.001",
        "tactic": "Credential Access",
        "severity": "HIGH",
        "confidence": "HIGH",
        "data_source": "Security Event ID 4769 (TGS Request)",
        "sigma_rule": "rules/sigma/win_kerberoasting.yml",
        "wazuh_rule_id": 100016,
        "automated_response": "Reset Service Account & Revoke Kerberos Ticket",
        "delc_document": "docs/lifecycle/DELC-004_Kerberoasting_TGS.md",
        "validation_status": "pending"
    },
    {
        "detection_id": "SOC-RULE-008",
        "title": "Active Directory Replication Abuse (DCSync)",
        "technique_id": "T1003.006",
        "tactic": "Credential Access",
        "severity": "CRITICAL",
        "confidence": "CRITICAL",
        "data_source": "Security Event ID 4662 (Extended Rights)",
        "sigma_rule": "rules/sigma/win_dcsync.yml",
        "wazuh_rule_id": 100017,
        "automated_response": "Isolate Account & Revoke Replication Rights",
        "delc_document": "docs/lifecycle/DELC-005_DCSync_Replication_Abuse.md",
        "validation_status": "pending"
    }
]

_SCRIPTED_VALIDATION_CACHE = {}

def _scripted_validation():
    """Run the scripted validation once per process and cache the counts."""
    if not _SCRIPTED_VALIDATION_CACHE:
        _SCRIPTED_VALIDATION_CACHE.update(run_scripted())
    return _SCRIPTED_VALIDATION_CACHE

def _resolve_api_key():
    """Resolve the API key from the environment.

    In production mode the key MUST be provided explicitly; the well-known
    development default is only acceptable for local lab usage.
    """
    key = os.environ.get("CYBERPULSE_API_KEY", "").strip()
    if key:
        return key
    if ENV == "production":
        logger.critical(
            "CYBERPULSE_ENV=production requires CYBERPULSE_API_KEY to be set. "
            "Refusing to start with the development default key."
        )
        sys.exit(1)
    logger.warning(
        "CYBERPULSE_API_KEY not set - using the development default key. "
        "Set CYBERPULSE_ENV=production and a strong key before exposing this service."
    )
    return "cyberpulse-dev-secret-key-2026"

API_KEY = _resolve_api_key()
ALLOWED_ORIGIN = os.environ.get("CORS_ALLOWED_ORIGIN", "http://localhost:5000")

class SlidingWindowRateLimiter:
    """Thread-safe per-client sliding-window rate limiter."""

    def __init__(self, max_events, window_sec=60):
        self.max_events = max_events
        self.window_sec = window_sec
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key):
        """Record an event for `key`; return False once the window is saturated."""
        now = time.monotonic()
        with self._lock:
            window = self._events[key]
            while window and now - window[0] > self.window_sec:
                window.popleft()
            if len(window) >= self.max_events:
                return False
            window.append(now)
            return True

    def hit_without_recording(self, key):
        """Check saturation for `key` without consuming an event slot."""
        now = time.monotonic()
        with self._lock:
            window = self._events[key]
            while window and now - window[0] > self.window_sec:
                window.popleft()
            return len(window) >= self.max_events

api_rate_limiter = SlidingWindowRateLimiter(RATE_LIMIT_PER_MINUTE)
auth_failure_limiter = SlidingWindowRateLimiter(AUTH_FAILURE_LIMIT_PER_MINUTE)

class SOCHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    server_version = f"CyberPulse/{__version__}"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_message(self, format, *args):
        """Route built-in access logging through the structured logger."""
        logger.info("%s %s", self.client_address[0], format % args)

    def end_headers(self):
        """Attach baseline security headers to every response (API and static)."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def _client_ip(self):
        return self.client_address[0] if self.client_address else "unknown"

    def _is_authenticated(self):
        """Validates API Key or Bearer token for API endpoints (timing-safe)."""
        auth_header = self.headers.get("Authorization", "")
        api_key_header = self.headers.get("X-API-Key", "")

        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        elif api_key_header:
            token = api_key_header.strip()

        return hmac.compare_digest(token.encode("utf-8"), API_KEY.encode("utf-8"))

    def _check_api_access(self):
        """Rate limiting + authentication gate for /api/* endpoints.

        Returns True when the request may proceed; otherwise the error
        response has already been sent.
        """
        client_ip = self._client_ip()

        if not api_rate_limiter.allow(client_ip):
            self._send_json(429, {
                "error": "Too Many Requests: API rate limit exceeded.",
                "retry_after_sec": 60
            })
            return False

        if auth_failure_limiter.hit_without_recording(client_ip):
            self._send_json(429, {
                "error": "Too Many Requests: repeated authentication failures. Back off and retry.",
                "retry_after_sec": 60
            })
            return False

        if not self._is_authenticated():
            auth_failure_limiter.allow(client_ip)
            logger.warning("Rejected unauthenticated API request from %s to %s", client_ip, self.path)
            self._send_json(401, {
                "error": "Unauthorized: Invalid or missing API key.",
                "hint": "Provide 'X-API-Key: <token>' or 'Authorization: Bearer <token>' header."
            })
            return False

        return True

    def _send_cors_headers(self):
        """Applies origin-restricted CORS headers."""
        origin = self.headers.get("Origin")
        if origin and (origin.startswith("http://localhost:") or origin.startswith("http://127.0.0.1:")):
            self.send_header("Access-Control-Allow-Origin", origin)
        else:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

    def _send_json(self, status_code, payload):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def _parse_pagination(self, query):
        """Extract validated limit/offset pagination parameters."""
        params = parse_qs(query or "")
        try:
            limit = int(params.get("limit", [DEFAULT_PAGE_SIZE])[0])
        except (TypeError, ValueError):
            limit = DEFAULT_PAGE_SIZE
        try:
            offset = int(params.get("offset", [0])[0])
        except (TypeError, ValueError):
            offset = 0
        limit = max(1, min(limit, MAX_PAGE_SIZE))
        offset = max(0, offset)
        return limit, offset

    def _handle_incident_subresource(self, inc_id, subresource):
        """Dispatch GET /api/incidents/<id>/<subresource> routes."""
        if inc_id not in orchestrator.dfir_engine.incidents:
            self._send_json(404, {"error": "Incident not found"})
            return

        inc = orchestrator.dfir_engine.incidents[inc_id]

        if subresource == "attack-graph":
            graph = inc.get("attack_graph") or orchestrator.attack_graph_engine.build_attack_graph(inc)
            self._send_json(200, {"attack_graph": graph})
        elif subresource == "evidence":
            self._send_json(200, {"evidence_package": inc.get("evidence_package", {})})
        elif subresource == "ai-analysis":
            analysis = inc.get("ai_analysis") or orchestrator.ai_copilot.generate_incident_analysis(inc)
            self._send_json(200, {"ai_analysis": analysis})
        elif subresource == "identity":
            self._send_json(200, {"identity_blast_radius": inc.get("identity_blast_radius", {})})
        elif subresource == "report":
            html = report_generator.generate_html_report(inc)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        else:
            self._send_json(404, {"error": "Unknown incident subresource"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Unauthenticated liveness probe for load balancers / container healthchecks
        if path == "/healthz":
            self._send_json(200, {"status": "ok", "service": "cyberpulse-soc", "version": __version__})
            return

        # Enforce rate limiting + API key authentication on all /api/* endpoints
        if path.startswith("/api/"):
            if not self._check_api_access():
                return

        segments = [s for s in path.split("/") if s]

        if path == "/api/incidents" or path == "/api/alerts":
            all_incidents = orchestrator.dfir_engine.incident_list
            limit, offset = self._parse_pagination(parsed.query)
            page = all_incidents[offset:offset + limit]
            self._send_json(200, {
                "total": len(all_incidents),
                "count": len(page),
                "limit": limit,
                "offset": offset,
                "incidents": page,
                "alerts": page
            })

        elif len(segments) == 3 and segments[0] == "api" and segments[1] == "incidents":
            inc_id = segments[2]
            if inc_id in orchestrator.dfir_engine.incidents:
                self._send_json(200, {"incident": orchestrator.dfir_engine.incidents[inc_id]})
            else:
                self._send_json(404, {"error": "Incident not found"})

        elif len(segments) == 4 and segments[0] == "api" and segments[1] == "incidents":
            self._handle_incident_subresource(segments[2], segments[3])

        elif path == "/api/version":
            self._send_json(200, {
                "service": "cyberpulse-soc",
                "version": __version__,
                "environment": ENV,
                "detection_rules": len(DETECTION_CATALOGUE)
            })

        elif path == "/api/metrics":
            metrics = orchestrator.metrics_engine.get_soc_metrics()
            self._send_json(200, metrics)

        elif path == "/api/health":
            health = orchestrator.health_monitor.check_all_integrations()
            self._send_json(200, health)

        elif path == "/api/detections":
            scripted = _scripted_validation()
            rules = [
                dict(r, validation_status=scripted_status(r["detection_id"], scripted), real_world_noise_tested=False)
                for r in DETECTION_CATALOGUE
            ]
            self._send_json(200, {
                "total_rules": len(rules),
                "validation_note": "Counts come from scripts/validate_detections.py on self-authored synthetic events; not real-world efficacy. No rule has been tested against real-world noise.",
                "rules": rules
            })

        elif path == "/api/purple-team/scenarios":
            self._send_json(200, {"scenarios": list(SCENARIOS.keys())})

        elif path == "/api/syslog/stats":
            stats = orchestrator.syslog_receiver.get_stats()
            self._send_json(200, stats)

        elif path == "/api/identity/graph":
            graph_data = orchestrator.identity_engine.generate_identity_graph_data()
            self._send_json(200, graph_data)

        elif path == "/api/identity/delegation-risks":
            risks = orchestrator.identity_engine.get_kerberos_delegation_risks()
            self._send_json(200, {"delegation_risks": risks})

        elif path == "/api/identity/bloodhound-export":
            export_bundle = bloodhound_exporter.export_all()
            self._send_json(200, export_bundle)

        elif path.startswith("/api/"):
            self._send_json(404, {"error": "Endpoint Not Found"})

        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Enforce rate limiting + API key authentication on all /api/* endpoints
        if path.startswith("/api/"):
            if not self._check_api_access():
                return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except (TypeError, ValueError):
            content_length = 0

        if content_length > MAX_BODY_BYTES:
            # Drain (and discard) a bounded amount of the body so the client
            # reliably receives the 413 instead of a connection reset.
            remaining = min(content_length, MAX_DRAIN_BYTES)
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            self.close_connection = True
            self._send_json(413, {
                "error": f"Payload Too Large: request body exceeds {MAX_BODY_BYTES} bytes."
            })
            return

        body = self.rfile.read(content_length).decode('utf-8', errors='replace') if content_length > 0 else "{}"
        try:
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object")
        except (ValueError, json.JSONDecodeError):
            self._send_json(400, {"error": "Bad Request: body must be a valid JSON object."})
            return

        if path == "/api/simulate":
            attack_type = data.get("type", "random")
            webhook_url = data.get("webhook_url", None)
            intent = data.get("intent", None)

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
            elif attack_type == "t1558":
                evt = simulate_t1558_kerberoasting()
            elif attack_type == "t1003_dcsync":
                evt = simulate_t1003_dcsync()
            elif attack_type == "cloud_aws":
                evt = simulate_cloud_aws_assumerole()
            elif attack_type == "cloud_entra":
                evt = simulate_cloud_entra_impossible_travel()
            else:
                evt = generate_random_attack()

            incident = orchestrator.process_event(evt, custom_webhook_url=webhook_url, execution_intent=intent)
            audit_logger.info(
                "SIMULATE client=%s type=%s incident=%s",
                self._client_ip(), attack_type, (incident or {}).get("incident_id")
            )
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
                if not action_id:
                    self._send_json(409, {"error": "No containment action recorded for this incident; nothing to roll back."})
                    return
                actor = data.get("actor", "analyst_lumidren")
                rb_res = orchestrator.containment_engine.rollback_containment(action_id, actor=actor)
                inc["status"] = "ROLLED_BACK"
                audit_logger.info(
                    "ROLLBACK client=%s incident=%s action=%s actor=%s",
                    self._client_ip(), inc_id, action_id, actor
                )
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
                audit_logger.info("POLICY_CHANGE client=%s mode=%s", self._client_ip(), new_mode)
                self._send_json(200, {"status": "SUCCESS", "active_policy_mode": new_mode})
            else:
                self._send_json(400, {"error": "Invalid mode. Choose AUTOMATIC, APPROVAL_REQUIRED, or DRY_RUN."})

        elif path == "/api/ingest":
            result = orchestrator.webhook_ingest.handle_ingest(data)
            if result.get("status") == "SUCCESS" and result.get("normalized_event"):
                incident = orchestrator.process_event(result["normalized_event"])
                self._send_json(200, {"status": "INGESTED_AND_PROCESSED", "incident": incident})
            else:
                self._send_json(400, result)

        elif path == "/api/identity/analyze":
            username = data.get("username", "")
            if username:
                analysis = orchestrator.identity_engine.analyze_compromised_identity(username)
                self._send_json(200, analysis)
            else:
                self._send_json(400, {"error": "Missing 'username' field."})

        elif path == "/api/identity/path":
            from_user = data.get("from_user", "")
            to_user = data.get("to_user", "Administrator")
            if from_user:
                path_result = orchestrator.identity_engine.get_shortest_path(from_user, to_user)
                self._send_json(200, path_result)
            else:
                self._send_json(400, {"error": "Missing 'from_user' field."})

        else:
            self._send_json(404, {"error": "Endpoint Not Found"})

def create_server(host=None, port=None):
    """Build the threaded HTTP server without starting it (also used by tests)."""
    host = HOST if host is None else host
    port = PORT if port is None else port
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer.daemon_threads = True
    return ThreadingHTTPServer((host, port), SOCHttpRequestHandler)

def run_server(port=None, host=None):
    httpd = create_server(host=host, port=port)
    bound_host, bound_port = httpd.server_address[:2]
    display_host = "localhost" if bound_host in ("0.0.0.0", "::") else bound_host

    def _graceful_shutdown(signum, frame):
        logger.info("Received signal %s - shutting down SOC server.", signum)
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _graceful_shutdown)
        except (ValueError, OSError, AttributeError):
            pass  # Not on main thread, or signal unsupported on this platform

    logger.info("CyberPulse SOC Lab v%s running at http://%s:%s", __version__, display_host, bound_port)
    logger.info("Environment: %s | Serving web console from %s", ENV, WEB_DIR)
    logger.info("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down SOC Server.")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    run_server()
