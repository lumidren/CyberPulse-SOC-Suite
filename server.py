"""
Lab Backend & REST API Server for the CyberPulse SOC Lab
Provides endpoints for Incident Triage, DFIR Timelines, SOAR Rollbacks,
Performance Metrics, Integration Health, Detection Catalogue, and Purple Team Scenarios.
"""

import hmac
import secrets
import http.cookies
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

# Validate configuration (environment + optional CYBERPULSE_CONFIG file) before
# anything reads a setting; refuse to start on invalid values (roadmap F93).
from soar.config import ConfigError, load_and_apply  # noqa: E402
try:
    load_and_apply()
except ConfigError as _exc:
    for _problem in _exc.problems:
        print(f"[config] {_problem}", file=sys.stderr)
    sys.exit(2)

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
from soar.auth import SessionStore
from soar.privacy import mask_identities, masking_enabled
from soar.observability import render_prometheus
from soar.chatops import ChatOpsApprovals
from soar.ingest_auth import SIGNATURE_HEADER, TIMESTAMP_HEADER, IngestVerifier
from scripts.validate_detections import run_scripted, scripted_status
from simulator.lab_guard import SimulationThrottle, lab_mode_enabled

__version__ = "2.5.0"

# ------------------------------------------------------------------------------
# Logging: structured operational log + dedicated audit trail for state-changing
# SOC actions (simulations, rollbacks, policy changes, ingestion).
# ------------------------------------------------------------------------------
LOG_LEVEL = os.environ.get("CYBERPULSE_LOG_LEVEL", "INFO").upper()
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))
_log_handlers = [logging.StreamHandler()]
if os.environ.get("LOG_FILE"):
    import logging.handlers
    # Daily rotation; keep RETENTION_DAYS files, older ones are deleted (roadmap E47)
    _log_handlers.append(logging.handlers.TimedRotatingFileHandler(
        os.environ["LOG_FILE"], when="midnight", backupCount=RETENTION_DAYS, encoding="utf-8"))
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=_log_handlers,
)
if os.environ.get("LOG_FORMAT", "text").lower() == "json":
    from soar.observability import JsonLogFormatter  # noqa: E402
    for _h in _log_handlers:
        _h.setFormatter(JsonLogFormatter())
from soar.redaction import RedactingFilter  # noqa: E402

for _handler in logging.getLogger().handlers:
    _handler.addFilter(RedactingFilter())  # credentials never reach the logs
logger = logging.getLogger("cyberpulse.server")
audit_logger = logging.getLogger("cyberpulse.audit")

VALID_POLICY_MODES = ("APPROVAL_REQUIRED", "DRY_RUN", "AUTOMATIC")
# Approval is the default. Full-auto must be explicitly opted into by the operator.
ALLOW_FULL_AUTO = os.environ.get("CYBERPULSE_ALLOW_FULL_AUTO", "false").strip().lower() == "true"
POLICY_MODE = os.environ.get("POLICY_MODE", "APPROVAL_REQUIRED").split("#")[0].strip().upper() or "APPROVAL_REQUIRED"
if POLICY_MODE not in VALID_POLICY_MODES:
    logger.warning("Unknown POLICY_MODE=%r; falling back to APPROVAL_REQUIRED.", POLICY_MODE)
    POLICY_MODE = "APPROVAL_REQUIRED"
if POLICY_MODE == "AUTOMATIC" and not ALLOW_FULL_AUTO:
    logger.warning("POLICY_MODE=AUTOMATIC ignored: set CYBERPULSE_ALLOW_FULL_AUTO=true to opt in. Using APPROVAL_REQUIRED.")
    POLICY_MODE = "APPROVAL_REQUIRED"

from soar.plugins import load_plugins  # noqa: E402

LOADED_PLUGINS = load_plugins()  # only modules from plugins/ named in CYBERPULSE_PLUGINS
orchestrator = SOAROrchestrator(policy_mode=POLICY_MODE)
purple_runner = PurpleTeamRunner(orchestrator)
bloodhound_exporter = BloodHoundExporter()
report_generator = IncidentReportGenerator()

# ------------------------------------------------------------------------------
# Environment-driven configuration (see .env.example)
# ------------------------------------------------------------------------------
ENV = os.environ.get("CYBERPULSE_ENV", "development").strip().lower()
PORT = int(os.environ.get("PORT", "5000"))
# Loopback by default: binding 0.0.0.0 exposes the console and API to every network
# the machine is attached to. Only do that behind a TLS reverse proxy / firewall.
HOST = os.environ.get("HOST", "127.0.0.1")
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
        "technique_id": "T1558.003",
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
    if not _SCRIPTED_VALIDATION_CACHE and lab_mode_enabled():
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
    # No hardcoded fallback: generate a random key for this process only and show it
    # once on the console (not in the log files) so the developer can sign in.
    key = secrets.token_urlsafe(24)
    logger.warning("CYBERPULSE_API_KEY not set - generated a random key for this process only.")
    print(f"[*] Development API key for this run (sign in with it): {key}", file=sys.stderr)
    return key

API_KEY = _resolve_api_key()
ALLOWED_ORIGIN = os.environ.get("CORS_ALLOWED_ORIGIN", "http://localhost:5000")

def allowed_origins():
    """Origins whose browser requests may change state with a session cookie."""
    port = PORT
    return {ALLOWED_ORIGIN, f"http://localhost:{port}", f"http://127.0.0.1:{port}"}

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

# Dashboard sessions: the API key is exchanged once for an HttpOnly cookie
SESSION_COOKIE = "cp_session"
SESSION_TTL_MIN = int(os.environ.get("SESSION_TTL_MIN", "480"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true" if ENV == "production" else "false").lower() == "true"
session_store = SessionStore(ttl_sec=SESSION_TTL_MIN * 60)
SYNTHETIC_DIRECTORY_NOTE = ("SYNTHETIC lab directory (soar/identity_graph.py): invented accounts and hosts, "
                            "no real employee data")

# Endpoints whose responses contain telemetry; every read is audit-logged (E55)
TELEMETRY_VIEW_PREFIXES = ("/api/incidents", "/api/alerts", "/api/approvals", "/api/syslog")
# Static files reachable without a session (everything else in web/ needs login)
PUBLIC_STATIC_PATHS = {"/login.html", "/login.js", "/styles.css", "/favicon.ico"}

# Machine webhook receiver (/api/ingest) authenticates with an HMAC signature
ingest_verifier = IngestVerifier(os.environ.get("INGEST_HMAC_SECRET", ""))
chatops = ChatOpsApprovals(orchestrator.containment_engine)

api_rate_limiter = SlidingWindowRateLimiter(RATE_LIMIT_PER_MINUTE)
simulation_throttle = SimulationThrottle()
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

    def _session_token(self):
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def _session(self):
        return session_store.get(self._session_token())

    def _key_matches(self, token):
        return hmac.compare_digest((token or "").encode("utf-8"), API_KEY.encode("utf-8"))

    def _has_valid_api_key(self):
        auth_header = self.headers.get("Authorization", "")
        api_key_header = self.headers.get("X-API-Key", "")
        if auth_header.startswith("Bearer "):
            return self._key_matches(auth_header.split(" ", 1)[1].strip())
        if api_key_header:
            return self._key_matches(api_key_header.strip())
        return False

    def _principal(self):
        """How the caller authenticated, for the audit trail (never the secret itself)."""
        if self._has_valid_api_key():
            return "api-key"
        session = self._session()
        return f"session:{session['principal']}" if session else "anonymous"

    def _csrf_ok(self):
        """Cookie-authenticated state changes need the session's CSRF token and a same-origin request.

        API-key clients are exempt: a browser never attaches that header on its own,
        so a forged cross-site request cannot carry it.
        """
        if self._has_valid_api_key():
            return True
        session = self._session()
        if not session:
            return True  # unauthenticated requests are rejected by the auth gate instead
        origin = self.headers.get("Origin")
        if origin and origin not in allowed_origins():
            return False
        supplied = self.headers.get("X-CSRF-Token", "")
        return hmac.compare_digest(supplied.encode("utf-8"), session["csrf_token"].encode("utf-8"))

    def _is_authenticated(self):
        """Valid dashboard session cookie, or API key / Bearer token (timing-safe)."""
        if self._session():
            return True
        auth_header = self.headers.get("Authorization", "")
        api_key_header = self.headers.get("X-API-Key", "")

        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        elif api_key_header:
            token = api_key_header.strip()

        return self._key_matches(token)

    def _set_session_cookie(self, token, max_age):
        attrs = [f"{SESSION_COOKIE}={token}", "HttpOnly", "SameSite=Strict", "Path=/", f"Max-Age={max_age}"]
        if COOKIE_SECURE:
            attrs.append("Secure")
        self.send_header("Set-Cookie", "; ".join(attrs))

    def _handle_login(self, data):
        """POST /api/session: exchange the API key for a session cookie."""
        client_ip = self._client_ip()
        if auth_failure_limiter.hit_without_recording(client_ip):
            self._send_json(429, {"error": "Too many failed sign-ins. Wait a minute and retry."})
            return
        if not self._key_matches(str(data.get("api_key", ""))):
            auth_failure_limiter.allow(client_ip)
            audit_logger.warning("LOGIN_FAILED client=%s", client_ip)
            self._send_json(401, {"error": "Invalid API key."})
            return
        token, csrf = session_store.create(principal="api-key-holder")
        audit_logger.info("LOGIN client=%s", client_ip)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self._set_session_cookie(token, SESSION_TTL_MIN * 60)
        self.end_headers()
        self.wfile.write(json.dumps({"status": "SUCCESS", "csrf_token": csrf,
                                     "expires_in_sec": SESSION_TTL_MIN * 60}).encode("utf-8"))

    def _handle_logout(self):
        session_store.destroy(self._session_token())
        audit_logger.info("LOGOUT client=%s", self._client_ip())
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self._set_session_cookie("", 0)
        self.end_headers()
        self.wfile.write(json.dumps({"status": "SUCCESS"}).encode("utf-8"))

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

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
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-CSRF-Token")

    # Responses that carry incident/telemetry data get account names masked (E45)
    MASKED_PREFIXES = ("/api/incidents", "/api/alerts", "/api/approvals", "/api/simulate",
                       "/api/purple-team/run", "/api/ingest")

    def _send_json(self, status_code, payload):
        if isinstance(payload, dict) and urlparse(self.path).path.startswith("/api/identity"):
            # Identity views run on the invented lab directory, never a real one (E56)
            payload = dict(payload, data_source=SYNTHETIC_DIRECTORY_NOTE)
        if masking_enabled() and urlparse(self.path).path.startswith(self.MASKED_PREFIXES):
            payload = mask_identities(payload)
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
            html = report_generator.generate_html_report(mask_identities(inc) if masking_enabled() else inc)
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

        # Prometheus scrape endpoint (API key / Bearer token, same as the REST API)
        if path == "/metrics":
            if not self._check_api_access():
                return
            body = render_prometheus(orchestrator).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return

        # Session status is readable without auth (it says whether you are logged in)
        if path == "/api/session":
            session = self._session()
            self._send_json(200, {"authenticated": bool(session),
                                  "csrf_token": session["csrf_token"] if session else None})
            return

        # Enforce rate limiting + API key authentication on all /api/* endpoints
        if path.startswith("/api/"):
            if not self._check_api_access():
                return
            if path.startswith(TELEMETRY_VIEW_PREFIXES):
                # Who looked at telemetry (Sysmon/Security events, evidence, reports), and how
                audit_logger.info("DATA_ACCESS client=%s principal=%s path=%s",
                                  self._client_ip(), self._principal(), path)
        elif path not in PUBLIC_STATIC_PATHS and not self._session():
            # Console pages and scripts require a dashboard session
            self._redirect("/login.html")
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

        elif path == "/api/approvals":
            pending = orchestrator.containment_engine.pending_approvals()
            items = []
            for action in pending:
                inc = orchestrator.dfir_engine.find_by_action_id(action["action_id"])
                items.append({"incident_id": inc["incident_id"] if inc else None, "action": action})
            self._send_json(200, {"total": len(items), "pending": items})

        elif path == "/api/policy/config":
            self._send_json(200, {
                "active_policy_mode": orchestrator.risk_engine.policy_mode,
                "default_policy_mode": "APPROVAL_REQUIRED",
                "full_auto_allowed": ALLOW_FULL_AUTO
            })

        elif path == "/api/exceptions":
            self._send_json(200, orchestrator.exceptions.status())

        elif path == "/api/safety":
            self._send_json(200, orchestrator.containment_engine.safety.status())

        elif path == "/api/enrichment":
            client = orchestrator.intel_client
            self._send_json(200, {"enabled": client.enabled,
                                  "providers": {"virustotal": bool(client.vt_key), "abuseipdb": bool(client.abuse_key)},
                                  "cache": {"entries": len(client.cache), "max_entries": client.cache.maxsize,
                                            "ttl_sec": client.cache.ttl_sec}})

        elif path == "/api/version":
            self._send_json(200, {
                "service": "cyberpulse-soc",
                "version": __version__,
                "environment": ENV,
                "lab_mode": lab_mode_enabled(),
                "detection_rules": len(DETECTION_CATALOGUE)
            })

        elif path == "/api/metrics":
            metrics = orchestrator.metrics_engine.get_soc_metrics()
            self._send_json(200, metrics)

        elif path == "/api/health":
            health = orchestrator.health_monitor.check_all_integrations(
                enrichment_enabled=orchestrator.intel_client.enabled)
            self._send_json(200, health)

        elif path == "/api/detections":
            scripted = _scripted_validation()
            rules = [
                dict(r, validation_status=scripted_status(r["detection_id"], scripted), real_world_noise_tested=False)
                for r in DETECTION_CATALOGUE
            ]
            self._send_json(200, {
                "total_rules": len(rules),
                "validation_note": ("Counts come from scripts/validate_detections.py on self-authored synthetic events; "
                                    "not real-world efficacy. No rule has been tested against real-world noise."),
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

    def _handle_chatops(self, path, raw_body):
        if not api_rate_limiter.allow(self._client_ip()):
            self._send_json(429, {"error": "Too Many Requests"})
            return
        if path.endswith("/slack"):
            ok, reason = chatops.verify_slack(self.headers.get("X-Slack-Request-Timestamp"),
                                              self.headers.get("X-Slack-Signature"), raw_body)
            if not ok:
                audit_logger.warning("CHATOPS_REJECTED platform=slack client=%s reason=%s", self._client_ip(), reason)
                self._send_json(401, {"error": reason})
                return
            self._send_json(200, chatops.handle_slack(raw_body))
            return
        ok, reason = chatops.verify_telegram(self.headers.get("X-Telegram-Bot-Api-Secret-Token"))
        if not ok:
            audit_logger.warning("CHATOPS_REJECTED platform=telegram client=%s reason=%s", self._client_ip(), reason)
            self._send_json(401, {"error": reason})
            return
        try:
            update = json.loads(raw_body.decode("utf-8", errors="replace"))
        except ValueError:
            self._send_json(400, {"error": "body must be JSON"})
            return
        self._send_json(200, chatops.handle_telegram(update if isinstance(update, dict) else {}))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Read the (bounded) request body before any rejection: replying before the body
        # is consumed makes clients see a connection reset instead of the status code.
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

        raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        body = raw_body.decode('utf-8', errors='replace')


        # Chat-platform callbacks authenticate with the platform's own signature, not the API key
        if path in ("/api/chatops/slack", "/api/chatops/telegram"):
            self._handle_chatops(path, raw_body)
            return

        # Login and the HMAC-signed webhook receiver do not use the API key / session gate
        login_request = path == "/api/session"
        signed_ingest = path == "/api/ingest"
        if path == "/api/session/logout":
            if not self._csrf_ok():
                self._send_json(403, {"error": "CSRF check failed."})
                return
            self._handle_logout()
            return

        # Enforce rate limiting + API key authentication on all /api/* endpoints
        if path.startswith("/api/") and not login_request and not signed_ingest:
            if not self._check_api_access():
                return
            if not self._csrf_ok():
                audit_logger.warning("CSRF_REJECTED client=%s path=%s", self._client_ip(), path)
                self._send_json(403, {"error": "CSRF check failed: missing/invalid X-CSRF-Token or cross-origin request."})
                return

        if signed_ingest:
            if not api_rate_limiter.allow(self._client_ip()):
                self._send_json(429, {"error": "Too Many Requests"})
                return
            if not ingest_verifier.enabled:
                self._send_json(503, {"error": "Webhook receiver disabled: set INGEST_HMAC_SECRET on the server."})
                return
            ok, reason = ingest_verifier.verify(self.headers.get(TIMESTAMP_HEADER), self.headers.get(SIGNATURE_HEADER), raw_body)
            if not ok:
                audit_logger.warning("INGEST_REJECTED client=%s reason=%s", self._client_ip(), reason)
                self._send_json(401, {"error": f"Unauthorized: {reason}"})
                return
        try:
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object")
        except (ValueError, json.JSONDecodeError):
            self._send_json(400, {"error": "Bad Request: body must be a valid JSON object."})
            return

        if login_request:
            self._handle_login(data)
            return

        if path in ("/api/simulate", "/api/purple-team/run") and not lab_mode_enabled():
            self._send_json(403, {
                "error": "Simulation disabled: start the server with CYBERPULSE_LAB_MODE=true, "
                         "and only in a lab you own or are authorised to test."
            })
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

            allowed, cap = simulation_throttle.allow([evt.get("technique_id", "")])
            if not allowed:
                self._send_json(429, {"error": f"Simulation rate limit reached ({cap}); try again in a minute.",
                                      "limits_per_minute": simulation_throttle.limits})
                return

            incident = orchestrator.process_event(evt, custom_webhook_url=webhook_url, execution_intent=intent)
            audit_logger.info(
                "SIMULATE client=%s type=%s incident=%s",
                self._client_ip(), attack_type, (incident or {}).get("incident_id")
            )
            self._send_json(200, {"status": "SUCCESS", "incident": incident, "alert": incident})

        elif path == "/api/purple-team/run":
            scenario_key = data.get("scenario", "APT29_COZY_BEAR")
            webhook_url = data.get("webhook_url", None)
            stages = SCENARIOS.get(scenario_key, {}).get("stages", [])
            allowed, cap = simulation_throttle.allow([s["technique_id"] for s in stages])
            if not allowed:
                self._send_json(429, {"error": f"Simulation rate limit reached ({cap}); try again in a minute."})
                return
            res = purple_runner.run_scenario(scenario_key, custom_webhook_url=webhook_url)
            self._send_json(200, res)

        elif path.startswith("/api/approvals/") and (path.endswith("/approve") or path.endswith("/reject")):
            parts = [s for s in path.split("/") if s]
            if len(parts) != 4:
                self._send_json(404, {"error": "Endpoint Not Found"})
                return
            action_id, decision = parts[2], parts[3]
            approver = str(data.get("approver", "")).strip()
            note = str(data.get("comment", data.get("reason", ""))).strip()
            engine = orchestrator.containment_engine
            result = engine.approve_action(action_id, approver, note) if decision == "approve" \
                else engine.reject_action(action_id, approver, note)
            if result["status"] != "SUCCESS":
                self._send_json(409 if "not pending" in result["message"] else 400, result)
                return
            inc = orchestrator.dfir_engine.find_by_action_id(action_id)
            if inc:
                orchestrator.dfir_engine.refresh_status(inc)
                orchestrator.dfir_engine.add_analyst_note(
                    inc["incident_id"], f"{decision.upper()}D containment {action_id}. {note}".strip(), author=approver
                )
            audit_logger.info(
                "APPROVAL client=%s action=%s decision=%s approver=%s",
                self._client_ip(), action_id, decision, approver
            )
            self._send_json(200, {"status": "SUCCESS", "decision": decision, "incident_id": inc["incident_id"] if inc else None,
                                  "action": result["action"]})

        elif path == "/api/enrichment/cache/clear":
            removed = orchestrator.intel_client.cache.clear()
            audit_logger.info("ENRICHMENT_CACHE_CLEAR client=%s removed=%s", self._client_ip(), removed)
            self._send_json(200, {"status": "SUCCESS", "entries_removed": removed})

        elif path == "/api/enrichment/config":
            enabled = data.get("enabled")
            if not isinstance(enabled, bool):
                self._send_json(400, {"error": "Provide {'enabled': true|false}."})
                return
            orchestrator.intel_client.enabled = enabled
            audit_logger.info("ENRICHMENT_TOGGLE client=%s enabled=%s", self._client_ip(), enabled)
            self._send_json(200, {"status": "SUCCESS", "enabled": enabled})

        elif path == "/api/safety/kill-switch":
            actor = str(data.get("actor", "")).strip()
            reason = str(data.get("reason", "")).strip()
            if not actor:
                self._send_json(400, {"error": "An 'actor' is required to change the kill switch."})
                return
            safety = orchestrator.containment_engine.safety
            if bool(data.get("engaged", True)):
                state = safety.engage_kill_switch(actor, reason)
            else:
                state = safety.release_kill_switch(actor, reason)
            audit_logger.warning(
                "KILL_SWITCH client=%s engaged=%s actor=%s reason=%s",
                self._client_ip(), state["engaged"], actor, reason
            )
            self._send_json(200, {"status": "SUCCESS", "kill_switch": state})

        elif path.startswith("/api/actions/") and path.endswith("/extend"):
            parts = [s for s in path.split("/") if s]
            try:
                minutes = int(data.get("minutes", 60))
            except (TypeError, ValueError):
                minutes = 0
            if len(parts) != 4 or not 1 <= minutes <= 1440:
                self._send_json(400, {"error": "Provide 'minutes' between 1 and 1440."})
                return
            actor = str(data.get("actor", "")).strip()
            result = orchestrator.containment_engine.extend_action(parts[2], minutes, actor)
            if result["status"] != "SUCCESS":
                self._send_json(400, result)
                return
            audit_logger.info("TTL_EXTEND client=%s action=%s minutes=%s actor=%s", self._client_ip(), parts[2], minutes, actor)
            self._send_json(200, result)

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
                if rb_res.get("status") not in ("SUCCESS",):
                    self._send_json(409, rb_res)
                    return
                orchestrator.dfir_engine.refresh_status(inc)
                note = f"Rolled back {rb_res['action_type']} ({rb_res['reversibility']})."
                if rb_res.get("not_restored"):
                    note += f" Not restored: {rb_res['not_restored']}"
                orchestrator.dfir_engine.add_analyst_note(inc_id, note, author=actor)
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
            new_mode = str(data.get("mode", "")).upper()
            if new_mode == "AUTOMATIC" and not ALLOW_FULL_AUTO:
                self._send_json(403, {
                    "error": "Full-auto containment is opt-in. Start the server with CYBERPULSE_ALLOW_FULL_AUTO=true to enable AUTOMATIC mode.",
                    "active_policy_mode": orchestrator.risk_engine.policy_mode
                })
                return
            if new_mode in VALID_POLICY_MODES:
                orchestrator.risk_engine.policy_mode = new_mode
                audit_logger.info("POLICY_CHANGE client=%s mode=%s", self._client_ip(), new_mode)
                self._send_json(200, {"status": "SUCCESS", "active_policy_mode": new_mode})
            else:
                self._send_json(400, {"error": "Invalid mode. Choose APPROVAL_REQUIRED, DRY_RUN, or AUTOMATIC."})

        elif path in ("/api/ingest", "/api/ingest/manual"):
            # /api/ingest: HMAC-signed machine webhook. /api/ingest/manual: analyst paste-in
            # from the console (session + CSRF, or API key). Both audit-logged.
            audit_logger.info("INGEST client=%s via=%s", self._client_ip(), "hmac" if signed_ingest else "manual")
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

def _start_ttl_sweeper(interval_sec=60):
    """Background thread that rolls back containment whose TTL has expired."""
    def sweep():
        while True:
            time.sleep(interval_sec)
            try:
                for entry in orchestrator.expire_containment():
                    audit_logger.info("TTL_EXPIRY action=%s rollback=%s", entry["original_action_id"], entry["rollback_id"])
                purged = orchestrator.apply_retention(RETENTION_DAYS)
                if purged["incidents_purged"] or purged["syslog_events_purged"]:
                    audit_logger.info("RETENTION_PURGE %s", purged)
            except Exception:
                logger.exception("TTL sweeper failed")
    threading.Thread(target=sweep, name="ttl-sweeper", daemon=True).start()

def run_server(port=None, host=None):
    httpd = create_server(host=host, port=port)
    _start_ttl_sweeper()
    bound_host, bound_port = httpd.server_address[:2]
    display_host = "localhost" if bound_host in ("0.0.0.0", "::") else bound_host  # nosec B104 - comparison, not a bind

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
    if bound_host in ("0.0.0.0", "::"):  # nosec B104 - warning when bound to all interfaces
        logger.warning("Listening on ALL interfaces (%s). Anyone who can reach this port can try to sign in; "
                       "keep it behind a firewall and a TLS reverse proxy.", bound_host)
    logger.info("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down SOC Server.")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    run_server()
