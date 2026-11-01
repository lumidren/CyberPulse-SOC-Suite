"""
SOAR Engine & Detection Orchestrator for the CyberPulse SOC Lab
Integrates Detection Matching, Non-Blocking Threat Intel, Multi-Factor Risk Scoring,
Configurable Policy Evaluation, Resilient Containment, DFIR Case Generation,
Attack Graph Visualization, DFIR Evidence Collection, AI Analyst Copilot,
Live Syslog Ingestion, Identity Blast Radius Analysis, and Observability.
"""

import json
import time
from datetime import datetime, timezone

from soar.notifications import WebhookDispatcher
from soar.risk_engine import RiskAndPolicyEngine
from soar.resilient_containment import ResilientContainmentEngine, next_id
from soar.dfir_engine import DFIREngine
from soar.metrics_engine import SOCMetricsEngine
from soar.health_monitor import IntegrationHealthMonitor
from soar.attack_graph import AttackGraphEngine
from soar.evidence_collector import VolatileEvidenceCollector
from soar.ai_copilot import SOCCopilot
from soar.syslog_receiver import SyslogReceiver, WebhookIngestionHandler
from soar.identity_graph import IdentityBlastRadiusEngine
from soar.enrichment import ThreatIntelClient
from soar.plugins import run_enrichers
from soar.appeals import AppealStore
from soar.case_manager import CaseManager
from soar.custody import CustodyLedger, sha256_of
from soar.orchestrator_hook import OrchestratorWebhook
from soar.sandbox import SandboxClient
from soar.thehive import TheHiveClient
from soar.triage_package import write_automatic as write_triage_package
from soar.user_notify import UserNotifier
from soar.threat_feeds import FeedClient, FeedStore
from soar.phishing_triage import triage as phishing_triage
from soar.playbooks import PlaybookRegistry
from soar.rule_exceptions import ExceptionRegistry
from soar.sigma_correlation import CorrelationEngine
from soar.sigma_engine import SEVERITY_ORDER, SigmaEngine

# SYNTHETIC lab threat-intel fixture. IPs are RFC 5737 documentation addresses
# (198.51.100.0/24, 203.0.113.0/24) and providers are fictional, so no real
# network or company is labelled malicious. Not derived from any provider's data.
THREAT_INTEL_CACHE = {
    "198.51.100.5": {
        "reputation": "MALICIOUS",
        "abuse_score": 98,
        "country": "Germany",
        "country_code": "DE",
        "flag": "🇩🇪",
        "lat": 52.5200,
        "lon": 13.4050,
        "isp": "Fictional Exit Relay (lab data)",
        "category": "SSH/RDP Brute Force, Scanner",
        "virustotal_positives": 42
    },
    "198.51.100.33": {
        "reputation": "MALICIOUS",
        "abuse_score": 95,
        "country": "Russia",
        "country_code": "RU",
        "flag": "🇷🇺",
        "lat": 55.7558,
        "lon": 37.6173,
        "isp": "Fictional BadHost Ltd (lab data)",
        "category": "C2 Server, Credential Harvester",
        "virustotal_positives": 38
    },
    "203.0.113.12": {
        "reputation": "SUSPICIOUS",
        "abuse_score": 76,
        "country": "Netherlands",
        "country_code": "NL",
        "flag": "🇳🇱",
        "lat": 52.3676,
        "lon": 4.9041,
        "isp": "Fictional VPN Provider (lab data)",
        "category": "Port Scanning, Exploit Probe",
        "virustotal_positives": 14
    },
    "203.0.113.210": {
        "reputation": "MALICIOUS",
        "abuse_score": 92,
        "country": "Romania",
        "country_code": "RO",
        "flag": "🇷🇴",
        "lat": 44.4268,
        "lon": 26.1025,
        "isp": "Fictional Hosting SRL (lab data)",
        "category": "Ransomware Distribution, Cobalt Strike C2",
        "virustotal_positives": 49
    },
    "198.51.100.172": {
        "reputation": "MALICIOUS",
        "abuse_score": 88,
        "country": "Ukraine",
        "country_code": "UA",
        "flag": "🇺🇦",
        "lat": 50.4501,
        "lon": 30.5234,
        "isp": "Fictional Hostlife LLC (lab data)",
        "category": "Malware Stager C2",
        "virustotal_positives": 33
    },
    "203.0.113.112": {
        "reputation": "MALICIOUS",
        "abuse_score": 91,
        "country": "Sweden",
        "country_code": "SE",
        "flag": "🇸🇪",
        "lat": 59.3293,
        "lon": 18.0686,
        "isp": "Fictional Cloud AB (lab data)",
        "category": "Brute Force, Exploit Botnet",
        "virustotal_positives": 27
    },
    "SHA256=F058F9A5D60E36E4E2C79E89DCE9A32158814F23D6980D4181F54B00D499E0C1": {
        "reputation": "MALICIOUS",
        "threat_name": "PowerShell.Empire.Stager",
        "virustotal_positives": 54,
        "signature": "Trojan.Generic.Heuristic"
    }
}

MEASUREMENT_BASIS = (
    "Lab-measured: in-process wall-clock time on emulated telemetry. "
    "Containment is simulated (no network calls), so these numbers are not "
    "comparable to production SOC latencies."
)

DATACENTER_GEO = {
    "name": "SOC-DC-NORTH-AMERICA",
    "location": "New York, USA",
    "lat": 40.7128,
    "lon": -74.0060
}

class SOAROrchestrator:
    def __init__(self, webhook_url=None, policy_mode="APPROVAL_REQUIRED"):
        self.risk_engine = RiskAndPolicyEngine(policy_mode=policy_mode)
        self.containment_engine = ResilientContainmentEngine()
        self.dfir_engine = DFIREngine()
        self.metrics_engine = SOCMetricsEngine()
        self.health_monitor = IntegrationHealthMonitor()
        self.dispatcher = WebhookDispatcher(webhook_url=webhook_url)
        self.attack_graph_engine = AttackGraphEngine()
        self.evidence_collector = VolatileEvidenceCollector()
        self.ai_copilot = SOCCopilot()
        self.syslog_receiver = SyslogReceiver(port=5514)
        self.webhook_ingest = WebhookIngestionHandler()
        self.identity_engine = IdentityBlastRadiusEngine()
        # Detection logic lives in the Sigma rules (rules/sigma/*.yml), mapped to playbooks
        # by rules/soar_mapping.yml
        self.sigma = SigmaEngine()
        self.correlation = CorrelationEngine()
        self.exceptions = ExceptionRegistry()
        self.playbooks = PlaybookRegistry()
        self.case_manager = CaseManager()
        self.appeals = AppealStore(ledger=self.containment_engine.ledger)
        self.custody = CustodyLedger()
        self.thehive = TheHiveClient()
        self.orchestrator_hook = OrchestratorWebhook()
        self.user_notifier = UserNotifier()
        self.sandbox = SandboxClient()
        # Bulk threat feeds (CIPHER) matched locally; nothing about events leaves (off unless configured)
        self.feeds = FeedStore()
        self.feed_client = FeedClient(self.feeds)
        if self.feed_client.configured:
            self.feed_client.refresh()
        # Optional external enrichment (off unless EXTERNAL_ENRICHMENT_ENABLED=true + API keys)
        self.intel_client = ThreatIntelClient()
        # Circuit-breaker trips page a human through the configured notification channel
        self.containment_engine.safety.pager = lambda message: self.dispatcher.dispatch_text(
            f"🚨 [CyberPulse PAGE] {message}")

    def apply_retention(self, days=None, now=None):
        """Delete incidents, their action records and buffered events older than the retention period."""
        import os
        from datetime import timedelta
        days = int(days if days is not None else os.environ.get("RETENTION_DAYS", "30"))
        now = now or datetime.now(timezone.utc)
        cutoff = now - timedelta(days=days)
        removed = self.dfir_engine.purge_older_than(cutoff)
        actions = 0
        for inc in removed:
            action_id = inc.get("containment_action", {}).get("action_id")
            if action_id and self.containment_engine.action_registry.pop(action_id, None) is not None:
                actions += 1
        syslog = self.syslog_receiver.purge_older_than(cutoff.timestamp())
        cases = self.case_manager.purge_missing(set(self.dfir_engine.incidents))
        self.custody.purge(set(self.dfir_engine.incidents))
        return {"retention_days": days, "incidents_purged": len(removed),
                "actions_purged": actions, "syslog_events_purged": syslog, "cases_purged": cases}

    def expire_containment(self):
        """Roll back expired actions and record it on their incidents."""
        expired = self.containment_engine.expire_actions()
        for entry in expired:
            inc = self.dfir_engine.find_by_action_id(entry["original_action_id"])
            if inc:
                self.dfir_engine.refresh_status(inc)
                self.dfir_engine.add_analyst_note(
                    inc["incident_id"], f"Containment {entry['original_action_id']} expired and was rolled back. "
                    "Renew it if the threat is still active.", author="ttl-expiry")
        return expired

    @property
    def alert_history(self):
        """Backward compatibility for existing API callers"""
        return self.dfir_engine.incident_list

    def evaluate_detection(self, event):
        """Match an event against the Sigma rules in rules/sigma/ (detection-as-code),
        then feed it to the correlation rules in rules/sigma/correlations/."""
        hit = self.sigma.evaluate(event, suppress=self._suppressed)
        fired = [r for r in self.correlation.observe(event) if not self.exceptions.suppressing(r["rule_id"], event)]
        if not fired:
            return hit
        candidates = fired + ([hit] if hit else [])
        candidates.sort(key=lambda r: -SEVERITY_ORDER.get(r["severity"], 0))
        best = dict(candidates[0])
        best["also_matched"] = [r["rule_id"] for r in candidates[1:]] + list((hit or {}).get("also_matched", []))
        return best

    def propose_action(self, incident_id, analyst, action_type=None):
        """Analyst-initiated proposal: stage a containment action for an existing incident.

        Used when policy only alerted (e.g. medium risk) but an analyst wants to act. The action
        defaults to the incident's playbook action and is always staged PENDING_APPROVAL, so it
        still needs an approval and passes every safety check at that point."""
        incident = self.dfir_engine.incidents.get(incident_id)
        if not incident:
            return {"status": "ERROR", "message": f"incident {incident_id} not found"}
        if not analyst:
            return {"status": "ERROR", "message": "an analyst name is required"}
        playbook = self.playbooks.select(incident.get("rule") or {})
        action_type = action_type or (playbook.action if playbook else None) or (incident.get("rule") or {}).get("action_recommended")
        from soar.action_tiers import ACTION_TIERS
        if action_type not in ACTION_TIERS:
            return {"status": "ERROR", "message": f"{action_type!r} is not a containment action"}
        telemetry = incident.get("telemetry") or {}
        details = telemetry.get("details") or {}
        action = self.containment_engine.execute_containment(
            action_type=action_type, target_host=telemetry.get("computer_name"), target_ip=telemetry.get("source_ip"),
            target_user=telemetry.get("user"), pid=details.get("ProcessId", 0),
            process_name=details.get("Image", "n/a"), execution_intent="PENDING_APPROVAL",
            correlation_id=incident.get("correlation_id"),
            context={"message_id": details.get("NetworkMessageId"), "proposed_by": analyst})
        incident.setdefault("proposed_actions", []).append({"action_id": action["action_id"], "action_type": action_type,
                                                            "status": action["status"], "proposed_by": analyst})
        self.dfir_engine.add_analyst_note(incident_id, f"{analyst} proposed {action_type} ({action['action_id']}); awaiting approval.")
        return {"status": "SUCCESS", "action": action}

    def _suppressed(self, rule, event):
        """True when an active exception in rules/exceptions.yml covers this rule match."""
        return self.exceptions.suppressing(rule.soar.get("soc_rule_id", rule.id), event) is not None

    def enrich_threat_intel(self, event):
        """Non-blocking Threat Intelligence & GeoIP enrichment with Circuit Breaker"""
        source_ip = event.get("source_ip")
        details = event.get("details", {})
        hash_val = details.get("Hashes") or details.get("FileHash_SHA256")

        default_geo = {
            "reputation": "INTERNAL / LOCAL",
            "abuse_score": 0,
            "country": "Internal Network",
            "country_code": "LAN",
            "flag": "🏢",
            "lat": 40.7128,
            "lon": -74.0060,
            "isp": "CORP.LOCAL Intranet",
            "category": "Internal Subnet",
            "virustotal_positives": 0
        }

        ip_intel = THREAT_INTEL_CACHE.get(source_ip, default_geo)

        intel = {
            # Live lookups only for public IPs, only when enabled (see soar/enrichment.py)
            # Only typed indicators (public IP, file hash) are ever looked up externally
            "external": {
                "ip": self.intel_client.lookup(source_ip) if source_ip else {"status": "NO_INDICATOR", "verdicts": []},
                "hash": self.intel_client.lookup(hash_val) if hash_val else {"status": "NO_INDICATOR", "verdicts": []},
            },
            "plugins": run_enrichers(event),
            "feed_matches": self.feeds.match(event),
            "ip_reputation": ip_intel,
            "hash_reputation": THREAT_INTEL_CACHE.get(hash_val, {
                "reputation": "UNKNOWN",
                "virustotal_positives": 0
            }),
            "target_datacenter": DATACENTER_GEO
        }
        return intel

    def process_event(self, event, custom_webhook_url=None, execution_intent=None):
        """
        Full Closed-Loop SOC Pipeline Execution:
        Adversary Emulation ➔ Telemetry ➔ Detection ➔ Enrichment ➔ Risk Scoring ➔
        Policy Decision ➔ Resilient Containment ➔ DFIR Incident ➔ Metrics ➔ Notifications
        """
        # All stage timings below are wall-clock measurements of this process
        # (time.perf_counter) on emulated telemetry; nothing is synthesized.
        t_detect = time.perf_counter()
        matched_rule = self.evaluate_detection(event)
        detection_ms = round((time.perf_counter() - t_detect) * 1000, 3)
        if not matched_rule:
            return None

        # The YAML playbook (playbooks/*.yml) chooses the proposed action before policy runs
        playbook = self.playbooks.select(matched_rule)
        matched_rule = PlaybookRegistry.apply_to_rule(playbook, matched_rule)

        # Stage 2: Threat Intel Enrichment
        t_intel = time.perf_counter()
        intel = self.enrich_threat_intel(event)
        intel_ms = round((time.perf_counter() - t_intel) * 1000, 3)

        # Stage 3: Multi-Factor Risk Assessment
        risk_assessment = self.risk_engine.calculate_risk_score(event, matched_rule, intel)

        # Stage 4: Policy Decision
        policy_decision = self.risk_engine.evaluate_policy(risk_assessment, matched_rule)
        if execution_intent:
            policy_decision["execution_intent"] = execution_intent
        # ...and may only make the decision more conservative (min risk, forced approval)
        policy_decision = PlaybookRegistry.apply_to_decision(playbook, policy_decision)

        # Stage 5a: Volatile evidence is collected BEFORE any containment can run
        evidence_package = self.evidence_collector.collect_volatile_evidence(event, None)

        # Stage 5b: Resilient Containment Dispatch
        target_host = event.get("computer_name")
        target_ip = event.get("source_ip")
        target_user = event.get("user")
        process_name = event.get("details", {}).get("SourceImage") or event.get("details", {}).get("Image", "system")
        pid = event.get("details", {}).get("SourceProcessId") or event.get("details", {}).get("ProcessId", 4012)
        correlation_id = next_id("CORR")

        containment_action = self.containment_engine.execute_containment(
            action_type=policy_decision["action"],
            target_host=target_host,
            target_ip=target_ip,
            target_user=target_user,
            pid=pid,
            process_name=process_name,
            execution_intent=policy_decision["execution_intent"],
            correlation_id=correlation_id,
            context={
                "task_name": event.get("details", {}).get("TaskName"),
                "task_xml": event.get("details", {}).get("TaskContent"),
                "message_id": event.get("details", {}).get("NetworkMessageId"),
                "reason": f"{matched_rule.get('rule_id')}: {policy_decision.get('rationale', '')}",
            },
        )

        total_ms = round(detection_ms + intel_ms + containment_action["latency_ms"], 3)
        total_sec = round(total_ms / 1000.0, 4)

        timing_breakdown = {
            "stage1_detection_ms": detection_ms,
            "stage2_threat_intel_ms": intel_ms,
            "stage3_containment_ms": containment_action["latency_ms"],
            "total_pipeline_latency_ms": total_ms,
            "total_pipeline_sec": total_sec,
            "measurement_basis": MEASUREMENT_BASIS
        }

        # Stage 6: Unified Incident & DFIR Case Creation
        incident = self.dfir_engine.create_incident(
            event=event,
            matched_rule=matched_rule,
            intel=intel,
            risk_assessment=risk_assessment,
            policy_decision=policy_decision,
            containment_action=containment_action,
            timing_breakdown=timing_breakdown
        )

        # Stage 7: Pipeline Telemetry & Metrics Aggregation
        self.metrics_engine.record_pipeline_execution(
            detection_ms=detection_ms,
            intel_ms=intel_ms,
            containment_ms=containment_action["latency_ms"],
            total_ms=total_ms,
            detected=True,
            contained=(containment_action["status"] == "SUCCESS")
        )

        # Stage 8: Attach the pre-containment evidence collected in stage 5a
        incident["evidence_package"] = evidence_package
        # Chain of custody starts at collection (F50)
        self.custody.record(incident["incident_id"], "collected", "evidence_package", sha256_of(evidence_package), "soar-pipeline")
        self.custody.record(incident["incident_id"], "collected", "telemetry", sha256_of(incident["telemetry"]), "soar-pipeline")
        incident["thehive_evidence_attachment"] = self.evidence_collector.package_for_thehive(evidence_package)

        # Stage 9: Interactive Attack Graph & Process Tree
        attack_graph = self.attack_graph_engine.build_attack_graph(incident)
        incident["attack_graph"] = attack_graph

        # Stage 10: AI SOC Analyst Copilot Report
        ai_analysis = self.ai_copilot.generate_incident_analysis(incident)
        incident["ai_analysis"] = ai_analysis

        # Stage 11: Identity Blast Radius Analysis
        target_username = (event.get("user", "") or "").split("\\")[-1] if event.get("user") else None
        if target_username:
            identity_analysis = self.identity_engine.analyze_compromised_identity(target_username)
            incident["identity_blast_radius"] = identity_analysis
        else:
            incident["identity_blast_radius"] = {"status": "NO_USER_CONTEXT"}

        if event.get("event_source") == "m365:email":
            # Offline header/URL analysis for the analyst (no network calls, metadata only)
            incident["phishing_triage"] = phishing_triage(event.get("details") or {})
        # Lab sandbox: hash look-ups always, URL detonation only if opted in (off unless SANDBOX_URL is set)
        incident["sandbox"] = self.sandbox.for_incident(event)

        incident["playbook"] = ({**playbook.summary(), "tasks": [{"title": t, "status": "Open"} for t in playbook.tasks]}
                                if playbook else None)

        # Every incident is filed into a case (same host within the grouping window = same case)
        incident["case_id"] = self.case_manager.attach(incident)["case_id"]
        # Optional push to the analysts' own TheHive (off unless THEHIVE_ENABLED=true)
        incident["thehive_sync"] = self.thehive.send(incident, incident["case_id"])
        # Optional hand-off to Shuffle / n8n (off unless ORCHESTRATOR_WEBHOOK_URL + _SECRET are set)
        incident["orchestrator_dispatch"] = self.orchestrator_hook.send(incident)
        # Tell the affected user about a suspicious sign-in (off by default; never for simulated events)
        incident["user_notification"] = self.user_notifier.notify(incident)
        # Triage package written automatically only if TRIAGE_PACKAGE_DIR is set (F49)
        incident["triage_package"] = write_triage_package(incident, self.case_manager.cases.get(incident["case_id"]))

        # Stage 12: Real-Time Mobile / Slack / Discord Notification
        if playbook is None or playbook.notify:
            webhook_res = self.dispatcher.dispatch(incident, custom_webhook_url=custom_webhook_url)
        else:
            webhook_res = {"status": "SKIPPED", "message": f"playbook {playbook.name} disables notifications"}
        incident["webhook_dispatch"] = webhook_res

        # Compatibility fields
        incident["alert_id"] = incident["incident_id"]
        incident["soar_response"] = containment_action
        incident["pipeline_timing"] = timing_breakdown

        return incident

if __name__ == "__main__":
    from simulator.attack_simulator import generate_random_attack
    orchestrator = SOAROrchestrator()
    sample_evt = generate_random_attack()
    res = orchestrator.process_event(sample_evt)
    print(json.dumps(res, indent=2))
