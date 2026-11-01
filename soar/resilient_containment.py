"""
Resilient Containment, Circuit Breaker & Rollback Engine for CyberPulse SOC Suite
Provides fault-tolerant execution, non-blocking enrichment fallback,
idempotent operations, and automated containment rollback capabilities.
"""

import hashlib
import itertools
import time
from datetime import datetime, timezone

from soar import command_builder as cmd
from soar.entra_responder import EntraResponder
from soar.plugins import RESPONDERS
from soar.evidence_collector import VolatileEvidenceCollector
from soar.process_termination import RANSOMWARE_GRACE_SECONDS, termination_plan
from soar.protected_assets import protected_account_match, protected_match
from soar.safety import AutomationSafety

# Actions that disrupt the target host, and the perimeter block that must never
# drop one of our own protected addresses.
HOST_DISRUPTING_ACTIONS = {
    "ISOLATE_HOST_AND_KILL_PROCESS", "REVERT_DEFENDER_POLICY_AND_ISOLATE", "REMOVE_SCHEDULED_TASK",
    "KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS", "UNLOAD_DRIVER_AND_ENFORCE_WDAC_BLOCK", "TERMINATE_PROCESS_TREE",
}
# Actions that stop a process (graceful-first plan recorded, see soar/process_termination.py)
PROCESS_KILLING_ACTIONS = {
    "ISOLATE_HOST_AND_KILL_PROCESS", "TERMINATE_PROCESS_TREE", "KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS",
}
# Actions that lock, disable, reset or revoke the target account
ACCOUNT_DISRUPTING_ACTIONS = {
    "TERMINATE_PROCESS_TREE", "RESET_SERVICE_ACCOUNT_AND_REVOKE_KERBEROS_TICKET",
    "ISOLATE_ACCOUNT_AND_REVOKE_REPLICATION_PRIVILEGES", "REVOKE_AWS_STS_SESSION_AND_ATTACH_DENY_POLICY",
    "REVOKE_ENTRA_REFRESH_TOKENS_AND_FORCE_MFA",
}

# Monotonic per-process sequence: IDs must never collide, even within one millisecond.
_ID_SEQUENCE = itertools.count(1)


def next_id(prefix):
    """Unique, sortable ID such as ACT-1730412345-000042."""
    return f"{prefix}-{int(time.time())}-{next(_ID_SEQUENCE):06d}"


class CircuitBreaker:
    def __init__(self, failure_threshold=3, recovery_time_sec=60):
        self.failure_threshold = failure_threshold
        self.recovery_time_sec = recovery_time_sec
        self.failure_count = 0
        self.state = "CLOSED" # CLOSED, OPEN, HALF_OPEN
        self.last_failure_time = 0

    def record_success(self):
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"

    def is_available(self):
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.recovery_time_sec:
                self.state = "HALF_OPEN"
                return True
            return False
        return True

class ResilientContainmentEngine:
    def __init__(self, safety=None, evidence_collector=None):
        self.safety = safety or AutomationSafety()
        self.evidence_collector = evidence_collector or VolatileEvidenceCollector()
        self.action_registry = {} # action_id -> action record
        self.circuit_breaker = CircuitBreaker()
        self.host_isolation_registry = set()
        self.blocked_ips = set()
        self.disabled_users = set()
        # Live Entra ID responder (F44); simulated unless ENTRA_RESPONDER_ENABLED=true and configured
        self.entra = EntraResponder()

    def execute_containment(self, action_type, target_host, target_ip, target_user, pid, process_name, execution_intent="EXECUTE_IMMEDIATE", correlation_id=None, context=None):
        """
        Executes idempotent policy-driven containment with audit logging and rollback metadata.
        """
        t_start = time.perf_counter()
        action_id = next_id("ACT")
        idempotency_key = f"{action_type}:{target_host}:{target_ip}:{pid}"

        action_record = {
            "context": dict(context or {}),
            "action_id": action_id,
            "correlation_id": correlation_id or f"CORR-{action_id}",
            "idempotency_key": idempotency_key,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_type": action_type,
            "target_host": target_host,
            "target_ip": target_ip,
            "target_user": target_user,
            "pid": pid,
            "process_name": process_name,
            "status": "SUCCESS",
            "execution_intent": execution_intent,
            "execution_protocol": "",
            "execution_log": "",
            "rollback_plan": {},
            "latency_ms": 0
        }

        # Protected accounts are never locked, reset or revoked through SOAR
        account_protection = self._protected_account_for(action_record)
        if account_protection:
            action_record["status"] = "BLOCKED_PROTECTED_ACCOUNT"
            action_record["execution_protocol"] = "Protected Account List"
            action_record["execution_log"] = (
                f"{action_type} refused: account {target_user} is protected ({account_protection}). "
                "Handle it manually through the identity team."
            )
            action_record["latency_ms"] = round((time.perf_counter() - t_start) * 1000, 3)
            self.action_registry[action_id] = action_record
            return action_record

        # Protected assets are never isolated or blocked through SOAR (any mode, any approval)
        protection = self._protected_asset_for(action_record)
        if protection:
            action_record["status"] = "BLOCKED_PROTECTED_ASSET"
            action_record["execution_protocol"] = "Protected Asset Allowlist"
            action_record["execution_log"] = (
                f"{action_type} refused: {target_host or target_ip} is protected ({protection}). "
                "Contain it manually through the change process."
            )
            action_record["latency_ms"] = round((time.perf_counter() - t_start) * 1000, 3)
            self.action_registry[action_id] = action_record
            return action_record

        # Handle DRY-RUN Simulation Mode
        if execution_intent == "DRY_RUN_SIMULATION":
            action_record["status"] = "SIMULATED_NO_DISRUPTION"
            action_record["execution_protocol"] = "DRY-RUN Simulation Subsystem"
            action_record["execution_log"] = f"[DRY-RUN] Policy simulated {action_type} on {target_host} / {target_ip}. Zero host or network disruption occurred."
            action_record["latency_ms"] = round((time.perf_counter() - t_start) * 1000, 3)
            self.action_registry[action_id] = action_record
            return action_record

        # Handle PENDING APPROVAL Mode
        if execution_intent == "PENDING_APPROVAL":
            action_record["status"] = "PENDING_ANALYST_APPROVAL"
            action_record["execution_protocol"] = "Analyst Approval Gate"
            action_record["execution_log"] = f"Action {action_type} for {target_host} staged; nothing runs until an analyst approves it."
            action_record["latency_ms"] = round((time.perf_counter() - t_start) * 1000, 3)
            self.action_registry[action_id] = action_record
            return action_record

        # Global kill switch: nothing executes while it is engaged
        if self.safety.is_halted():
            ks = self.safety.kill_switch
            action_record["status"] = "HALTED_BY_KILL_SWITCH"
            action_record["execution_protocol"] = "Automation Kill Switch"
            action_record["execution_log"] = (
                f"Kill switch engaged by {ks['actor']} ({ks['reason'] or 'no reason given'}); "
                f"{action_type} on {target_host} was not executed."
            )
            action_record["latency_ms"] = round((time.perf_counter() - t_start) * 1000, 3)
            self.action_registry[action_id] = action_record
            return action_record

        # Rate limit on automated execution: excess actions wait for an analyst instead
        if self.safety.rate_limit_exceeded():
            action_record["status"] = "PENDING_ANALYST_APPROVAL"
            action_record["execution_intent"] = "PENDING_APPROVAL"
            action_record["execution_protocol"] = "Containment Rate Limit"
            action_record["execution_log"] = (
                f"Hourly containment budget ({self.safety.max_actions_per_hour}) reached; "
                f"{action_type} on {target_host} staged for analyst approval instead of running."
            )
            action_record["latency_ms"] = round((time.perf_counter() - t_start) * 1000, 3)
            self.action_registry[action_id] = action_record
            return action_record

        # Execute Concrete Containment Playbooks
        self._apply_action(action_record)
        self.safety.record_execution(action_record)
        self._set_expiry(action_record)

        # Measured in-process time only. Responders are simulated, so this is NOT
        # a network round-trip to WinRM/pfSense/AD and must not be presented as one.
        action_record["latency_ms"] = round((time.perf_counter() - t_start) * 1000, 3)
        self.action_registry[action_id] = action_record
        return action_record

    def _apply_action(self, action_record):
        """Run the playbook; values that fail command validation stop the action before it is built."""
        try:
            self._apply_action_unchecked(action_record)
        except cmd.CommandValidationError as exc:
            action_record["status"] = "FLAGGED_FOR_MANUAL_REVIEW"
            action_record["execution_protocol"] = "Command Validation"
            action_record["execution_log"] = f"Refused to build responder command: {exc}. No action taken."
            action_record.pop("rollback_plan", None)

    def _apply_action_unchecked(self, action_record):
        """Run the (simulated) playbook for an action record and fill in its execution fields."""
        action_type = action_record["action_type"]
        target_host = action_record["target_host"]
        target_ip = action_record["target_ip"]
        target_user = action_record["target_user"]
        pid = action_record["pid"]
        process_name = action_record["process_name"]
        # Snapshot the (simulated) responder state first so rollback can restore it exactly
        action_record["pre_action_state"] = self._capture_state(action_record)
        action_record["status"] = "SUCCESS"

        # Evidence before disruption: snapshot process + memory before any kill or isolation
        if action_type in PROCESS_KILLING_ACTIONS or action_type in ("REVERT_DEFENDER_POLICY_AND_ISOLATE",):
            action_record["pre_containment_snapshot"] = self.evidence_collector.snapshot_process(
                target_host, pid, process_name)

        # Any action that stops a process records a graceful-first termination plan
        if action_type in PROCESS_KILLING_ACTIONS and pid:
            grace = RANSOMWARE_GRACE_SECONDS if action_type == "KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS" else None
            kwargs = {"grace_seconds": grace} if grace is not None else {}
            try:
                action_record["termination_plan"] = termination_plan(pid, process_name, **kwargs)
            except (TypeError, ValueError) as exc:
                action_record["termination_plan"] = {"error": str(exc)}

        if action_type == "BLOCK_SOURCE_IP_FIREWALL":
            action_record["execution_argv"] = cmd.iptables_drop(target_ip)
            action_record["execution_protocol"] = "pfSense REST API / iptables Netfilter"
            action_record["execution_log"] = f"[pfSense Gateway 10.0.0.1:8443] Injected packet drop rule: DROP INBOUND TCP/UDP from {target_ip}/32 on WAN."
            action_record["rollback_plan"] = {
                "method": "REST_API_DELETE",
                "endpoint": cmd.pfsense_rule_path(target_ip),
                "argv": cmd.iptables_undrop(target_ip)
            }
            self.blocked_ips.add(target_ip)

        elif action_type == "ISOLATE_HOST_AND_KILL_PROCESS":
            action_record["execution_protocol"] = "WinRM over TLS (Port 5986) + WFP NetFirewallRule"
            action_record["execution_log"] = f"[WinRM TLS 5986 -> {target_host}] Injected WFP emergency isolation filter (allow only 10.0.1.10). Stopping PID {pid} ({process_name}) graceful-first (see termination_plan)."
            action_record["rollback_plan"] = {
                "method": "WINRM_POWERSHELL",
                "invocation": cmd.ps_invocation("Remove-NetFirewallRule", DisplayName=cmd.ISOLATION_RULE)
            }
            self.host_isolation_registry.add(target_host)

        elif action_type == "REMOVE_SCHEDULED_TASK":
            task_name = action_record["context"].get("task_name")
            if not task_name:
                action_record["status"] = "FLAGGED_FOR_MANUAL_REVIEW"
                action_record["execution_log"] = "No task name in telemetry; cannot export the task first, so it was not touched."
                return
            # Export first, then DISABLE (reversible). Deletion is left to an analyst after review.
            task_xml = action_record["context"].get("task_xml") or ""
            action_record["task_export"] = {
                "task_name": task_name,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "export_argv": cmd.schtasks("export", task_name),
                "disable_argv": cmd.schtasks("disable", task_name),
                "xml": task_xml,
                "sha256": hashlib.sha256(task_xml.encode("utf-8")).hexdigest(),
            }
            action_record["execution_protocol"] = "WinRM PowerShell Remoting"
            action_record["execution_log"] = (
                f"[WinRM TLS 5986 -> {target_host}] Exported task XML for {task_name} "
                f"(sha256 {action_record['task_export']['sha256'][:12]}...), then disabled the task. Not deleted."
            )
            action_record["rollback_plan"] = {
                "method": "WINRM",
                "argv": cmd.schtasks("enable", task_name),
                "fallback": "Re-register from task_export.xml if the task was later deleted.",
            }

        elif action_type == "TERMINATE_PROCESS_TREE":
            action_record["execution_protocol"] = "WinRM + Active Directory LDAP"
            action_record["execution_log"] = f"[WinRM -> {target_host}] Stopping {process_name} (PID {pid}) graceful-first, children by PID (see termination_plan). Revoked session and locked account {target_user}."
            action_record["rollback_plan"] = {
                "method": "ACTIVE_DIRECTORY_LDAP",
                "invocation": cmd.ps_invocation("Enable-ADAccount", Identity=target_user)
            }
            self.disabled_users.add(target_user)

        elif action_type == "REVERT_DEFENDER_POLICY_AND_ISOLATE":
            action_record["execution_protocol"] = "WinRM PowerShell Remoting + EDR API"
            action_record["execution_log"] = f"[WinRM TLS 5986 -> {target_host}] Re-enabled Windows Defender Real-Time Protection via Set-MpPreference. Host isolated."
            action_record["rollback_plan"] = {
                "method": "WINRM_POWERSHELL",
                "invocation": cmd.ps_invocation("Remove-NetFirewallRule", DisplayName=cmd.ISOLATION_RULE)
            }
            self.host_isolation_registry.add(target_host)

        elif action_type == "KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS":
            action_record["execution_protocol"] = "WinRM + Volume Shadow Copy (VSS)"
            action_record["execution_log"] = f"[WinRM -> {target_host}] Force-terminated ransomware PID {pid} immediately (no grace period: encryption in progress). Restored canary files from VSS Snapshot #41."
            action_record["rollback_plan"] = {"method": "VSS_VERIFIED", "note": "Files restored from shadow copy."}

        elif action_type == "RESET_SERVICE_ACCOUNT_AND_REVOKE_KERBEROS_TICKET":
            action_record["execution_protocol"] = "Active Directory PowerShell & Kerberos KDC"
            action_record["execution_log"] = f"[AD KDC -> {target_host}] Purged compromised TGS ticket. Enforced immediate password reset for targeted SPN service account."
            action_record["rollback_plan"] = {
                "method": "ACTIVE_DIRECTORY_LDAP",
                "invocation": cmd.ps_invocation("Set-ADUser", Identity=target_user, ChangePasswordAtLogon=False)
            }
            self.disabled_users.add(target_user)

        elif action_type == "ISOLATE_ACCOUNT_AND_REVOKE_REPLICATION_PRIVILEGES":
            action_record["execution_protocol"] = "Active Directory LDAP ADSI"
            action_record["execution_log"] = f"[AD DS -> {target_host}] Revoked DS-Replication-Get-Changes extended rights from {target_user} and locked account."
            action_record["rollback_plan"] = {
                "method": "ACTIVE_DIRECTORY_LDAP",
                "invocation": cmd.ps_invocation("Enable-ADAccount", Identity=target_user)
            }
            self.disabled_users.add(target_user)

        elif action_type == "QUARANTINE_EMAIL":
            message_id = (action_record.get("context") or {}).get("message_id")
            action_record["execution_protocol"] = "Microsoft Graph mail API"
            action_record["execution_log"] = (f"[MS Graph -> {target_user}] Moved message {message_id} to the "
                                              "CyberPulseQuarantine folder (simulated responder).")
            action_record["rollback_plan"] = {
                "method": "MS_GRAPH_API",
                "request": cmd.graph_move_message(target_user, message_id, "inbox"),
            }
            action_record["quarantine_request"] = cmd.graph_move_message(target_user, message_id, "CyberPulseQuarantine")

        elif action_type == "REVOKE_AWS_STS_SESSION_AND_ATTACH_DENY_POLICY":
            action_record["execution_protocol"] = "AWS IAM & STS API (boto3)"
            action_record["execution_log"] = f"[AWS IAM -> {target_user}] Attached AWSRevokeOlderSessions inline policy and invalidated active STS tokens."
            action_record["rollback_plan"] = {
                "method": "AWS_IAM_API",
                "argv": cmd.aws_delete_deny_policy(target_user)
            }
            self.disabled_users.add(target_user)

        elif action_type == "REVOKE_ENTRA_REFRESH_TOKENS_AND_FORCE_MFA":
            action_record["execution_protocol"] = "Microsoft Graph API / Azure AD"
            if self.entra.enabled:
                try:
                    live = self.entra.contain(target_user)
                except cmd.CommandValidationError:
                    raise
                except Exception as exc:
                    action_record["status"] = "FLAGGED_FOR_MANUAL_REVIEW"
                    action_record["execution_mode"] = "live"
                    action_record["execution_log"] = f"[MS Graph] Live response failed: {exc}. Finish it manually in Entra."
                    return
                action_record["execution_mode"] = "live"
                action_record["execution_log"] = f"[MS Graph -> {target_user}] " + "; ".join(live["steps"]) + "."
            else:
                action_record["execution_log"] = f"[MS Graph -> {target_user}] Revoked all OAuth refresh tokens via RevokeSignInSessions API and enforced immediate MFA re-challenge."
            action_record["rollback_plan"] = {
                "method": "MS_GRAPH_API",
                "note": "Revoked sessions cannot be restored; the user signs in again. Remove any forced-MFA "
                        "conditional-access assignment manually.",
                "revocation_request": cmd.graph_revoke_sessions(target_user)
            }
            self.disabled_users.add(target_user)

        elif action_type == "UNLOAD_DRIVER_AND_ENFORCE_WDAC_BLOCK":
            action_record["execution_protocol"] = "WinRM fltmc / Service Controller + WDAC CI Policy"
            action_record["execution_log"] = f"[WinRM -> {target_host}] Unloaded vulnerable kernel driver and refreshed WDAC CI Policy to enforce blocklist."
            action_record["rollback_plan"] = {
                "method": "WINRM_POWERSHELL",
                "argv": cmd.citool_refresh()
            }

        elif action_type in RESPONDERS:
            # Plugin responder: runs only here, after every safety gate in execute/approve
            RESPONDERS[action_type](action_record)

        elif action_type == "ESCALATE_TO_ANALYST":
            action_record["status"] = "FLAGGED_FOR_MANUAL_REVIEW"
            action_record["execution_protocol"] = "Analyst Escalation"
            action_record["execution_log"] = "Rule confidence below threshold; escalated to an analyst. No containment proposed."

        else:
            action_record["status"] = "FLAGGED_FOR_MANUAL_REVIEW"
            action_record["execution_log"] = "No disruptive containment policy matched. Staged for analyst review."

    @staticmethod
    def _protected_asset_for(record):
        """Protection entry blocking this action, if any."""
        if record["action_type"] in HOST_DISRUPTING_ACTIONS:
            return protected_match(host=record.get("target_host"))
        if record["action_type"] == "BLOCK_SOURCE_IP_FIREWALL":
            return protected_match(ip=record.get("target_ip"))
        return None

    @staticmethod
    def _protected_account_for(record):
        """Protection entry blocking an identity action on this account, if any."""
        if record["action_type"] in ACCOUNT_DISRUPTING_ACTIONS:
            return protected_account_match(record.get("target_user"))
        return None

    def _set_expiry(self, record, minutes=None):
        """Stamp a TTL on isolation / block actions so they cannot linger forever."""
        ttl = minutes if minutes is not None else self.safety.ttl_for(record["action_type"])
        if not ttl or record["status"] != "SUCCESS":
            return
        expires = self.safety.clock() + ttl * 60
        record["expires_at_epoch"] = expires
        record["expires_at"] = datetime.fromtimestamp(expires, timezone.utc).isoformat()

    def extend_action(self, action_id, minutes, actor):
        """Analyst renews an active action's TTL from now."""
        record = self.action_registry.get(action_id)
        if not record or record["status"] != "SUCCESS" or "expires_at_epoch" not in record:
            return {"status": "ERROR", "message": f"Action {action_id} is not an active, expiring action."}
        if not actor:
            return {"status": "ERROR", "message": "An actor is required to extend an action."}
        self._set_expiry(record, minutes=int(minutes))
        record.setdefault("ttl_extensions", []).append(
            {"actor": actor, "minutes": int(minutes), "timestamp": datetime.now(timezone.utc).isoformat()})
        return {"status": "SUCCESS", "action": record}

    def expire_actions(self):
        """Roll back every active action whose TTL has passed. Returns the rollback entries."""
        now = self.safety.clock()
        expired = []
        for record in list(self.action_registry.values()):
            if record["status"] == "SUCCESS" and record.get("expires_at_epoch", float("inf")) <= now:
                entry = self.rollback_containment(record["action_id"], actor="ttl-expiry")
                entry["reason"] = "TTL expired; renew explicitly if containment is still needed."
                expired.append(entry)
        return expired

    def pending_approvals(self):
        """Actions staged for analyst sign-off, oldest first."""
        return [r for r in self.action_registry.values() if r["status"] == "PENDING_ANALYST_APPROVAL"]

    def approve_action(self, action_id, approver, comment=""):
        """Analyst approves a staged action; only then is the playbook applied."""
        record = self.action_registry.get(action_id)
        if not record:
            return {"status": "ERROR", "message": f"Action ID {action_id} not found."}
        if record["status"] != "PENDING_ANALYST_APPROVAL":
            return {"status": "ERROR", "message": f"Action {action_id} is {record['status']}, not pending approval."}
        if not approver:
            return {"status": "ERROR", "message": "An approver identity is required."}
        if self.safety.is_halted():
            return {"status": "ERROR", "message": "Kill switch engaged: approvals cannot execute until it is released."}
        protection = self._protected_asset_for(record)
        if protection:
            return {"status": "ERROR", "message": f"{record['target_host']} is a protected asset ({protection}); contain it manually."}
        account_protection = self._protected_account_for(record)
        if account_protection:
            return {"status": "ERROR", "message": f"{record['target_user']} is a protected account ({account_protection}); handle it manually."}

        t_start = time.perf_counter()
        record["approval"] = {
            "decision": "APPROVED",
            "approver": approver,
            "comment": comment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        record["execution_intent"] = "EXECUTE_AFTER_APPROVAL"
        self._apply_action(record)
        # Approved actions count toward the hourly budget (they are not blocked by it)
        self.safety.record_execution(record)
        self._set_expiry(record)
        record["latency_ms"] = round((time.perf_counter() - t_start) * 1000, 3)
        return {"status": "SUCCESS", "action": record}

    def reject_action(self, action_id, approver, reason=""):
        """Analyst rejects a staged action; nothing is executed."""
        record = self.action_registry.get(action_id)
        if not record:
            return {"status": "ERROR", "message": f"Action ID {action_id} not found."}
        if record["status"] != "PENDING_ANALYST_APPROVAL":
            return {"status": "ERROR", "message": f"Action {action_id} is {record['status']}, not pending approval."}
        if not approver:
            return {"status": "ERROR", "message": "An approver identity is required."}
        record["status"] = "REJECTED_BY_ANALYST"
        record["approval"] = {
            "decision": "REJECTED",
            "approver": approver,
            "comment": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        record["execution_log"] = f"Analyst {approver} rejected {record['action_type']}; no action executed."
        return {"status": "SUCCESS", "action": record}


    def rollback_containment(self, action_id, actor="analyst_lumidren"):
        """
        Reverses an executed containment action and records exactly what was and
        was not restored. Only executed (SUCCESS) actions can be rolled back; staged
        actions are rejected instead, and terminal states are left alone.
        """
        if action_id not in self.action_registry:
            return {"status": "ERROR", "message": f"Action ID {action_id} not found in registry."}

        record = self.action_registry[action_id]
        if record["status"] == "ROLLED_BACK":
            return {"status": "ALREADY_ROLLED_BACK", "message": f"Action {action_id} was already reversed."}
        if record["status"] != "SUCCESS":
            hint = " Reject it instead." if record["status"] == "PENDING_ANALYST_APPROVAL" else ""
            return {"status": "ERROR", "message": f"Action {action_id} is {record['status']}; nothing was executed to roll back.{hint}"}

        playbook = ROLLBACK_PLAYBOOKS.get(record["action_type"])
        rollback_entry = {
            "rollback_id": next_id("RB"),
            "original_action_id": action_id,
            "action_type": record["action_type"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "status": "SUCCESS",
            "reversibility": "FULL",
            "not_restored": None,
            "log": "",
        }

        if playbook is None:
            rollback_entry["log"] = f"No containment side effects recorded for {record['action_type']}; audit flag reversed."
        else:
            reversibility, describe, not_restored = playbook
            rollback_entry["reversibility"] = reversibility
            rollback_entry["log"] = describe(record)
            rollback_entry["not_restored"] = not_restored
        if record["action_type"] == "REVOKE_ENTRA_REFRESH_TOKENS_AND_FORCE_MFA" and record.get("execution_mode") == "live":
            try:
                rollback_entry["live_result"] = self.entra.release(record.get("target_user"))
            except Exception as exc:
                rollback_entry["status"] = "PARTIAL_FAILURE"
                rollback_entry["log"] += f" Live step-up group removal failed: {exc}; remove it manually in Entra."
        rollback_entry["restored_state"] = self._release_state(record)
        rollback_entry["pre_action_state"] = record.get("pre_action_state")

        record["status"] = "ROLLED_BACK"
        record["rollback_history"] = rollback_entry
        return rollback_entry

    def _capture_state(self, record):
        """What the target looked like before this action touched it.

        A flag counts as pre-existing only if it was set outside SOAR; state held
        by another active SOAR action is tracked by that action instead.
        """
        def external(key, registry, value):
            return value in registry and not self._held_by_other_action(record, key)

        return {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "host_isolated": external("host_isolated", self.host_isolation_registry, record.get("target_host")),
            "ip_blocked": external("ip_blocked", self.blocked_ips, record.get("target_ip")),
            "user_disabled": external("user_disabled", self.disabled_users, record.get("target_user")),
        }

    def _held_by_other_action(self, record, key):
        """True if another still-active action holds the same effect on the same target."""
        field = {"host_isolated": "target_host", "ip_blocked": "target_ip", "user_disabled": "target_user"}[key]
        for other in self.action_registry.values():
            if other is record or other["status"] != "SUCCESS":
                continue
            if other.get(field) == record.get(field) and self._effects(other).get(key):
                return True
        return False

    @staticmethod
    def _effects(record):
        """Which responder-state flags an action turns on."""
        return {
            "host_isolated": record["action_type"] in ("ISOLATE_HOST_AND_KILL_PROCESS", "REVERT_DEFENDER_POLICY_AND_ISOLATE"),
            "ip_blocked": record["action_type"] == "BLOCK_SOURCE_IP_FIREWALL",
            "user_disabled": record["action_type"] in ACCOUNT_DISRUPTING_ACTIONS,
        }

    def _release_state(self, record):
        """Restore the pre-action state: undo only what this action changed and nothing still held."""
        pre = record.get("pre_action_state", {})
        effects = self._effects(record)
        targets = {
            "host_isolated": (self.host_isolation_registry, record.get("target_host")),
            "ip_blocked": (self.blocked_ips, record.get("target_ip")),
            "user_disabled": (self.disabled_users, record.get("target_user")),
        }
        restored = {}
        for key, (registry, value) in targets.items():
            if not effects[key]:
                continue
            if pre.get(key) or self._held_by_other_action(record, key):
                restored[key] = "kept (was already set before this action, or another active action holds it)"
                continue
            registry.discard(value)
            restored[key] = "restored to pre-action state"
        return restored


# action_type -> (reversibility, log builder, what cannot be restored)
ROLLBACK_PLAYBOOKS = {
    "QUARANTINE_EMAIL": (
        "FULL",
        lambda r: f"[MS Graph] Moved message {(r.get('context') or {}).get('message_id')} back to {r['target_user']}'s inbox.",
        None),
    "BLOCK_SOURCE_IP_FIREWALL": (
        "FULL",
        lambda r: f"[pfSense] Removed drop rule for {r['target_ip']}/32. Traffic unblocked.",
        None),
    "ISOLATE_HOST_AND_KILL_PROCESS": (
        "PARTIAL",
        lambda r: f"[WinRM -> {r['target_host']}] Removed SOC-Emergency-Isolation firewall rule. Network restored.",
        "The terminated process is not restarted."),
    "REVERT_DEFENDER_POLICY_AND_ISOLATE": (
        "PARTIAL",
        lambda r: f"[WinRM -> {r['target_host']}] Removed isolation rule. Network restored.",
        "Defender real-time protection stays re-enabled (intentionally not reverted to the tampered state)."),
    "REMOVE_SCHEDULED_TASK": (
        "FULL",
        lambda r: f"[WinRM -> {r['target_host']}] Re-enabled task {r['task_export']['task_name']} "
                  f"(exported XML sha256 {r['task_export']['sha256'][:12]}... kept for re-registration).",
        None),
    "KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS": (
        "PARTIAL",
        lambda r: f"[WinRM -> {r['target_host']}] Containment record released; restored files are kept.",
        "The killed process is not restarted and the VSS restore is not undone."),
    "UNLOAD_DRIVER_AND_ENFORCE_WDAC_BLOCK": (
        "PARTIAL",
        lambda r: f"[WinRM -> {r['target_host']}] Reverted WDAC policy to audit mode; driver loading allowed again.",
        "The unloaded driver is not reloaded automatically."),
    "TERMINATE_PROCESS_TREE": (
        "PARTIAL",
        lambda r: f"[AD LDAP] Re-enabled account {r['target_user']}.",
        "The terminated process tree is not restarted."),
    "RESET_SERVICE_ACCOUNT_AND_REVOKE_KERBEROS_TICKET": (
        "PARTIAL",
        lambda r: f"[AD LDAP] Cleared forced password change on {r['target_user']}.",
        "The old password and revoked tickets cannot be restored; dependent services need the new password."),
    "ISOLATE_ACCOUNT_AND_REVOKE_REPLICATION_PRIVILEGES": (
        "FULL",
        lambda r: f"[AD LDAP] Re-enabled {r['target_user']} and restored its pre-action replication rights.",
        None),
    "REVOKE_AWS_STS_SESSION_AND_ATTACH_DENY_POLICY": (
        "PARTIAL",
        lambda r: f"[AWS IAM] Removed AWSRevokeOlderSessions policy from {r['target_user']}.",
        "Already-revoked STS sessions stay revoked; callers must re-authenticate."),
    "REVOKE_ENTRA_REFRESH_TOKENS_AND_FORCE_MFA": (
        "PARTIAL",
        lambda r: f"[MS Graph] Cleared forced MFA re-challenge on {r['target_user']}.",
        "Revoked refresh tokens stay revoked; the user signs in again."),
}
