"""
Multi-Factor Risk & Policy Decision Engine for CyberPulse SOC Suite
Calculates composite risk scores based on Asset Criticality, Account Privilege, 
MITRE Tactic Weight, Threat Intel Reputation, and Historical Frequency.
"""

import json
import os
import time

from soar.action_tiers import requires_approval, tier_for

# Asset Criticality Dictionary (0.0 to 1.0)
ASSET_CRITICALITY = {
    "WIN-DC01.corp.local": 1.0,    # Domain Controller (Tier 0)
    "WIN-DC01": 1.0,
    "CORP-FINANCE-02": 0.9,       # High-Value Financial Asset (Tier 1)
    "CORP-RDP-GW01": 0.85,        # Perimeter Access Gateway (Tier 1)
    "WIN-WORKSTATION09": 0.60,    # Standard Client Endpoint (Tier 2)
    "DEFAULT": 0.60
}

# User Account Privilege Context (0.0 to 1.0)
ACCOUNT_PRIVILEGES = {
    "CORP\\Administrator": 1.0,
    "admin": 1.0,
    "administrator": 1.0,
    "root": 1.0,
    "CORP\\finance_admin": 0.85,
    "service_acct": 0.80,
    "CORP\\j.doe": 0.50,
    "CORP\\m.worker": 0.50,
    "DEFAULT": 0.50
}

# MITRE Tactic Severity Weights (0.0 to 1.0)
TACTIC_WEIGHTS = {
    "Impact": 1.0,
    "Credential Access": 0.95,
    "Defense Evasion": 0.95,
    "Persistence": 0.85,
    "Execution": 0.80,
    "Initial Access": 0.75,
    "DEFAULT": 0.70
}

class RiskAndPolicyEngine:
    def __init__(self, policy_mode="APPROVAL_REQUIRED"):
        """
        Policy Modes:
        - 'APPROVAL_REQUIRED' (default): Stage containment as PENDING_APPROVAL for analyst sign-off.
        - 'AUTOMATIC': Execute containment when the risk threshold is met (explicit opt-in only).
        - 'DRY_RUN': Simulate and log containment with zero network/host disruption.
        """
        self.policy_mode = policy_mode
        self.incident_history = []
        self.ip_frequency = {}

    def calculate_risk_score(self, event, matched_rule, intel):
        """
        Computes an explainable, multi-factor risk score from 0.0 to 100.0
        """
        host = event.get("computer_name", "DEFAULT")
        user = event.get("user", "DEFAULT")
        tactic = event.get("tactic", "DEFAULT")
        source_ip = event.get("source_ip", "")

        # 1. Asset Criticality Factor (0 - 100)
        asset_weight = ASSET_CRITICALITY.get(host, ASSET_CRITICALITY["DEFAULT"]) * 100

        # 2. User Privilege Factor (0 - 100)
        user_weight = ACCOUNT_PRIVILEGES.get(user, ACCOUNT_PRIVILEGES["DEFAULT"]) * 100

        # 3. Tactic Severity Factor (0 - 100)
        tactic_weight = TACTIC_WEIGHTS.get(tactic, TACTIC_WEIGHTS["DEFAULT"]) * 100

        # 4. Detection Rule Confidence Factor (0 - 100)
        rule_severity = matched_rule.get("severity", "MEDIUM")
        rule_base_score = 98.0 if rule_severity == "CRITICAL" else (82.0 if rule_severity == "HIGH" else 55.0)

        # 5. Threat Intelligence Reputation Factor (0 - 100)
        ip_intel = intel.get("ip_reputation", {})
        vt_positives = ip_intel.get("virustotal_positives", 0)
        abuse_score = ip_intel.get("abuse_score", 0)
        intel_score = min(100.0, (vt_positives / 72.0 * 60.0) + (abuse_score * 0.4))

        # 6. Historical Repeat Offender Weight (0 - 100)
        self.ip_frequency[source_ip] = self.ip_frequency.get(source_ip, 0) + 1
        history_bonus = min(15.0, (self.ip_frequency[source_ip] - 1) * 5.0)

        # Multi-factor Weighted Composite Formula
        composite_score = (
            (rule_base_score * 0.35) +
            (tactic_weight * 0.25) +
            (asset_weight * 0.15) +
            (user_weight * 0.10) +
            (intel_score * 0.15) +
            history_bonus
        )

        final_score = round(min(100.0, max(0.0, composite_score)), 1)

        # Risk Classification
        if final_score >= 80.0:
            risk_level = "CRITICAL"
        elif final_score >= 65.0:
            risk_level = "HIGH"
        elif final_score >= 40.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        breakdown = {
            "final_score": final_score,
            "risk_level": risk_level,
            "factors": {
                "rule_base_score": round(rule_base_score, 1),
                "tactic_weight": round(tactic_weight, 1),
                "asset_criticality": round(asset_weight, 1),
                "user_privilege": round(user_weight, 1),
                "threat_intel_score": round(intel_score, 1),
                "repeat_incident_bonus": round(history_bonus, 1)
            }
        }
        return breakdown

    def _containment_intent(self, action, decision):
        """Decide how a containment action may proceed given mode and blast-radius tier.

        DRY_RUN only logs. Anything else is staged for approval, except that in
        opt-in AUTOMATIC mode a TIER_1 (narrow, reversible) action may run.
        """
        if self.policy_mode == "DRY_RUN":
            return "DRY_RUN_SIMULATION"
        if self.policy_mode == "AUTOMATIC" and not requires_approval(action):
            return "EXECUTE_IMMEDIATE"
        decision["approval_token"] = f"APPR-{int(time.time())}"
        if self.policy_mode == "AUTOMATIC":
            decision["approval_reason"] = f"{tier_for(action)} actions always require analyst approval."
        return "PENDING_APPROVAL"

    def evaluate_policy(self, risk_assessment, matched_rule):
        """
        Determines the automated response action based on risk level and policy mode.
        """
        risk_level = risk_assessment["risk_level"]
        score = risk_assessment["final_score"]
        action_recommended = matched_rule.get("action_recommended", "LOG_AND_MONITOR")

        decision = {
            "policy_id": "POL-LAB-DEFAULT-v2.5",
            "risk_level": risk_level,
            "risk_score": score,
            "mode": self.policy_mode,
            "action": action_recommended,
            "execution_intent": "EXECUTE",
            "approval_token": None,
            "blast_radius_tier": tier_for(action_recommended),
            "rationale": ""
        }

        if score >= 80.0 or matched_rule.get("severity") == "CRITICAL":
            decision["rationale"] = f"Critical risk score ({score}/100) or Critical rule trigger. Proposing containment for analyst review."
            decision["execution_intent"] = self._containment_intent(action_recommended, decision)

        elif score >= 65.0:
            decision["rationale"] = f"High risk score ({score}/100). Proposing targeted mitigation and opening a high-priority incident."
            decision["execution_intent"] = self._containment_intent(action_recommended, decision)

        elif score >= 40.0:
            decision["action"] = "ENRICH_AND_ALERT_ANALYST"
            decision["execution_intent"] = "ALERT_ONLY"
            decision["rationale"] = f"Medium risk score ({score}/100). Threat intelligence enriched; alerting Tier-1 SOC queue."

        else:
            decision["action"] = "LOG_AND_MONITOR"
            decision["execution_intent"] = "LOG_ONLY"
            decision["rationale"] = f"Low risk score ({score}/100). Event indexed in SIEM baseline."

        return decision
