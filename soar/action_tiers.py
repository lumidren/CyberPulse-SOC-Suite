"""
Blast-Radius Tiers for Containment Actions (CyberPulse SOC Lab)

Each containment action is assigned a tier describing how much legitimate
business activity it can disrupt if it is wrong:

* TIER_1_AUTO_ELIGIBLE - narrow, reversible, external-facing (block one
  external IP at the perimeter). May run without approval, but only when the
  operator has opted into AUTOMATIC mode.
* TIER_2_HOST - disrupts a whole host (isolation, process kill, task or
  driver removal). Always needs analyst approval.
* TIER_3_IDENTITY - disables or resets an account or revokes sessions,
  which can lock people out of everything. Always needs analyst approval.

Unknown actions default to the most restrictive tier.
"""

TIER_1_AUTO_ELIGIBLE = "TIER_1_AUTO_ELIGIBLE"
TIER_2_HOST = "TIER_2_HOST"
TIER_3_IDENTITY = "TIER_3_IDENTITY"

ACTION_TIERS = {
    "BLOCK_SOURCE_IP_FIREWALL": TIER_1_AUTO_ELIGIBLE,

    "ISOLATE_HOST_AND_KILL_PROCESS": TIER_2_HOST,
    "REVERT_DEFENDER_POLICY_AND_ISOLATE": TIER_2_HOST,
    "REMOVE_SCHEDULED_TASK": TIER_2_HOST,
    "KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS": TIER_2_HOST,
    "UNLOAD_DRIVER_AND_ENFORCE_WDAC_BLOCK": TIER_2_HOST,

    "TERMINATE_PROCESS_TREE": TIER_3_IDENTITY,  # also locks the user account
    "RESET_SERVICE_ACCOUNT_AND_REVOKE_KERBEROS_TICKET": TIER_3_IDENTITY,
    "ISOLATE_ACCOUNT_AND_REVOKE_REPLICATION_PRIVILEGES": TIER_3_IDENTITY,
    "REVOKE_AWS_STS_SESSION_AND_ATTACH_DENY_POLICY": TIER_3_IDENTITY,
    "REVOKE_ENTRA_REFRESH_TOKENS_AND_FORCE_MFA": TIER_3_IDENTITY,
}

TIER_DESCRIPTIONS = {
    TIER_1_AUTO_ELIGIBLE: "Narrow and reversible; may auto-run only in opt-in AUTOMATIC mode.",
    TIER_2_HOST: "Disrupts a whole host; always requires analyst approval.",
    TIER_3_IDENTITY: "Locks or resets an identity; always requires analyst approval.",
}


def tier_for(action_type):
    """Blast-radius tier for an action; unknown actions get the strictest tier."""
    return ACTION_TIERS.get(action_type, TIER_3_IDENTITY)


def requires_approval(action_type):
    """True if the action may never run without an analyst approving it."""
    return tier_for(action_type) != TIER_1_AUTO_ELIGIBLE
