#!/usr/bin/env python3
"""
Generate docs/AUTOMATED_ACTIONS.md (roadmap E93): every automated action, what it does,
who must approve it, how it is undone, and how it can fail.

    python scripts/document_actions.py           # write the doc
    python scripts/document_actions.py --check   # exit 1 if stale

Tier and reversibility come from the code (soar/action_tiers.py, ROLLBACK_PLAYBOOKS),
so they cannot drift; the descriptions and failure modes below are maintained by hand,
and a test fails if an action exists in code without an entry here.
"""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.action_tiers import ACTION_TIERS, requires_approval  # noqa: E402
from soar.resilient_containment import ROLLBACK_PLAYBOOKS  # noqa: E402

REPORT = os.path.join(ROOT, "docs", "AUTOMATED_ACTIONS.md")

# action: (what it does, failure modes)
CONTAINMENT = {
    "BLOCK_SOURCE_IP_FIREWALL": (
        "Adds a perimeter drop rule for one source IP (pfSense / iptables).",
        "Blocking a shared address (VPN, NAT, CDN) cuts off legitimate users; an attacker changes IP and the "
        "block only adds noise; the firewall API is down so the block silently does not exist."),
    "ISOLATE_HOST_AND_KILL_PROCESS": (
        "Network-isolates a host (WinRM) and terminates the offending process.",
        "Isolating a server stops a business service; killing the wrong PID; isolation succeeds but the kill "
        "fails (or the reverse); the host is unreachable so nothing happens while the record says it ran."),
    "REVERT_DEFENDER_POLICY_AND_ISOLATE": (
        "Restores Defender real-time protection settings and isolates the host.",
        "A legitimate admin change is reverted; isolation of a critical host; a GPO reapplies the attacker's "
        "setting after the revert."),
    "REMOVE_SCHEDULED_TASK": (
        "Exports, then deletes or disables the malicious scheduled task.",
        "A legitimate maintenance task with similar content is removed; the attacker has other persistence, "
        "so removal gives false comfort."),
    "KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS": (
        "Graceful-then-forced kill of the encrypting process and restore from shadow copies.",
        "A backup or sync tool that writes many files is killed; shadow copies were already deleted, so restore "
        "fails; restoring overwrites files a user changed legitimately."),
    "UNLOAD_DRIVER_AND_ENFORCE_WDAC_BLOCK": (
        "Unloads a vulnerable driver and adds it to the WDAC block policy.",
        "Blocking a driver that hardware needs (storage, network) can leave the host unbootable or offline."),
    "QUARANTINE_EMAIL": (
        "Moves one message to a quarantine folder via Microsoft Graph.",
        "A legitimate but unusual email (invoice, HR notice) is hidden from its recipient; copies in other "
        "mailboxes are not touched."),
    "TERMINATE_PROCESS_TREE": (
        "Terminates a process tree and locks the user account involved.",
        "A user loses unsaved work and access; locking a shared or service account stops a business process."),
    "RESET_SERVICE_ACCOUNT_AND_REVOKE_KERBEROS_TICKET": (
        "Forces a password reset on a service account and purges its Kerberos tickets.",
        "Every service using that account fails until its stored credential is updated."),
    "ISOLATE_ACCOUNT_AND_REVOKE_REPLICATION_PRIVILEGES": (
        "Removes directory-replication rights from an account and locks it.",
        "Removing replication rights from a real domain controller or sync service breaks replication."),
    "REVOKE_AWS_STS_SESSION_AND_ATTACH_DENY_POLICY": (
        "Attaches a deny-older-sessions policy to an IAM principal, invalidating active sessions.",
        "CI/CD pipelines and workloads using the role fail until they re-authenticate."),
    "REVOKE_ENTRA_REFRESH_TOKENS_AND_FORCE_MFA": (
        "Revokes Entra ID sessions and adds the account to an MFA step-up group (live only when configured).",
        "The user is signed out everywhere; if the Conditional Access policy is misconfigured, step-up never "
        "triggers or locks the user out; the Graph call fails midway (flagged for manual follow-up)."),
}

# Automated side effects that are not containment
SIDE_EFFECTS = [
    ("Chat notification", "notifications.py", "Default on when a webhook URL is set",
     "Pseudonymised summary sent to Slack/Discord/custom webhook.", "Webhook down: alert not delivered (logged)."),
    ("User sign-in email", "user_notify.py", "Off (USER_NOTIFY_ENABLED)",
     "Emails the affected user about a suspicious sign-in.", "Wrong address in the address book informs the wrong person; message filtered as spam."),
    ("TheHive alert", "thehive.py", "Off (THEHIVE_ENABLED)", "Creates a TheHive alert per incident.",
     "TheHive down: recorded as ERROR, local case record remains."),
    ("Shuffle / n8n hand-off", "orchestrator_hook.py", "Off (ORCHESTRATOR_WEBHOOK_URL)",
     "Signed POST of the incident to an external orchestrator.", "A workflow acts without asking a human (the receiving workflow's design)."),
    ("Threat-intel lookups", "enrichment.py, intel_providers.py", "Off (EXTERNAL_ENRICHMENT_ENABLED)",
     "Public IPs and hashes sent to reputation providers.",
     "Provider wrong or rate-limited: verdict missing or misleading; scores are corroborated, never decisive alone."),
    ("Sandbox look-ups", "sandbox.py", "Off (SANDBOX_URL)", "Hash look-up in a lab sandbox; URL detonation only if opted in.",
     "Detonation tips off the sender (hence opt-in)."),
    ("Triage package to disk", "triage_package.py", "Off (TRIAGE_PACKAGE_DIR)", "Writes a zip of incident data per incident.",
     "Disk fills or folder is readable by others: personal data exposure."),
    ("Containment expiry (TTL)", "safety.py, resilient_containment.py", "On", "Rolls back containment when its TTL ends.",
     "An attacker still present regains access when the TTL expires unless an analyst extended it."),
    ("Retention purge", "soar_engine.py apply_retention", "On (RETENTION_DAYS)", "Deletes incidents, cases and custody logs past retention.",
     "Evidence needed for a late investigation is gone; export triage packages first."),
]


def render():
    lines = [
        "# Automated Actions and Their Failure Modes",
        "",
        "> Generated by `python scripts/document_actions.py`. Tier, approval and reversibility are read from",
        "> the code; descriptions and failure modes are maintained in that script.",
        "",
        "Every containment action below is **staged for analyst approval by default**. Only TIER_1 actions may run",
        "on their own, and only in opt-in AUTOMATIC mode with the kill switch, hourly rate limit, isolation circuit",
        "breaker, protected-asset list and TTL in force. Every action is logged with who, what, why and when, and",
        "can be rolled back to the extent the Reversibility column says.",
        "",
        "## Containment actions",
        "",
        "| Action | Tier | Needs approval | Reversibility | What it does | How it can fail |",
        "| :--- | :--- | :---: | :--- | :--- | :--- |",
    ]
    for action, tier in ACTION_TIERS.items():
        what, failure = CONTAINMENT[action]
        reversibility = (ROLLBACK_PLAYBOOKS.get(action) or ("NONE",))[0]
        approval = "always" if requires_approval(action) else "unless opt-in AUTOMATIC"
        lines.append(f"| `{action}` | {tier} | {approval} | {reversibility} | {what} | {failure} |")
    lines += ["", "PARTIAL means some effects cannot be undone (a killed process, revoked sessions, a reset password);",
              "the rollback record lists what was not restored.", "",
              "## Other automated side effects", "",
              "| Side effect | Code | Default | What happens | How it can fail |", "| :--- | :--- | :--- | :--- | :--- |"]
    lines += [f"| {name} | `{code}` | {default} | {what} | {failure} |" for name, code, default, what, failure in SIDE_EFFECTS]
    lines += ["", "## When automation itself fails", "",
              "- Responder unreachable: the circuit breaker opens and actions are flagged for manual review, never retried blindly.",
              "- Command validation fails (malformed host, user or path): nothing is built or sent; flagged for manual review.",
              "- Too many actions: the hourly budget stages the rest for approval; mass isolation trips the circuit breaker,",
              "  which engages the kill switch and pages a human.",
              "- Kill switch engaged: every new action and every approval is refused until a lead releases it.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Document automated actions")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    body = render()
    if args.check:
        try:
            with open(REPORT, encoding="utf-8") as fh:
                sys.exit(0 if fh.read().replace("\r\n", "\n") == body else 1)
        except FileNotFoundError:
            sys.exit(1)
    with open(REPORT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)
    print(f"wrote {os.path.relpath(REPORT, ROOT)}")


if __name__ == "__main__":
    main()
