"""
Webhook Notification Dispatcher for CyberPulse SOC Suite
Dispatches real-time structured incident alerts to Discord, Slack, Telegram, or custom webhooks.

Chat and webhook services are external, so payloads carry no internal identifiers:
host names become stable pseudonyms (``host-1a2b3c4d``), internal IPs are withheld,
usernames and execution logs are left out. The incident id points the analyst to the
console, where the full record is.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import urllib.request
import urllib.error
from urllib.parse import urlparse

logger = logging.getLogger("cyberpulse.notifications")

# Operators may opt in to internal/private webhook targets (e.g. an on-prem
# Mattermost) by setting ALLOW_INTERNAL_WEBHOOKS=true in the environment.
ALLOW_INTERNAL_WEBHOOKS = os.environ.get("ALLOW_INTERNAL_WEBHOOKS", "false").strip().lower() == "true"

# Per-deployment key for host pseudonyms; random per process when unset (pseudonyms then change on restart)
_PSEUDONYM_KEY = (os.environ.get("CYBERPULSE_PSEUDONYM_KEY") or secrets.token_hex(16)).encode("utf-8")


def pseudonym(value, prefix="host"):
    """Stable, non-reversible label for an internal identifier (keyed HMAC, 8 hex chars)."""
    if not value:
        return "unknown"
    return f"{prefix}-{hmac.new(_PSEUDONYM_KEY, str(value).lower().encode('utf-8'), hashlib.sha256).hexdigest()[:8]}"


# RFC 5737 documentation ranges: the lab's synthetic "external" attackers; not internal addresses
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def shareable_ip(value):
    """A public (or RFC 5737 documentation) source IP may be shown; internal addresses are withheld."""
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return "n/a"
    if ip.is_global or any(ip in net for net in _DOC_NETS):
        return str(ip)
    return "internal (see console)"


def external_summary(alert):
    """The only alert fields that leave the network: no hostnames, usernames, internal IPs or logs."""
    rule = alert.get("rule", {}) or {}
    telemetry = alert.get("telemetry", {}) or {}
    action = alert.get("soar_response") or alert.get("containment_action") or {}
    return {
        "incident_id": alert.get("incident_id") or alert.get("alert_id"),
        "rule_id": rule.get("rule_id"),
        "rule_name": rule.get("rule_name"),
        "severity": rule.get("severity"),
        "technique_id": rule.get("mitre_id") or telemetry.get("technique_id"),
        "host": pseudonym(telemetry.get("computer_name")),
        "source_ip": shareable_ip(telemetry.get("source_ip")),
        "action_type": action.get("action_type"),
        "action_status": action.get("status"),
        "simulated": bool(alert.get("simulated")),
    }


def validate_webhook_url(url):
    """SSRF guard for analyst-supplied webhook URLs.

    Rejects non-HTTP(S) schemes and, unless ALLOW_INTERNAL_WEBHOOKS is set,
    literal private/loopback/link-local/reserved IP targets. Returns
    (is_valid, reason).
    """
    try:
        parsed = urlparse(url or "")
    except ValueError:
        return False, "Unparseable URL"

    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{parsed.scheme}'; only http/https webhooks are allowed."

    host = parsed.hostname
    if not host:
        return False, "URL is missing a hostname."

    if ALLOW_INTERNAL_WEBHOOKS:
        return True, ""

    if host.lower() in ("localhost",):
        return False, "Loopback webhook targets are blocked (set ALLOW_INTERNAL_WEBHOOKS=true to permit)."

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False, "Private/internal IP webhook targets are blocked (set ALLOW_INTERNAL_WEBHOOKS=true to permit)."
    except ValueError:
        pass  # Hostname, not a literal IP

    return True, ""

class WebhookDispatcher:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url or os.environ.get("SOC_WEBHOOK_URL")

    def format_discord_payload(self, alert):
        """Discord embed built only from external_summary() fields."""
        s = external_summary(alert)
        color = 16722517 if s["severity"] == "CRITICAL" else (16752384 if s["severity"] == "HIGH" else 58367)
        embed = {
            "title": f"[SOC ALERT] {s['rule_name'] or 'Threat Detected'}",
            "description": f"**MITRE ATT&CK**: `{s['technique_id']}`" + (" (simulated)" if s["simulated"] else ""),
            "color": color,
            "fields": [
                {"name": "Incident", "value": f"`{s['incident_id']}`", "inline": True},
                {"name": "Severity", "value": f"**{s['severity']}**", "inline": True},
                {"name": "Host", "value": f"`{s['host']}`", "inline": True},
                {"name": "Source IP", "value": f"`{s['source_ip']}`", "inline": True},
                {"name": "Response", "value": f"`{s['action_type']}` ({s['action_status']})", "inline": False},
            ],
            "footer": {"text": "CyberPulse SOC Suite | details in the console"},
            "timestamp": alert.get("timestamp"),
        }
        return {"username": "CyberPulse SOC Bot", "embeds": [embed]}

    def format_slack_payload(self, alert):
        """Slack Block Kit message built only from external_summary() fields."""
        s = external_summary(alert)
        return {
            "text": f"[SOC ALERT - {s['severity']}] {s['rule_name']} ({s['incident_id']})",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"[SOC ALERT] {s['rule_name']}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Technique:* `{s['technique_id']}`"},
                    {"type": "mrkdwn", "text": f"*Severity:* *{s['severity']}*"},
                    {"type": "mrkdwn", "text": f"*Host:* `{s['host']}`"},
                    {"type": "mrkdwn", "text": f"*Source IP:* `{s['source_ip']}`"},
                ]},
                {"type": "section", "text": {"type": "mrkdwn",
                                             "text": f"*Response:* `{s['action_type']}` ({s['action_status']}); "
                                                     f"incident `{s['incident_id']}` in the console"}},
            ],
        }

    def dispatch_text(self, text, custom_webhook_url=None):
        """Send a plain-text page (e.g. circuit-breaker trip) to the configured webhook."""
        target_url = custom_webhook_url or self.webhook_url
        if not target_url:
            logger.critical("PAGE (no webhook configured): %s", text)
            return {"status": "SKIPPED", "message": "No webhook URL configured; page written to the log."}
        is_valid, reason = validate_webhook_url(target_url)
        if not is_valid:
            logger.critical("PAGE (webhook blocked: %s): %s", reason, text)
            return {"status": "BLOCKED", "error": f"Webhook URL rejected: {reason}"}
        payload = {"content": text} if "discord.com" in target_url else {"text": text}
        try:
            req = urllib.request.Request(
                target_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "CyberPulse-SOC/2.0"}
            )
            # nosec B310: scheme restricted to http/https by validate_webhook_url() above
            with urllib.request.urlopen(req, timeout=5) as response:  # nosec B310
                return {"status": "SUCCESS", "code": response.status}
        except Exception as e:
            logger.critical("PAGE (delivery failed: %s): %s", e, text)
            return {"status": "ERROR", "error": str(e)}

    def dispatch(self, alert, custom_webhook_url=None):
        """Transmit webhook payload to configured endpoint"""
        target_url = custom_webhook_url or self.webhook_url
        if not target_url:
            return {"status": "SKIPPED", "message": "No webhook URL configured (local mode)."}

        is_valid, reason = validate_webhook_url(target_url)
        if not is_valid:
            logger.warning("Blocked webhook dispatch to %r: %s", target_url, reason)
            return {"status": "BLOCKED", "error": f"Webhook URL rejected: {reason}"}

        # Auto-detect webhook type
        if "discord.com" in target_url:
            payload = self.format_discord_payload(alert)
        elif "hooks.slack.com" in target_url:
            payload = self.format_slack_payload(alert)
        else:
            payload = external_summary(alert)

        try:
            req = urllib.request.Request(
                target_url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json', 'User-Agent': 'CyberPulse-SOC/2.0'}
            )
            # nosec B310: scheme restricted to http/https by validate_webhook_url() above
            with urllib.request.urlopen(req, timeout=5) as response:  # nosec B310
                return {"status": "SUCCESS", "code": response.status}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

if __name__ == "__main__":
    print("[*] WebhookDispatcher ready.")
