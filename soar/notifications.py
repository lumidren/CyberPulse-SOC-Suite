"""
Webhook Notification Dispatcher for CyberPulse SOC Suite
Dispatches real-time structured incident alerts to Discord, Slack, Telegram, or custom webhooks.
"""

import ipaddress
import json
import logging
import os
import urllib.request
import urllib.error
from urllib.parse import urlparse

logger = logging.getLogger("cyberpulse.notifications")

# Operators may opt in to internal/private webhook targets (e.g. an on-prem
# Mattermost) by setting ALLOW_INTERNAL_WEBHOOKS=true in the environment.
ALLOW_INTERNAL_WEBHOOKS = os.environ.get("ALLOW_INTERNAL_WEBHOOKS", "false").strip().lower() == "true"

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
        """Format alert as a high-visibility Discord Rich Embed"""
        rule = alert.get("rule", {})
        telemetry = alert.get("telemetry", {})
        intel = alert.get("threat_intel", {}).get("ip_reputation", {})
        soar_resp = alert.get("soar_response", {})
        timing = alert.get("pipeline_timing", {})

        severity = rule.get("severity", "MEDIUM")
        # Crimson for CRITICAL, Orange for HIGH, Cyan for others
        color = 16722517 if severity == "CRITICAL" else (16752384 if severity == "HIGH" else 58367)

        embed = {
            "title": f"🚨 [SOC ALERT] {rule.get('rule_name', 'Threat Detected')}",
            "description": f"**MITRE ATT&CK**: `{alert.get('telemetry', {}).get('technique_id', 'Unknown')}` - {alert.get('telemetry', {}).get('technique_name', '')}",
            "color": color,
            "fields": [
                {"name": "Alert ID", "value": f"`{alert.get('alert_id')}`", "inline": True},
                {"name": "Severity", "value": f"**{severity}**", "inline": True},
                {"name": "Target Host", "value": f"`{telemetry.get('computer_name', 'Unknown')}`", "inline": True},
                {"name": "Attacker IP", "value": f"`{telemetry.get('source_ip', 'Unknown')}`", "inline": True},
                {"name": "VirusTotal Rep", "value": f"{intel.get('virustotal_positives', 0)} / 72 Vendors", "inline": True},
                {"name": "AbuseIPDB Score", "value": f"{intel.get('abuse_score', 0)}% Confidence", "inline": True},
                {"name": "Automated SOAR Action", "value": f"✅ `{soar_resp.get('action_type', 'NONE')}`\n*{soar_resp.get('execution_log', '')}*", "inline": False},
                {"name": "Pipeline Latency", "value": f"⚡ Total: **{timing.get('total_pipeline_sec', 0)}s** (Ingest: {timing.get('stage1_detection_ms', 0)}ms | Contain: {timing.get('stage3_containment_ms', 0)}ms)", "inline": False}
            ],
            "footer": {
                "text": "CyberPulse SOC Suite | Automated SOAR Engine"
            },
            "timestamp": alert.get("timestamp")
        }

        return {"username": "CyberPulse SOC Bot", "embeds": [embed]}

    def format_slack_payload(self, alert):
        """Format alert as a Slack Block Kit payload"""
        rule = alert.get("rule", {})
        telemetry = alert.get("telemetry", {})
        soar_resp = alert.get("soar_response", {})

        return {
            "text": f"🚨 [SOC ALERT - {rule.get('severity')}] {rule.get('rule_name')}",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 [SOC ALERT] {rule.get('rule_name')}"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Technique:* `{telemetry.get('technique_id')}`"},
                        {"type": "mrkdwn", "text": f"*Severity:* *{rule.get('severity')}*"},
                        {"type": "mrkdwn", "text": f"*Host:* `{telemetry.get('computer_name')}`"},
                        {"type": "mrkdwn", "text": f"*Source IP:* `{telemetry.get('source_ip')}`"}
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*SOAR Action:* `{soar_resp.get('action_type')}`\n>{soar_resp.get('execution_log')}"}
                }
            ]
        }

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
            payload = alert

        try:
            req = urllib.request.Request(
                target_url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json', 'User-Agent': 'CyberPulse-SOC/2.0'}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                return {"status": "SUCCESS", "code": response.status}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

if __name__ == "__main__":
    print("[*] WebhookDispatcher ready.")
