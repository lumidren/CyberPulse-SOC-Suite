"""
Automatic user notification for suspicious sign-ins (roadmap F43) - off by default.

When an alert concerns a user's sign-in (impossible travel, brute force or spraying
against the account), the affected person can be told by email, so they can say "that
was me" or raise the alarm. Safeguards:

  * Off unless ``USER_NOTIFY_ENABLED=true`` and SMTP is configured
    (``USER_NOTIFY_SMTP_HOST``, ``_PORT`` (587), ``_USER``, ``_PASSWORD``, ``USER_NOTIFY_FROM``).
    STARTTLS is required; the message is never sent in clear text.
  * Never for simulated events: synthetic incidents must not email real people.
  * Only for accounts in the address book ``USER_NOTIFY_DIRECTORY`` (a JSON file mapping
    account name to email address); no address is guessed.
  * Never for protected or service accounts (soar/protected_assets.py), which are
    handled by the SOC directly.
  * At most one message per account per ``USER_NOTIFY_COOLDOWN_HOURS`` (24).
  * The message contains **no links and no incident details**: it tells the user to
    contact the help desk through a channel they already know (``USER_NOTIFY_HELPDESK``),
    so it cannot be mistaken for, or copied as, a phishing template.

Status: message building and every guard are unit-tested; no email has been sent.
"""

import json
import os
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage

from soar.protected_assets import protected_account_match

NOTIFY_TECHNIQUE_PREFIXES = ("T1078", "T1110")
SERVICE_PREFIXES = ("svc_", "svc-", "sa_", "srv_")


def _account(user):
    return str(user or "").split("\\")[-1].split("@")[0].strip()


def build_message(account, sender, recipient, helpdesk, when):
    msg = EmailMessage()
    msg["Subject"] = "Unusual sign-in activity on your account"
    msg["From"] = sender
    msg["To"] = recipient
    msg.set_content(
        f"Hello {account},\n\n"
        f"Our security monitoring noticed unusual sign-in activity on your work account around {when} (UTC).\n\n"
        "If you were signing in from a new place or device, no action is needed.\n"
        f"If you were not, please contact the IT help desk ({helpdesk}) using a phone number or "
        "channel you already know. Do not reply to this message, and never share your password.\n\n"
        "This message contains no links on purpose.\n"
    )
    return msg


class UserNotifier:
    def __init__(self, environ=os.environ, smtp_factory=smtplib.SMTP, clock=time.time):
        self.enabled = environ.get("USER_NOTIFY_ENABLED", "false").lower() == "true"
        self.host = environ.get("USER_NOTIFY_SMTP_HOST", "")
        self.port = int(environ.get("USER_NOTIFY_SMTP_PORT", "587"))
        self.user = environ.get("USER_NOTIFY_SMTP_USER", "")
        self.password = environ.get("USER_NOTIFY_SMTP_PASSWORD", "")
        self.sender = environ.get("USER_NOTIFY_FROM", "")
        self.helpdesk = environ.get("USER_NOTIFY_HELPDESK", "the IT help desk")
        self.cooldown = float(environ.get("USER_NOTIFY_COOLDOWN_HOURS", "24")) * 3600
        self.directory = {}
        path = environ.get("USER_NOTIFY_DIRECTORY", "")
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                self.directory = {str(k).lower(): str(v) for k, v in json.load(fh).items()}
        self._smtp = smtp_factory
        self._clock = clock
        self._last = {}
        self._lock = threading.Lock()

    def decide(self, incident):
        """(decision, account, recipient) without sending anything."""
        rule = incident.get("rule") or {}
        if not str(rule.get("mitre_id", "")).startswith(NOTIFY_TECHNIQUE_PREFIXES):
            return "NOT_A_SIGN_IN_ALERT", None, None
        if not (self.enabled and self.host and self.sender):
            return "DISABLED", None, None
        if incident.get("simulated"):
            return "SKIPPED_SIMULATED", None, None
        telemetry = incident.get("telemetry") or {}
        raw_user = telemetry.get("user") or (telemetry.get("details") or {}).get("TargetUserName")
        account = _account(raw_user)
        if not account:
            return "NO_ACCOUNT", None, None
        if account.lower().startswith(SERVICE_PREFIXES) or protected_account_match(raw_user):
            return "SKIPPED_PROTECTED_OR_SERVICE", account, None
        recipient = self.directory.get(account.lower())
        if not recipient:
            return "NO_ADDRESS", account, None
        with self._lock:
            if self._clock() - self._last.get(account.lower(), -1e18) < self.cooldown:
                return "SKIPPED_COOLDOWN", account, recipient
        return "SEND", account, recipient

    def notify(self, incident):
        """Send the notification if every guard allows it. Never raises."""
        decision, account, recipient = self.decide(incident)
        if decision != "SEND":
            return {"status": decision}
        msg = build_message(account, self.sender, recipient, self.helpdesk, incident.get("created_at", "")[:16])
        try:
            with self._smtp(self.host, self.port, timeout=15) as smtp:
                smtp.starttls(context=ssl.create_default_context())
                if self.user:
                    smtp.login(self.user, self.password)
                smtp.send_message(msg)
        except Exception as exc:
            return {"status": "ERROR", "message": type(exc).__name__}
        with self._lock:
            self._last[account.lower()] = self._clock()
        return {"status": "SENT", "account": account}
