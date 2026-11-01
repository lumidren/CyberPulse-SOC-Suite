"""
ChatOps approval buttons (roadmap F31): approve or reject staged containment from
Slack, Microsoft Teams or Telegram.

Automation stays approval-required: a button press is a human approval, handled by
the same ``approve_action`` / ``reject_action`` path as the console, with the same
kill-switch, protected-asset and rate-limit checks. What a chat platform can do:

  * Slack: interactive message buttons. Requests to ``POST /api/chatops/slack`` are
    verified with the Slack signing secret (``SLACK_SIGNING_SECRET``; v0 HMAC over
    timestamp and body, 5-minute replay window).
  * Telegram: inline keyboard buttons. Updates to ``POST /api/chatops/telegram`` must
    carry ``X-Telegram-Bot-Api-Secret-Token`` equal to ``TELEGRAM_WEBHOOK_SECRET``
    (set when registering the bot webhook).
  * Teams: incoming-webhook cards cannot call back without a registered bot, so the
    Teams card's buttons open the console's approval queue instead.

Only platform user ids listed in ``CHATOPS_APPROVERS`` (``slack:U0123,telegram:42``)
may approve or reject; anyone else gets a refusal and an audit log entry. Messages
use host pseudonyms, never host names (they go to an external service).

Status: implemented and tested with locally signed requests; not yet exercised with
a real Slack app or Telegram bot.
"""

import hashlib
import hmac
import json
import logging
import os
import time
from urllib.parse import parse_qs

from soar.notifications import pseudonym

audit_logger = logging.getLogger("cyberpulse.audit")
SLACK_MAX_SKEW_SEC = 300
DECISIONS = {"approve", "reject"}


def parse_approvers(value):
    approvers = {}
    for item in (value or "").split(","):
        platform, _, user = item.strip().partition(":")
        if platform and user:
            approvers.setdefault(platform.lower(), set()).add(user)
    return approvers


def _button_value(decision, action_id):
    return f"{decision}:{action_id}"


def _parse_button(value):
    decision, _, action_id = str(value or "").partition(":")
    return (decision, action_id) if decision in DECISIONS and action_id.startswith("ACT-") else (None, None)


def _describe(record):
    return (f"{record.get('action_type')} on {pseudonym(record.get('target_host'))} "
            f"(action {record.get('action_id')}, tier {record.get('blast_radius_tier', 'n/a')})")


def slack_approval_message(record):
    return {
        "text": f"Approval needed: {_describe(record)}",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Containment awaiting approval*\n{_describe(record)}"}},
            {"type": "actions", "elements": [
                {"type": "button", "style": "danger", "text": {"type": "plain_text", "text": "Approve"},
                 "action_id": "cyberpulse_approve", "value": _button_value("approve", record["action_id"])},
                {"type": "button", "text": {"type": "plain_text", "text": "Reject"},
                 "action_id": "cyberpulse_reject", "value": _button_value("reject", record["action_id"])},
            ]},
        ],
    }


def telegram_approval_message(record, chat_id):
    return {
        "chat_id": chat_id,
        "text": f"Containment awaiting approval: {_describe(record)}",
        "reply_markup": {"inline_keyboard": [[
            {"text": "Approve", "callback_data": _button_value("approve", record["action_id"])},
            {"text": "Reject", "callback_data": _button_value("reject", record["action_id"])},
        ]]},
    }


def teams_approval_card(record, console_url):
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "type": "AdaptiveCard", "version": "1.4",
                "body": [{"type": "TextBlock", "weight": "Bolder", "text": "Containment awaiting approval"},
                         {"type": "TextBlock", "wrap": True, "text": _describe(record)}],
                "actions": [{"type": "Action.OpenUrl", "title": "Review in console",
                             "url": f"{console_url.rstrip('/')}/#approvals"}],
            },
        }],
    }


class ChatOpsApprovals:
    def __init__(self, engine, slack_secret=None, telegram_secret=None, approvers=None, clock=time.time):
        self.engine = engine
        self.slack_secret = slack_secret if slack_secret is not None else os.environ.get("SLACK_SIGNING_SECRET", "")
        self.telegram_secret = (telegram_secret if telegram_secret is not None
                                else os.environ.get("TELEGRAM_WEBHOOK_SECRET", ""))
        self.approvers = approvers if approvers is not None else parse_approvers(os.environ.get("CHATOPS_APPROVERS"))
        self.clock = clock

    # ------------------------------------------------------------------ verification
    def verify_slack(self, timestamp, signature, raw_body):
        if not self.slack_secret:
            return False, "Slack approvals disabled: SLACK_SIGNING_SECRET not set"
        try:
            ts = int(timestamp)
        except (TypeError, ValueError):
            return False, "missing or invalid X-Slack-Request-Timestamp"
        if abs(self.clock() - ts) > SLACK_MAX_SKEW_SEC:
            return False, "stale request (replay window exceeded)"
        expected = "v0=" + hmac.new(self.slack_secret.encode("utf-8"), f"v0:{ts}:".encode("ascii") + raw_body,
                                    hashlib.sha256).hexdigest()
        if not signature or not hmac.compare_digest(expected, str(signature)):
            return False, "bad Slack signature"
        return True, "ok"

    def verify_telegram(self, token):
        if not self.telegram_secret:
            return False, "Telegram approvals disabled: TELEGRAM_WEBHOOK_SECRET not set"
        if not token or not hmac.compare_digest(self.telegram_secret, str(token)):
            return False, "bad Telegram secret token"
        return True, "ok"

    # ------------------------------------------------------------------ decisions
    def _decide(self, platform, user, value):
        decision, action_id = _parse_button(value)
        if not decision:
            return {"status": "ERROR", "message": "unrecognised button"}
        if user not in self.approvers.get(platform, set()):
            audit_logger.warning("CHATOPS_REFUSED platform=%s user=%s action=%s decision=%s",
                                 platform, user, action_id, decision)
            return {"status": "ERROR", "message": "you are not an authorised approver"}
        actor = f"{platform}:{user}"
        audit_logger.info("CHATOPS_DECISION platform=%s user=%s action=%s decision=%s", platform, user, action_id, decision)
        if decision == "approve":
            result = self.engine.approve_action(action_id, approver=actor, comment=f"approved via {platform}")
        else:
            result = self.engine.reject_action(action_id, approver=actor, reason=f"rejected via {platform}")
        # Engine messages can name hosts or accounts; the reply goes to an external chat service
        if result.get("status") == "SUCCESS":
            return {"status": "SUCCESS", "message": f"{decision} recorded for {action_id}"}
        audit_logger.info("CHATOPS_NOT_APPLIED action=%s detail=%s", action_id, result.get("message"))
        return {"status": "ERROR", "message": f"{decision} not applied to {action_id}; see the console for why"}

    def handle_slack(self, raw_body):
        form = parse_qs(raw_body.decode("utf-8", errors="replace"))
        try:
            payload = json.loads(form.get("payload", ["{}"])[0])
            action = (payload.get("actions") or [{}])[0]
            user = (payload.get("user") or {}).get("id")
        except (ValueError, AttributeError):
            return {"status": "ERROR", "message": "malformed Slack payload"}
        result = self._decide("slack", user, action.get("value"))
        return {"replace_original": False, "text": f"CyberPulse: {result.get('status')} - {result.get('message', '')}".strip()}

    def handle_telegram(self, update):
        query = update.get("callback_query") or {}
        user = str((query.get("from") or {}).get("id", ""))
        result = self._decide("telegram", user, query.get("data"))
        return {"method": "answerCallbackQuery", "callback_query_id": query.get("id"),
                "text": f"{result.get('status')}: {result.get('message', '')}"[:200]}
