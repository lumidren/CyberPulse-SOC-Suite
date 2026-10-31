"""
Example responder plugin: a non-disruptive "notify the asset owner" action.

Enable with CYBERPULSE_PLUGINS=notify_only_responder. Simulated: it only
records what it would do. Because NOTIFY_ASSET_OWNER is not in
soar/action_tiers.py it gets the strictest tier, so it still waits for an
analyst like every unknown action.
"""

from soar.plugins import register_responder


@register_responder("NOTIFY_ASSET_OWNER")
def notify_asset_owner(action_record):
    action_record["execution_protocol"] = "Plugin: notify_only_responder (simulated)"
    action_record["execution_log"] = (
        f"Would notify the owner of {action_record.get('target_host')} about the incident. No system change."
    )
    action_record["rollback_plan"] = {"method": "NONE", "note": "Notification only; nothing to roll back."}
