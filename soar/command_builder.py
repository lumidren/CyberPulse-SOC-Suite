"""
Injection-Safe Responder Command Builder (CyberPulse SOC Lab)

Responder commands are built as argv lists or structured invocations from
validated values, never by concatenating strings. A value that fails
validation raises CommandValidationError and the action is not built at all,
so a hostile hostname, username or task name in telemetry cannot smuggle in
extra arguments or a second command.
"""

import ipaddress
import re
from urllib.parse import quote


class CommandValidationError(ValueError):
    """A value destined for a responder command failed validation."""


_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
_ACCOUNT_RE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9-]{0,14}\\)?[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TASK_NAME_RE = re.compile(r"^\\[A-Za-z0-9 _.\\-]{1,200}$")
_UPN_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}(@[A-Za-z0-9.-]{1,190})?$")


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        raise CommandValidationError(f"not an IP address: {str(value)[:60]!r}")


def valid_hostname(value):
    if not isinstance(value, str) or not _HOSTNAME_RE.match(value):
        raise CommandValidationError(f"not a valid hostname: {str(value)[:60]!r}")
    return value


def valid_account(value):
    """sAMAccountName with optional NetBIOS domain, e.g. CORP\\j.doe. No quotes, spaces or shell metacharacters."""
    if not isinstance(value, str) or not _ACCOUNT_RE.match(value):
        raise CommandValidationError(f"not a valid account name: {str(value)[:60]!r}")
    return value


def valid_task_name(value):
    if not isinstance(value, str) or not _TASK_NAME_RE.match(value) or ".." in value:
        raise CommandValidationError(f"not a valid scheduled task path: {str(value)[:60]!r}")
    return value


def valid_pid(value):
    try:
        pid = int(value)
    except (TypeError, ValueError):
        raise CommandValidationError(f"not a PID: {value!r}")
    if not 4 < pid < 4_194_304:
        raise CommandValidationError(f"PID out of range: {pid}")
    return pid


def valid_upn(value):
    if not isinstance(value, str) or not _UPN_RE.match(value):
        raise CommandValidationError(f"not a valid user principal name: {str(value)[:60]!r}")
    return value


# ------------------------------------------------------- PowerShell over WinRM (E71)
# Only these cmdlets, with these named parameters and value checks, can be built.
# The responder must pass `parameters` as a splatted hashtable to a fixed wrapper
# (param($Cmdlet, $Params) & $Cmdlet @Params) - never interpolate into script text.
ISOLATION_RULE = "SOC-Emergency-Isolation"
PS_CMDLETS = {
    "Set-ADUser": {"Identity": valid_account, "Enabled": bool, "ChangePasswordAtLogon": bool},
    "Disable-ADAccount": {"Identity": valid_account},
    "Enable-ADAccount": {"Identity": valid_account},
    "New-NetFirewallRule": {"DisplayName": {ISOLATION_RULE}, "Direction": {"Inbound", "Outbound"},
                            "Action": {"Block", "Allow"}, "RemoteAddress": valid_ip},
    "Remove-NetFirewallRule": {"DisplayName": {ISOLATION_RULE}},
    "Set-MpPreference": {"DisableRealtimeMonitoring": bool},
}


def ps_invocation(cmdlet, **params):
    """Structured, validated PowerShell invocation for WinRM-over-HTTPS transport."""
    schema = PS_CMDLETS.get(cmdlet)
    if schema is None:
        raise CommandValidationError(f"cmdlet not allowlisted: {cmdlet!r}")
    clean = {}
    for name, value in params.items():
        rule = schema.get(name)
        if rule is None:
            raise CommandValidationError(f"{cmdlet}: parameter not allowed: {name}")
        if rule is bool:
            if not isinstance(value, bool):
                raise CommandValidationError(f"{cmdlet} -{name} must be a boolean")
            clean[name] = value
        elif isinstance(rule, set):
            if value not in rule:
                raise CommandValidationError(f"{cmdlet} -{name} must be one of {sorted(rule)}")
            clean[name] = value
        else:
            clean[name] = rule(value)
    return {"transport": "winrm-https", "cmdlet": cmdlet, "parameters": clean}


def graph_revoke_sessions(upn):
    """Microsoft Graph request with the UPN validated and URL-encoded."""
    return {"method": "POST",
            "url": f"https://graph.microsoft.com/v1.0/users/{quote(valid_upn(upn), safe='@.')}/revokeSignInSessions"}


def citool_refresh():
    return ["CiTool.exe", "--refresh"]


# --------------------------------------------------------------------- argv builders
def iptables_drop(ip):
    return ["iptables", "-I", "INPUT", "1", "-s", f"{valid_ip(ip)}/32", "-j", "DROP",
            "-m", "comment", "--comment", "CyberPulse-Auto-Block"]


def iptables_undrop(ip):
    return ["iptables", "-D", "INPUT", "-s", f"{valid_ip(ip)}/32", "-j", "DROP",
            "-m", "comment", "--comment", "CyberPulse-Auto-Block"]


def pfsense_rule_path(ip):
    return f"/api/v1/firewall/rule/{valid_ip(ip)}"


def aws_delete_deny_policy(user):
    return ["aws", "iam", "delete-user-policy", "--user-name", valid_account(user).split("\\")[-1],
            "--policy-name", "AWSRevokeOlderSessions"]


def schtasks(action, task_name):
    flags = {"export": ["/Query", "/TN", None, "/XML"], "disable": ["/Change", "/TN", None, "/DISABLE"],
             "enable": ["/Change", "/TN", None, "/ENABLE"]}[action]
    name = valid_task_name(task_name)
    return ["schtasks.exe"] + [name if f is None else f for f in flags]
