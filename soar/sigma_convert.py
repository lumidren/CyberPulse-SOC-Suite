"""
Sigma -> Splunk SPL / Elastic (Lucene) / Microsoft KQL / Wazuh XML converter.

Converts the documented Sigma subset supported by soar/sigma_engine.py. The
condition tree is expanded to disjunctive normal form (OR of AND-branches) so
targets without nested boolean logic (Wazuh) get one rule per branch.

Field names are mapped per target (Sysmon/Security field names for Splunk,
ECS for Elastic, Defender/Sentinel columns for KQL, win.eventdata.* for
Wazuh). The output is generated, not hand-tuned: review it, and validate it
in your SIEM before deploying. None of it has been run against a live SIEM in
this lab.
"""

import re
from xml.sax.saxutils import escape as xml_escape

from soar.sigma_engine import LOGSOURCE_EVENT_IDS, LOGSOURCE_SOURCES

TARGETS = ("splunk", "elastic", "kql", "wazuh")

# Wazuh decoder groups and field prefixes per log product
WAZUH_PRODUCTS = {"windows": ("windows", "win.eventdata."), "aws": ("amazon", "aws."), "azure": ("azure", "azure.")}

ECS_FIELDS = {
    "Image": "process.executable", "CommandLine": "process.command_line", "ParentImage": "process.parent.executable",
    "TargetFilename": "file.path", "EventID": "event.code", "IpAddress": "source.ip", "sourceIPAddress": "source.ip",
    "eventName": "event.action", "eventSource": "event.provider",
}
KQL_FIELDS = {
    "Image": "FolderPath", "CommandLine": "ProcessCommandLine", "ParentImage": "InitiatingProcessFolderPath",
    "TargetFilename": "FolderPath", "IpAddress": "IpAddress", "eventName": "OperationName",
}
KQL_TABLES = {
    ("windows", "process_creation"): "DeviceProcessEvents",
    ("windows", "file_event"): "DeviceFileEvents",
    ("windows", "registry_set"): "DeviceRegistryEvents",
    ("aws", "cloudtrail"): "AWSCloudTrail",
    ("azure", "signinlogs"): "SigninLogs",
    ("azure", "auditlogs"): "AuditLogs",
    # Custom log table you create when forwarding GUARDIAN alerts to Sentinel (name is your choice)
    ("guardian", "anomaly"): "GuardianAnomaly_CL",
    ("m365", "email"): "EmailEvents",
    # Custom tables you create when forwarding sensor logs to Sentinel (names are your choice)
    ("zeek", "conn"): "ZeekConn_CL", ("zeek", "dns"): "ZeekDns_CL", ("zeek", "ssl"): "ZeekSsl_CL",
    ("zeek", "http"): "ZeekHttp_CL", ("suricata", "alert"): "SuricataAlert_CL",
}


class ConversionError(ValueError):
    pass


# ----------------------------------------------------------------- DNF expansion
def _dnf(node, selections):
    """List of branches; each branch is a list of (selection_name, negated)."""
    kind = node[0]
    if kind == "sel":
        return [[(node[1], False)]]
    if kind == "any":
        return [[(n, False)] for n in node[1]]
    if kind == "all":
        return [[(n, False) for n in node[1]]]
    if kind == "or":
        return _dnf(node[1], selections) + _dnf(node[2], selections)
    if kind == "and":
        return [a + b for a in _dnf(node[1], selections) for b in _dnf(node[2], selections)]
    if kind == "not":
        inner = node[1]
        if inner[0] == "sel":
            return [[(inner[1], True)]]
        if inner[0] == "any":  # not (a or b) = not a and not b
            return [[(n, True) for n in inner[1]]]
        raise ConversionError("only 'not <selection>' and 'not 1 of <pattern>' are supported")
    raise ConversionError(f"unsupported node {kind}")


def _expand_selection(selection):
    """A selection (map or list of maps) as a list of field-maps (OR)."""
    if isinstance(selection, dict):
        return [selection]
    if isinstance(selection, list) and all(isinstance(s, dict) for s in selection):
        return selection
    raise ConversionError("keyword selections are not convertible")


# ----------------------------------------------------------------- value rendering
def _regex_for(value, modifiers):
    if "re" in modifiers:
        return str(value)
    body = re.escape(str(value)).replace(r"\*", ".*").replace(r"\?", ".")
    if "contains" in modifiers:
        return body
    if "startswith" in modifiers:
        return "^" + body
    if "endswith" in modifiers:
        return body + "$"
    return "^" + body + "$"


def _numeric_op(modifiers):
    for op, sym in (("gte", ">="), ("gt", ">"), ("lte", "<="), ("lt", "<")):
        if op in modifiers:
            return sym
    return None


def _field_expr(target, field, modifiers, value):
    num = _numeric_op(modifiers)
    if target == "splunk":
        name = "EventCode" if field == "EventID" else field
        if value is None:
            return f"isnull('{name}')"
        if num:
            return f"'{name}'{num}{value}"
        if "cidr" in modifiers:
            return f'cidrmatch("{value}", \'{name}\')'
        pattern = _regex_for(value, modifiers).replace("\\", "\\\\").replace('"', '\\"')
        return f"match('{name}', \"(?i){pattern}\")"
    if target == "kql":
        name = KQL_FIELDS.get(field, field)
        sval = str(value).replace("\\", "\\\\").replace('"', '\\"')
        if value is None:
            return f"isempty({name})"
        if num:
            return f"{name} {num} {value}"
        if "cidr" in modifiers:
            return f'ipv4_is_in_range({name}, "{value}")'
        if "re" in modifiers:
            return f'{name} matches regex "{sval}"'
        for mod, op in (("contains", "contains"), ("startswith", "startswith"), ("endswith", "endswith")):
            if mod in modifiers:
                return f'{name} {op} "{sval}"'
        return f'{name} =~ "{sval}"'
    if target == "elastic":
        name = ECS_FIELDS.get(field, f"winlog.event_data.{field}")
        if value is None:
            return f"NOT _exists_:{name}"
        if num:
            return f"{name}:{num}{value}"
        if "re" in modifiers:
            return f"{name}:/{value}/"
        sval = re.sub(r'([+\-=&|><!(){}\[\]^"~:\\/ ])', r"\\\1", str(value))
        if "contains" in modifiers:
            return f"{name}:*{sval}*"
        if "startswith" in modifiers:
            return f"{name}:{sval}*"
        if "endswith" in modifiers:
            return f"{name}:*{sval}"
        return f"{name}:{sval}"
    raise ConversionError(target)


def _map_expr(target, fieldmap):
    parts = []
    for spec, expected in fieldmap.items():
        field, *mods = spec.split("|")
        values = expected if isinstance(expected, list) else [expected]
        exprs = [_field_expr(target, field, mods, v) for v in values]
        joiner = " AND " if "all" in mods else " OR "
        if target == "kql":
            joiner = joiner.lower()
        parts.append(exprs[0] if len(exprs) == 1 else "(" + joiner.join(exprs) + ")")
    return "(" + (" and " if target == "kql" else " AND ").join(parts) + ")"


def _selection_expr(target, selection):
    maps = [_map_expr(target, m) for m in _expand_selection(selection)]
    return maps[0] if len(maps) == 1 else "(" + (" or " if target == "kql" else " OR ").join(maps) + ")"


def _query(target, rule):
    or_ = " or " if target == "kql" else " OR "
    and_ = " and " if target == "kql" else " AND "
    not_ = "not " if target == "kql" else "NOT "
    branches = [b for c in rule.conditions for b in _dnf(c, rule.selections)]
    branch_exprs = []
    for branch in branches:
        terms = [(not_ if neg else "") + _selection_expr(target, rule.selections[name]) for name, neg in branch]
        branch_exprs.append("(" + and_.join(terms) + ")")
    return or_.join(branch_exprs)


def _logsource_prefix(target, rule):
    ls = rule.logsource
    key_cat = (ls.get("product"), ls.get("category"))
    key_svc = (ls.get("product"), ls.get("service"))
    ids = sorted(LOGSOURCE_EVENT_IDS.get(key_cat, set()))
    sources = sorted(LOGSOURCE_SOURCES.get(key_svc, set()))
    if target == "splunk":
        parts = ["index=*"]
        if ids:
            parts.append("(" + " OR ".join(f"EventCode={i}" for i in ids) + ")")
        if sources:
            parts.append("(" + " OR ".join(f'source="*{s}*"' for s in sources) + ")")
        return " ".join(parts) + " | where "
    if target == "elastic":
        parts = []
        if ids:
            parts.append("(" + " OR ".join(f"event.code:{i}" for i in ids) + ")")
        return (" AND ".join(parts) + " AND ") if parts else ""
    if target == "kql":
        table = KQL_TABLES.get(key_cat) or KQL_TABLES.get(key_svc) or "SecurityEvent"
        return f"{table}\n| where "
    return ""


def convert(rule, target):
    if target not in TARGETS:
        raise ConversionError(f"unknown target {target}")
    if target == "wazuh":
        return to_wazuh(rule)
    header = {"splunk": "``` {} ```", "elastic": "// {}", "kql": "// {}"}[target].format(
        f"{rule.soar.get('soc_rule_id', rule.id)}: {rule.title} (generated from {rule.file}; review before use)")
    return header + "\n" + _logsource_prefix(target, rule) + _query(target, rule) + "\n"


def to_wazuh(rule, base_id=None):
    """One Wazuh <rule> per DNF branch; values become pcre2 alternations on win.eventdata.* fields."""
    soc = rule.soar.get("soc_rule_id", "SOC-RULE-000")
    number = int(re.sub(r"\D", "", soc) or 0)
    base_id = base_id or 110000 + number * 10
    level = {"low": 5, "medium": 8, "high": 12, "critical": 14}.get(rule.level, 8)
    group, prefix = WAZUH_PRODUCTS.get(rule.logsource.get("product"), ("windows", "win.eventdata."))
    out = [f"<!-- {soc}: {xml_escape(rule.title)} (generated from {rule.file}; review before use) -->"]
    branches = [b for c in rule.conditions for b in _dnf(c, rule.selections)]
    rule_no = 0
    for branch in branches:
        positives = [rule.selections[n] for n, neg in branch if not neg]
        negatives = [rule.selections[n] for n, neg in branch if neg]
        for pos_map in _cartesian(positives):
            fields = []
            for fmap, negate in [(m, False) for m in pos_map] + [(m, True) for sel in negatives for m in _expand_selection(sel)]:
                if negate and len(fmap) > 1:
                    continue  # Wazuh cannot negate a multi-field conjunction; documented gap
                for spec, expected in fmap.items():
                    field, *mods = spec.split("|")
                    if _numeric_op(mods) or "cidr" in mods or expected is None:
                        continue
                    values = expected if isinstance(expected, list) else [expected]
                    pattern = "(?:" + "|".join(_regex_for(v, mods) for v in values) + ")"
                    if "all" in mods:
                        pattern = "".join(f"(?=.*{_regex_for(v, ['contains'])})" for v in values)
                    if field == "EventID":
                        name = "win.system.eventID"
                    elif prefix == "win.eventdata.":
                        name = prefix + field[0].lower() + field[1:]
                    else:
                        name = prefix + field
                    neg_attr = ' negate="yes"' if negate else ""
                    fields.append(f'    <field name="{name}" type="pcre2"{neg_attr}>(?i){xml_escape(pattern)}</field>')
            out.append(f'<rule id="{base_id + rule_no}" level="{level}">')
            out.append(f"    <if_group>{group}</if_group>")
            out.extend(fields)
            out.append(f"    <description>{xml_escape(soc)}: {xml_escape(rule.title)}</description>")
            out.append("    <group>cyberpulse,sigma_generated,</group>")
            out.append("</rule>")
            rule_no += 1
    return "\n".join(out) + "\n"


def _cartesian(selections):
    """Combine OR-alternatives of several selections into AND-lists of field maps."""
    combos = [[]]
    for sel in selections:
        combos = [c + [m] for c in combos for m in _expand_selection(sel)]
    return combos
