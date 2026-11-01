"""
PDF export of an incident report (roadmap F65), with no third-party dependency.

Writes a plain PDF 1.4 document (built-in Helvetica fonts, A4 pages, wrapped text). It
holds text only: no scripts, forms, links or embedded files. Account names are masked
like every other export (PRIVACY_MASK_USERNAMES) and third-party intel payloads are
left out (provider terms). Characters outside Latin-1 are replaced with '?', because
the built-in PDF fonts cannot show them.
"""

import textwrap
from datetime import datetime, timezone

from soar.enrichment import strip_provider_data
from soar.privacy import mask_identities, masking_enabled

PAGE_W, PAGE_H, MARGIN = 595, 842, 50  # A4 in points
LINE_H = {"title": 22, "h": 17, "body": 13}
SIZE = {"title": 16, "h": 12, "body": 9.5}
WRAP = {"title": 60, "h": 80, "body": 105}


def _escape(text):
    safe = str(text).encode("latin-1", errors="replace").decode("latin-1")
    return safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").replace("\r", " ")


def build_pdf(blocks, title="Report"):
    """blocks: [(style, text)] with style in title/h/body. Returns PDF bytes."""
    pages, current, y = [], [], PAGE_H - MARGIN
    for style, text in blocks:
        lines = textwrap.wrap(str(text), WRAP[style]) or [""]
        if style != "body":
            y -= 6
        for line in lines:
            if y - LINE_H[style] < MARGIN:
                pages.append(current)
                current, y = [], PAGE_H - MARGIN
            y -= LINE_H[style]
            font = "F2" if style in ("title", "h") else "F1"
            current.append(f"BT /{font} {SIZE[style]} Tf {MARGIN} {y} Td ({_escape(line)}) Tj ET")
    pages.append(current)

    objects = []  # 1-based object bodies

    def add(body):
        objects.append(body)
        return len(objects)

    catalog = add(None)
    pages_obj = add(None)
    font_regular = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    font_bold = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    page_ids = []
    for n, ops in enumerate(pages, 1):
        footer = f"BT /F1 8 Tf {MARGIN} 25 Td ({_escape(title)} - page {n} of {len(pages)}) Tj ET"
        stream = "\n".join(ops + [footer]).encode("latin-1")
        content = add(f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream")
        page_ids.append(add(f"<< /Type /Page /Parent {pages_obj} 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                            f"/Resources << /Font << /F1 {font_regular} 0 R /F2 {font_bold} 0 R >> >> "
                            f"/Contents {content} 0 R >>"))
    objects[catalog - 1] = f"<< /Type /Catalog /Pages {pages_obj} 0 R >>"
    objects[pages_obj - 1] = f"<< /Type /Pages /Kids [{' '.join(f'{p} 0 R' for p in page_ids)}] /Count {len(page_ids)} >>"
    info = add(f"<< /Title ({_escape(title)}) /Producer (CyberPulse SOC Suite) "
               f"/CreationDate (D:{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}Z) >>")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        data = body if isinstance(body, bytes) else body.encode("latin-1")
        out += f"{number} 0 obj\n".encode("ascii") + data + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii")
    out += "".join(f"{off:010d} 00000 n \n" for off in offsets).encode("ascii")
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root {catalog} 0 R /Info {info} 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode("ascii")
    return bytes(out)


def incident_blocks(incident, case=None, custody=None):
    inc = strip_provider_data(incident)
    if masking_enabled():
        inc = mask_identities(inc)
    rule = inc.get("rule") or {}
    tel = inc.get("telemetry") or {}
    risk = inc.get("risk_assessment") or {}
    decision = inc.get("policy_decision") or {}
    action = inc.get("containment_action") or {}
    blocks = [("title", f"Incident report {inc.get('incident_id')}"),
              ("body", f"Generated {datetime.now(timezone.utc).isoformat()[:19]} UTC by CyberPulse SOC Suite."),
              ("body", "SIMULATED: synthetic lab telemetry, not a real attack." if inc.get("simulated")
               else "Source: ingested telemetry."),
              ("h", "Summary"),
              ("body", f"Rule: {rule.get('rule_id')} {rule.get('rule_name')} (severity {rule.get('severity')})"),
              ("body", f"ATT&CK: {rule.get('mitre_id')}  Tactic: {tel.get('tactic', 'Unknown')}"),
              ("body", f"Host: {tel.get('computer_name')}  User: {tel.get('user')}  Source IP: {tel.get('source_ip')}"),
              ("body", f"Event time: {tel.get('timestamp')}  Recorded: {inc.get('created_at')}"),
              ("body", f"Case: {(case or {}).get('case_id', inc.get('case_id'))}  Status: {inc.get('status')}"),
              ("h", "Risk and decision"),
              ("body", f"Risk score {risk.get('final_score')} ({risk.get('risk_level')}). {decision.get('rationale', '')}"),
              ("body", f"Response: {action.get('action_type')} - {action.get('status')}. {action.get('execution_log', '')}"),
              ("h", "Timeline")]
    blocks += [("body", f"{t.get('timestamp', '')[:19]}  {t.get('stage', '')}: {t.get('title', '')}")
               for t in inc.get("timeline") or []]
    blocks.append(("h", "Observables"))
    blocks += [("body", f"{o.get('type')}: {o.get('value')}") for o in inc.get("observables") or []] or [("body", "None.")]
    tasks = (inc.get("playbook") or {}).get("tasks") or []
    if tasks:
        blocks.append(("h", f"Playbook tasks ({(inc.get('playbook') or {}).get('name')})"))
        blocks += [("body", f"[{'x' if t.get('status') == 'Done' else ' '}] {t['title']}") for t in tasks]
    notes = inc.get("analyst_notes") or []
    if notes:
        blocks.append(("h", "Analyst notes"))
        blocks += [("body", f"{n.get('timestamp', '')[:19]} {n.get('author')}: {n.get('note')}") for n in notes]
    if custody:
        blocks.append(("h", "Chain of custody"))
        blocks += [("body", f"#{e['seq']} {e['at'][:19]} {e['action']} {e['artifact']} by {e['actor']} sha256 {e['sha256'][:16]}...")
                   for e in custody]
    blocks.append(("body", "Third-party threat-intel payloads are omitted from exports (provider terms)."))
    return blocks


def incident_pdf(incident, case=None, custody=None):
    return build_pdf(incident_blocks(incident, case, custody), title=f"CyberPulse incident {incident.get('incident_id')}")
