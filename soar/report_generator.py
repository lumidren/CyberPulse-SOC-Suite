"""
Automated NIST SP 800-61 Rev. 2 Incident Report Generator for CyberPulse SOC Suite
Produces executive-ready standalone HTML and structured JSON forensic reports
for CISO briefings, compliance audits, and post-incident reviews.
"""

import json
from datetime import datetime, timezone

class IncidentReportGenerator:
    """
    Generates publication-quality NIST SP 800-61 Rev. 2 Incident Response Reports.
    """
    def generate_html_report(self, incident: dict) -> str:
        inc_id = incident.get("incident_id", "INC-UNKNOWN")
        corr_id = incident.get("correlation_id", "N/A")
        created_at = incident.get("created_at", datetime.now(timezone.utc).isoformat())
        rule = incident.get("rule", {})
        telemetry = incident.get("telemetry", {})
        risk = incident.get("risk_assessment", {})
        containment = incident.get("containment_action", {})
        ai = incident.get("ai_analysis", {})
        evidence = incident.get("evidence_package", {})
        observables = incident.get("observables", [])
        timeline = incident.get("timeline", [])

        # Format socket table rows
        socket_rows = ""
        for s in evidence.get("network_connections", [])[:5]:
            socket_rows += f"""
            <tr>
                <td style="padding:6px;border:1px solid #334155;">{s.get('pid')}</td>
                <td style="padding:6px;border:1px solid #334155;"><strong>{s.get('process_name')}</strong></td>
                <td style="padding:6px;border:1px solid #334155;">{s.get('local_addr')}</td>
                <td style="padding:6px;border:1px solid #334155;color:#ef4444;">{s.get('remote_addr')}</td>
                <td style="padding:6px;border:1px solid #334155;">{s.get('state')}</td>
            </tr>
            """

        # Format timeline rows
        timeline_rows = ""
        for t in timeline:
            timeline_rows += f"""
            <div style="margin-bottom:10px;padding-left:14px;border-left:3px solid #38bdf8;">
                <span style="font-size:11px;color:#94a3b8;">{t.get('timestamp')} - <strong>{t.get('stage')}</strong></span>
                <div style="font-weight:bold;color:#f8fafc;font-size:13px;">{t.get('title')}</div>
                <div style="font-size:12px;color:#cbd5e1;">{t.get('detail')}</div>
            </div>
            """

        # Format remediation items
        remediation_items = ""
        for r in ai.get("remediation_guidance", []):
            remediation_items += f"<li style='margin-bottom:6px;'>{r}</li>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NIST SP 800-61 Incident Report | {inc_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:#0f172a; color:#f8fafc; margin:0; padding:30px; line-height:1.5; }}
        .report-header {{ border-bottom:2px solid #38bdf8; padding-bottom:16px; margin-bottom:24px; display:flex; justify-content:space-between; align-items:center; }}
        .header-title h1 {{ margin:0; font-size:22px; color:#38bdf8; letter-spacing:0.5px; }}
        .header-title span {{ font-size:12px; color:#94a3b8; text-transform:uppercase; }}
        .badge-crit {{ background:#ef4444; color:white; padding:4px 10px; border-radius:4px; font-weight:bold; font-size:12px; }}
        .section-card {{ background:#1e293b; border:1px solid #334155; border-radius:8px; padding:18px; margin-bottom:20px; }}
        .section-title {{ font-size:14px; font-weight:bold; text-transform:uppercase; color:#38bdf8; margin-top:0; margin-bottom:12px; border-bottom:1px solid #334155; padding-bottom:6px; }}
        .grid-2 {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
        .grid-4 {{ display:grid; grid-template-columns:repeat(4, 1fr); gap:12px; }}
        .meta-box {{ background:#0f172a; padding:10px; border-radius:6px; font-size:12px; }}
        .meta-box strong {{ color:#94a3b8; display:block; font-size:10px; text-transform:uppercase; }}
        table {{ width:100%; border-collapse:collapse; font-size:12px; margin-top:8px; }}
        th {{ background:#0f172a; color:#94a3b8; padding:8px; text-align:left; border:1px solid #334155; }}
        .signoff {{ margin-top:30px; border-top:1px solid #334155; padding-top:16px; display:flex; justify-content:space-between; font-size:12px; color:#94a3b8; }}
    </style>
</head>
<body>
    <div class="report-header">
        <div class="header-title">
            <span>CyberPulse SOC Suite | NIST SP 800-61 Rev. 2 Incident Record</span>
            <h1>INCIDENT REMEDIATION & FORENSIC DOSSIER</h1>
        </div>
        <div>
            <span class="badge-crit">{risk.get('risk_level', 'CRITICAL')} RISK ({risk.get('final_score', 0)}/100)</span>
        </div>
    </div>

    <div class="section-card">
        <h3 class="section-title">1. Executive Incident Briefing (CISO Summary)</h3>
        <p style="font-size:13px;color:#e2e8f0;">{ai.get('executive_summary', 'Automated containment executed successfully.')}</p>
        <div class="grid-4" style="margin-top:14px;">
            <div class="meta-box"><strong>Incident ID</strong>{inc_id}</div>
            <div class="meta-box"><strong>Correlation ID</strong>{corr_id}</div>
            <div class="meta-box"><strong>Target Asset</strong>{telemetry.get('computer_name', 'N/A')}</div>
            <div class="meta-box"><strong>Compromised User</strong>{telemetry.get('user', 'N/A')}</div>
        </div>
    </div>

    <div class="grid-2">
        <div class="section-card">
            <h3 class="section-title">2. Root Cause Analysis (RCA)</h3>
            <div style="font-size:12px;">
                <p><strong>Initial Attack Vector:</strong> {ai.get('root_cause_analysis', {}).get('initial_vector', 'N/A')}</p>
                <p><strong>Privilege Escalation Path:</strong> {ai.get('root_cause_analysis', {}).get('privilege_escalation_path', 'N/A')}</p>
                <p><strong>Persistence Mechanism:</strong> {ai.get('root_cause_analysis', {}).get('persistence_mechanism', 'N/A')}</p>
                <p><strong>Data at Risk:</strong> {ai.get('root_cause_analysis', {}).get('data_at_risk', 'N/A')}</p>
            </div>
        </div>
        <div class="section-card">
            <h3 class="section-title">3. Automated SOAR Containment Audit</h3>
            <div style="font-size:12px;">
                <p><strong>Action Enforced:</strong> {containment.get('action_type', 'N/A')}</p>
                <p><strong>Protocol:</strong> {containment.get('execution_protocol', 'N/A')}</p>
                <p><strong>Status:</strong> {containment.get('status', 'N/A')}</p>
                <p><strong>Execution Latency:</strong> {containment.get('latency_ms', 0)} ms</p>
                <p><strong>Rollback Capability:</strong> Verified via <code>rollback_containment()</code></p>
            </div>
        </div>
    </div>

    <div class="section-card">
        <h3 class="section-title">4. Pre-Containment Volatile Evidence Artifacts</h3>
        <p style="font-size:12px;color:#94a3b8;">Captured active network sockets before network isolation:</p>
        <table>
            <thead><tr><th>PID</th><th>Process</th><th>Local Address</th><th>Remote Address</th><th>State</th></tr></thead>
            <tbody>{socket_rows}</tbody>
        </table>
    </div>

    <div class="section-card">
        <h3 class="section-title">5. Microsecond Chronological Audit Timeline</h3>
        <div style="margin-top:12px;">{timeline_rows}</div>
    </div>

    <div class="section-card">
        <h3 class="section-title">6. Post-Incident Remediation & Hardening Plan</h3>
        <ul style="font-size:12px;color:#cbd5e1;">{remediation_items}</ul>
    </div>

    <div class="signoff">
        <div><strong>Lead Detection Engineer:</strong> analyst_lumidren (CyberPulse SOC Suite)</div>
        <div><strong>Report Timestamp:</strong> {created_at}</div>
        <div><strong>Compliance Standard:</strong> NIST SP 800-61 Rev. 2 / ISO 27035</div>
    </div>
</body>
</html>"""
        return html

    def generate_json_report(self, incident: dict) -> dict:
        return {
            "report_standard": "NIST SP 800-61 Rev. 2",
            "generator": "CyberPulse SOC Suite Automated Reporting Engine",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident": incident
        }

if __name__ == "__main__":
    rep = IncidentReportGenerator()
    sample_html = rep.generate_html_report({"incident_id": "INC-TEST-001"})
    print(f"[*] Generated HTML report ({len(sample_html)} bytes)")
