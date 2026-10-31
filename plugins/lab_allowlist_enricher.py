"""
Example enricher plugin: flags source IPs that belong to known lab infrastructure.

Enable with CYBERPULSE_PLUGINS=lab_allowlist_enricher. Purely local (no network).
"""

import ipaddress

from soar.plugins import register_enricher

# Lab infrastructure ranges (SOC subnet); traffic from here is expected
KNOWN_LAB_RANGES = [ipaddress.ip_network("10.0.1.0/24")]


@register_enricher("lab_allowlist")
def lab_allowlist(event):
    try:
        ip = ipaddress.ip_address(event.get("source_ip", ""))
    except ValueError:
        return {"known_lab_infrastructure": False}
    return {"known_lab_infrastructure": any(ip in net for net in KNOWN_LAB_RANGES)}
