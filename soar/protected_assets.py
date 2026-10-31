"""
Protected Assets for the CyberPulse SOC Lab

Assets on this list can never be isolated or blocked through the SOAR engine,
whatever the policy mode and even with analyst approval. Containing one of
them (a Domain Controller, the SOC's own hosts, admin jump boxes) must go
through a manual, out-of-band change process, because doing it wrong takes
down authentication or the SOC's own visibility.

Entries may be hostnames (case-insensitive), shell-style patterns (JUMP-*),
IP addresses or CIDR ranges. Extend the list with PROTECTED_ASSETS
(comma-separated) in the environment.
"""

import fnmatch
import ipaddress
import os

# Lab inventory: hostname -> management IP (synthetic lab addressing)
ASSET_INVENTORY = {
    "WIN-DC01.corp.local": "10.0.0.10",
    "WIN-DC01": "10.0.0.10",
    "CORP-RDP-GW01": "10.0.0.20",
    "WIN-WORKSTATION09": "10.0.0.45",
    "CORP-FINANCE-02": "10.0.0.60",
    "wazuh.manager": "10.0.1.10",
    "cyberpulse-soar": "10.0.1.15",
    "thehive-cases": "10.0.1.20",
}

DEFAULT_PROTECTED_ASSETS = [
    "10.0.0.10",        # Domain Controller (roadmap E24: never auto-isolate)
    "WIN-DC01*",        # Domain Controller by name
    "DC0*",             # any other DCs
    "10.0.1.0/24",      # SOC management subnet (Wazuh, SOAR, TheHive)
    "wazuh.*",
    "cyberpulse-soar",
    "JUMP-*",           # admin jump boxes
    "PAW-*",            # privileged access workstations
]


def _load_entries():
    extra = [e.strip() for e in os.environ.get("PROTECTED_ASSETS", "").split(",") if e.strip()]
    return DEFAULT_PROTECTED_ASSETS + extra


def _ip_matches(ip, entry):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    try:
        return addr in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False


def protected_match(host=None, ip=None, entries=None):
    """Return the protecting entry for a host/IP, or None if it is not protected.

    The host's inventory IP is checked too, so protecting 10.0.0.10 also
    protects WIN-DC01 even when an event only names the host.
    """
    entries = entries if entries is not None else _load_entries()
    ips = {i for i in (ip, ASSET_INVENTORY.get(host or "")) if i}
    for entry in entries:
        if host and fnmatch.fnmatch(host.lower(), entry.lower()):
            return entry
        for candidate in ips:
            if _ip_matches(candidate, entry):
                return entry
    return None
