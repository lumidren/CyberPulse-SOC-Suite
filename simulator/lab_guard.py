"""
Lab Guardrails for the CyberPulse Attack Simulator

Every attack generator is wrapped with `lab_only`, so the simulator refuses to
produce adversary telemetry unless the operator has explicitly declared a lab
environment:

    CYBERPULSE_LAB_MODE=true

This is a deliberate speed bump: emulated attack telemetry should never be
injected into a pipeline that also handles real events by accident.
"""

import fnmatch
import functools
import ipaddress
import os
import threading
import time
from collections import deque


class LabModeRequired(RuntimeError):
    """Raised when the simulator is invoked without the explicit lab flag."""


class TargetNotAllowed(RuntimeError):
    """Raised when a simulated event would target something outside the lab."""


DEFAULT_LAB_CIDRS = "10.0.0.0/16"
# Accounts a simulated credential attack may name (dummy lab accounts only)
DEFAULT_LAB_ACCOUNTS = "lab.*"
CREDENTIAL_ATTACK_TECHNIQUES = ("T1110",)
DEFAULT_LAB_CLOUD_TARGETS = "aws-lab-account-*,cyberpulse-lab.onmicrosoft.com"
CLOUD_SOURCES = {"aws:cloudtrail", "azure:signinlogs"}


def lab_cidrs():
    """Configured lab ranges. Publicly routable ranges are rejected outright."""
    raw = os.environ.get("CYBERPULSE_LAB_CIDRS", DEFAULT_LAB_CIDRS)
    nets = [ipaddress.ip_network(c.strip(), strict=False) for c in raw.split(",") if c.strip()]
    public = [str(n) for n in nets if n.is_global]
    if public:
        raise TargetNotAllowed(f"CYBERPULSE_LAB_CIDRS may not contain public ranges: {', '.join(public)}")
    return nets


def lab_cloud_targets():
    raw = os.environ.get("CYBERPULSE_LAB_CLOUD_TARGETS", DEFAULT_LAB_CLOUD_TARGETS)
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def lab_accounts():
    raw = os.environ.get("CYBERPULSE_LAB_ACCOUNTS", DEFAULT_LAB_ACCOUNTS)
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def validate_credential_attack(event):
    """Simulated credential attacks may only name dummy lab accounts and carry no password material."""
    if not str(event.get("technique_id", "")).startswith(CREDENTIAL_ATTACK_TECHNIQUES):
        return event
    details = event.get("details", {})
    account = str(details.get("TargetUserName") or event.get("user") or "").split("\\")[-1].lower()
    if not any(fnmatch.fnmatch(account, p) for p in lab_accounts()):
        raise TargetNotAllowed(f"Credential-attack simulation may only target lab accounts, not {account!r}.")
    if details.get("CredentialMaterial", "none") != "none":
        raise TargetNotAllowed("Simulated credential attacks must not carry password material.")
    return event


class SimulationThrottle:
    """Per-minute caps on simulations triggered through the API / UI.

    Brute-force emulation has its own, tighter cap so a lab cannot be flooded
    with authentication-failure telemetry. In-process replay scripts
    (scripts/validate_detections.py, scripts/benchmark_pipeline.py) generate no
    traffic and are not throttled.
    """

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.limits = {
            "brute_force": int(os.environ.get("SIM_BRUTE_FORCE_PER_MIN", "6")),
            "any": int(os.environ.get("SIM_PER_MIN", "60")),
        }
        self._windows = {k: deque() for k in self.limits}
        self._lock = threading.Lock()

    def allow(self, techniques):
        """Record one simulation covering `techniques`; False if any cap is reached."""
        kinds = ["any"]
        if any(str(t).startswith(CREDENTIAL_ATTACK_TECHNIQUES) for t in techniques):
            kinds.append("brute_force")
        now = self.clock()
        with self._lock:
            for kind in kinds:
                window = self._windows[kind]
                while window and now - window[0] > 60:
                    window.popleft()
                if len(window) >= self.limits[kind]:
                    return False, kind
            for kind in kinds:
                self._windows[kind].append(now)
        return True, None


def resolve_target_ip(event):
    """Target IP of a simulated event: explicit target_ip, else the lab inventory address."""
    from soar.protected_assets import ASSET_INVENTORY
    return event.get("target_ip") or ASSET_INVENTORY.get(event.get("computer_name", ""))


def validate_target(event):
    """Refuse events whose target is outside the lab allowlist (lab CIDRs / lab cloud accounts)."""
    target = event.get("computer_name", "")
    if event.get("event_source") in CLOUD_SOURCES:
        if not any(fnmatch.fnmatch(target.lower(), p) for p in lab_cloud_targets()):
            raise TargetNotAllowed(f"Cloud target {target!r} is not an allowlisted lab account/tenant.")
        return event
    ip = resolve_target_ip(event)
    if not ip:
        raise TargetNotAllowed(f"Target {target!r} has no lab inventory address; refusing to simulate.")
    addr = ipaddress.ip_address(ip)
    # Never simulate against a publicly routable address, whatever the config says
    if addr.is_global:
        raise TargetNotAllowed(f"Target {target} ({ip}) is a public IP; the simulator never targets public addresses.")
    nets = lab_cidrs()
    if not any(addr in net for net in nets):
        raise TargetNotAllowed(f"Target {target} ({ip}) is outside the lab CIDRs {[str(n) for n in nets]}.")
    return event


LAB_FLAG = "CYBERPULSE_LAB_MODE"


def lab_mode_enabled():
    return os.environ.get(LAB_FLAG, "").strip().lower() == "true"


def require_lab_mode():
    if not lab_mode_enabled():
        raise LabModeRequired(
            f"The attack simulator only runs in a declared lab: set {LAB_FLAG}=true "
            "(and only on networks you own or are authorised to test)."
        )


def tag_simulated(event):
    """Mark an event as synthetic so no consumer can mistake it for real telemetry."""
    event["simulation"] = True
    event.setdefault("details", {})["simulation"] = True
    return event


def lab_only(generator):
    """Decorator: refuse to emit attack telemetry outside lab mode; tag what is emitted."""
    @functools.wraps(generator)
    def wrapper(*args, **kwargs):
        require_lab_mode()
        return tag_simulated(validate_credential_attack(validate_target(generator(*args, **kwargs))))
    return wrapper
