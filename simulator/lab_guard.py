"""
Lab Guardrails for the CyberPulse Attack Simulator

Every attack generator is wrapped with `lab_only`, so the simulator refuses to
produce adversary telemetry unless the operator has explicitly declared a lab
environment:

    CYBERPULSE_LAB_MODE=true

This is a deliberate speed bump: emulated attack telemetry should never be
injected into a pipeline that also handles real events by accident.
"""

import functools
import os


class LabModeRequired(RuntimeError):
    """Raised when the simulator is invoked without the explicit lab flag."""


LAB_FLAG = "CYBERPULSE_LAB_MODE"


def lab_mode_enabled():
    return os.environ.get(LAB_FLAG, "").strip().lower() == "true"


def require_lab_mode():
    if not lab_mode_enabled():
        raise LabModeRequired(
            f"The attack simulator only runs in a declared lab: set {LAB_FLAG}=true "
            "(and only on networks you own or are authorised to test)."
        )


def lab_only(generator):
    """Decorator: refuse to emit attack telemetry outside lab mode."""
    @functools.wraps(generator)
    def wrapper(*args, **kwargs):
        require_lab_mode()
        return generator(*args, **kwargs)
    return wrapper
