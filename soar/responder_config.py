"""
Responder Transport & Identity Configuration Checks (CyberPulse SOC Lab)

The lab's responders are simulated, but their configuration is validated as if
they were real so the documented deployment is safe by construction:

* WinRM must use HTTPS (port 5986) with certificate validation. There is no
  "skip verify" switch: a responder that can be man-in-the-middled can be
  tricked into isolating or unlocking the wrong host.
* The responder identity must be a dedicated, least-privilege service account,
  never a built-in or domain-wide admin (see docs/SERVICE_ACCOUNT.md).
"""

import re

PRIVILEGED_IDENTITY_RE = re.compile(r"(?i)(^|\\)(administrator|admin|root|krbtgt|domain admins?|enterprise admins?)$")

import os
from urllib.parse import urlparse


def winrm_settings(env=None):
    env = os.environ if env is None else env
    return {
        "endpoint": env.get("WINRM_ENDPOINT", ""),
        "verify_tls": env.get("WINRM_VERIFY_TLS", "true").strip().lower(),
        "ca_bundle": env.get("WINRM_CA_BUNDLE", ""),
        "user": env.get("WINRM_USER", ""),
    }


def validate_winrm(env=None):
    """Return {'configured', 'ok', 'errors', 'warnings'} for the WinRM responder settings."""
    s = winrm_settings(env)
    errors, warnings = [], []
    identity = validate_identity(s["user"])
    if not s["endpoint"]:
        return {"configured": False, "ok": True, "errors": [], "warnings": ["WINRM_ENDPOINT not set; responder stays simulated."]}

    parsed = urlparse(s["endpoint"])
    if parsed.scheme != "https":
        errors.append("WINRM_ENDPOINT must use https:// (WinRM over HTTPS, port 5986); plain HTTP is refused.")
    if parsed.port not in (None, 5986):
        warnings.append(f"WinRM HTTPS normally listens on 5986, not {parsed.port}.")
    if s["verify_tls"] != "true":
        errors.append("WINRM_VERIFY_TLS must be true: certificate validation cannot be disabled.")
    if s["ca_bundle"] and not os.path.isfile(s["ca_bundle"]):
        errors.append(f"WINRM_CA_BUNDLE does not exist: {s['ca_bundle']}")
    if not s["ca_bundle"]:
        warnings.append("WINRM_CA_BUNDLE not set; the system trust store will be used to validate the WinRM certificate.")
    errors += identity["errors"]
    warnings += identity["warnings"]
    return {"configured": True, "ok": not errors, "errors": errors, "warnings": warnings}


def validate_identity(user):
    """Least-privilege check for a responder account name."""
    if not user:
        return {"ok": True, "errors": [], "warnings": ["No responder identity configured (simulated)."]}
    errors, warnings = [], []
    if PRIVILEGED_IDENTITY_RE.search(user.strip()):
        errors.append(f"{user} is a built-in/privileged identity; use a dedicated least-privilege service account.")
    if not user.split("\\")[-1].lower().startswith(("svc_", "gmsa_")) and not user.endswith("$"):
        warnings.append(f"{user} does not look like a dedicated service account (svc_* / gMSA).")
    return {"ok": not errors, "errors": errors, "warnings": warnings}
