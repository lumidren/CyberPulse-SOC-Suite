"""
Configuration File + Schema Validation (CyberPulse SOC Lab)

Settings come from environment variables (highest priority) and, optionally,
a YAML file named by CYBERPULSE_CONFIG (see config/cyberpulse.example.yml).
Every known setting is validated against SCHEMA at startup; an invalid value
stops the server with a list of every problem instead of failing later.

Secrets (API keys, passwords, HMAC secrets) are refused in the config file:
keep them in the environment / .env (git-ignored) or a secrets manager.

    python -m soar.config --check [path/to/config.yml]
"""

import ipaddress
import os
import sys
from urllib.parse import urlparse

import yaml


def _bool(v):
    if str(v).strip().lower() not in ("true", "false"):
        raise ValueError("must be true or false")


def _int(lo=None, hi=None):
    def check(v):
        n = int(str(v))
        if (lo is not None and n < lo) or (hi is not None and n > hi):
            raise ValueError(f"must be between {lo} and {hi}")
    return check


def _float(lo, hi):
    def check(v):
        f = float(str(v))
        if not lo <= f <= hi:
            raise ValueError(f"must be between {lo} and {hi}")
    return check


def _enum(*allowed):
    def check(v):
        if str(v).strip().upper() not in {a.upper() for a in allowed}:
            raise ValueError(f"must be one of {', '.join(allowed)}")
    return check


def _cidr_list(v):
    for part in [p.strip() for p in str(v).split(",") if p.strip()]:
        ipaddress.ip_network(part, strict=False)


def _https_url_or_empty(v):
    if str(v).strip() and urlparse(str(v)).scheme != "https":
        raise ValueError("must be an https:// URL")


def _any(v):
    str(v)


# name -> (validator, description, secret)
SCHEMA = {
    "CYBERPULSE_ENV": (_enum("development", "production"), "Deployment environment", False),
    "HOST": (_any, "Bind address (127.0.0.1 by default)", False),
    "PORT": (_int(1, 65535), "HTTP port", False),
    "POLICY_MODE": (_enum("APPROVAL_REQUIRED", "DRY_RUN", "AUTOMATIC"), "Containment policy mode", False),
    "CYBERPULSE_ALLOW_FULL_AUTO": (_bool, "Permit AUTOMATIC mode", False),
    "CYBERPULSE_KILL_SWITCH": (_bool, "Start with automation halted", False),
    "CONFIDENCE_THRESHOLD": (_float(0.0, 1.0), "Escalate below this rule confidence", False),
    "CONTAINMENT_MAX_ACTIONS_PER_HOUR": (_int(0), "Hourly containment budget", False),
    "ISOLATION_BREAKER_MAX_HOSTS": (_int(1), "Hosts isolated in window that trip the breaker", False),
    "ISOLATION_BREAKER_WINDOW_MIN": (_int(1), "Circuit-breaker window (minutes)", False),
    "ISOLATION_TTL_MIN": (_int(1), "Isolation TTL (minutes)", False),
    "IP_BLOCK_TTL_MIN": (_int(1), "Perimeter block TTL (minutes)", False),
    "PROTECTED_ASSETS": (_any, "Extra protected assets", False),
    "PROTECTED_ACCOUNTS": (_any, "Extra protected accounts", False),
    "CYBERPULSE_LAB_MODE": (_bool, "Declare a lab (simulator gate)", False),
    "CYBERPULSE_LAB_CIDRS": (_cidr_list, "Lab target CIDRs", False),
    "CYBERPULSE_LAB_CLOUD_TARGETS": (_any, "Lab cloud accounts/tenants", False),
    "CYBERPULSE_LAB_ACCOUNTS": (_any, "Dummy lab accounts for credential simulations", False),
    "SIM_BRUTE_FORCE_PER_MIN": (_int(0), "Brute-force simulation cap", False),
    "SIM_PER_MIN": (_int(0), "Simulation cap", False),
    "SESSION_TTL_MIN": (_int(1, 7 * 24 * 60), "Dashboard session lifetime", False),
    "COOKIE_SECURE": (_bool, "Mark the session cookie Secure", False),
    "CORS_ALLOWED_ORIGIN": (_any, "Allowed browser origin", False),
    "RETENTION_DAYS": (_int(1, 3650), "Data retention (days)", False),
    "SYSLOG_MAX_EVENTS": (_int(1), "Syslog buffer cap", False),
    "SYSLOG_HOST": (_any, "Syslog bind address", False),
    "LOG_FILE": (_any, "Optional rotating log file", False),
    "LOG_FORMAT": (_enum("text", "json"), "Log format", False),
    "CYBERPULSE_LOG_LEVEL": (_enum("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"), "Log level", False),
    "MAX_BODY_BYTES": (_int(1024), "Request body cap (bytes)", False),
    "RATE_LIMIT_PER_MINUTE": (_int(1), "API requests per client per minute", False),
    "AUTH_FAILURE_LIMIT_PER_MINUTE": (_int(1), "Failed auths per client per minute", False),
    "PRIVACY_MASK_USERNAMES": (_bool, "Mask account names in output", False),
    "INGEST_EXTRA_FIELDS": (_any, "Extra ingest detail fields", False),
    "ALLOW_INTERNAL_WEBHOOKS": (_bool, "Permit private-IP webhook targets", False),
    "EXTERNAL_ENRICHMENT_ENABLED": (_bool, "Enable VirusTotal/AbuseIPDB lookups", False),
    "VIRUSTOTAL_API_TIER": (_enum("public", "premium"), "VirusTotal licence tier", False),
    "CYBERPULSE_COMMERCIAL_USE": (_bool, "Declare commercial use (VT public tier refused)", False),
    "VT_RATE_LIMIT_PER_MIN": (_int(1), "VirusTotal requests per minute", False),
    "VT_DAILY_QUOTA": (_int(1), "VirusTotal daily quota", False),
    "ABUSEIPDB_DAILY_QUOTA": (_int(1), "AbuseIPDB daily quota", False),
    "ABUSEIPDB_RATE_LIMIT_PER_MIN": (_int(1), "AbuseIPDB requests per minute", False),
    "ENRICHMENT_CACHE_SIZE": (_int(1), "IoC cache entries", False),
    "ENRICHMENT_CACHE_TTL_SEC": (_int(1), "IoC cache TTL (seconds)", False),
    "WINRM_ENDPOINT": (_https_url_or_empty, "WinRM HTTPS endpoint", False),
    "WINRM_VERIFY_TLS": (_enum("true"), "WinRM certificate validation (always true)", False),
    "CYBERPULSE_PLUGINS": (_any, "Plugin modules to load", False),
    # Secrets: accepted from the environment only, never from the config file
    "CYBERPULSE_API_KEY": (_any, "REST API key", True),
    "INGEST_HMAC_SECRET": (_any, "Webhook HMAC secret", True),
    "VIRUSTOTAL_API_KEY": (_any, "VirusTotal API key", True),
    "ABUSEIPDB_API_KEY": (_any, "AbuseIPDB API key", True),
    "WINRM_PASSWORD": (_any, "WinRM password", True),
}


class ConfigError(ValueError):
    def __init__(self, problems):
        super().__init__("; ".join(problems))
        self.problems = problems


def load_file(path):
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ConfigError([f"{path}: top level must be a mapping of SETTING: value"])
    return {str(k): v for k, v in data.items()}


def validate(file_values, env=None):
    """Return the list of problems in file values and environment values."""
    env = os.environ if env is None else env
    problems = []
    for key, value in file_values.items():
        if key not in SCHEMA:
            problems.append(f"config file: unknown setting {key}")
        elif SCHEMA[key][2]:
            problems.append(f"config file: {key} is a secret; set it in the environment / .env instead")
    for key, (check, _desc, _secret) in SCHEMA.items():
        for source, values in (("config file", file_values), ("environment", env)):
            if key in values and str(values[key]).strip() != "":
                try:
                    check(values[key])
                except (ValueError, TypeError) as exc:
                    problems.append(f"{source}: {key}={values[key]!r} {exc}")
    return problems


def load_and_apply(path=None, env=None):
    """Validate, then apply file values as defaults beneath the environment. Raises ConfigError."""
    env = os.environ if env is None else env
    path = path or env.get("CYBERPULSE_CONFIG")
    file_values = load_file(path) if path else {}
    problems = validate(file_values, env)
    if problems:
        raise ConfigError(problems)
    for key, value in file_values.items():
        env.setdefault(key, str(value).lower() if isinstance(value, bool) else str(value))
    return file_values


def main(argv):
    path = argv[1] if len(argv) > 1 and argv[0] == "--check" else (argv[0] if argv and argv[0] != "--check" else None)
    try:
        values = load_and_apply(path)
    except ConfigError as exc:
        for p in exc.problems:
            print(f"ERROR {p}")
        return 1
    print(f"Configuration valid ({len(values)} setting(s) from file, environment checked).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
