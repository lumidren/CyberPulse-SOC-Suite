"""
Benign Baseline Traffic Generator for the CyberPulse SOC Lab

Produces synthetic, *benign* events in the same schema as the attack
generators so false-positive behaviour can be measured. Each category models
routine activity that real SOCs see every day and that naive rules commonly
misfire on:

* admin_scripts  - signed maintenance PowerShell, inventory and service checks
* backups        - wbadmin / VSS snapshot listing during nightly backup windows
* patching       - msiexec / Windows Update and vendor updater scheduled tasks
* av_scanning    - Defender (MsMpEng.exe) opening lsass.exe for inspection
* normal_auth    - single mistyped passwords and AES Kerberos service tickets
* cloud_ops      - CI/CD pipeline AssumeRole calls from a known build account

Generation is deterministic for a given seed so FP counts are reproducible.
Everything here is synthetic: hosts, users and IPs are lab values, and no
command is ever executed.
"""

import random
from datetime import datetime, timedelta, timezone

LAB_HOSTS = ["WIN-WORKSTATION09", "CORP-FINANCE-02", "WIN-DC01.corp.local", "CORP-RDP-GW01"]
LAB_USERS = ["CORP\\j.doe", "CORP\\m.worker", "CORP\\svc_backup", "CORP\\svc_patch"]
LAB_INTERNAL_IPS = ["10.0.2.15", "10.0.4.88", "10.0.0.45", "10.0.1.15"]

BASE_TIME = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _base(rng, event_id, source, category, technique_hint=None):
    return {
        "event_id": event_id,
        "event_source": source,
        "technique_id": technique_hint or "BENIGN",
        "technique_name": f"Benign baseline: {category}",
        "tactic": "None",
        "timestamp": (BASE_TIME + timedelta(seconds=rng.randint(0, 30 * 86400))).isoformat(),
        "computer_name": rng.choice(LAB_HOSTS),
        "user": rng.choice(LAB_USERS),
        "source_ip": rng.choice(LAB_INTERNAL_IPS),
        "baseline_category": category,
        "details": {},
    }


def benign_admin_script(rng):
    evt = _base(rng, 1, "Microsoft-Windows-Sysmon/Operational", "admin_scripts")
    script = rng.choice(["inventory.ps1", "rotate_logs.ps1", "check_services.ps1", "disk_report.ps1"])
    evt["details"] = {
        "ProcessId": rng.randint(1000, 9000),
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": f"powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\\Scripts\\{script}",
        "ParentImage": "C:\\Windows\\System32\\svchost.exe",
        "Signed": True,
    }
    return evt


def benign_backup(rng):
    evt = _base(rng, 1, "Microsoft-Windows-Sysmon/Operational", "backups")
    evt["user"] = "CORP\\svc_backup"
    cmd = rng.choice([
        "wbadmin.exe start backup -backupTarget:E: -include:C: -quiet",
        "vssadmin.exe list shadows",
        "vssadmin.exe create shadow /for=C:",
    ])
    evt["details"] = {
        "ProcessId": rng.randint(1000, 9000),
        "Image": "C:\\Windows\\System32\\" + cmd.split()[0],
        "CommandLine": cmd,
        "ParentImage": "C:\\Program Files\\Backup\\agent.exe",
    }
    return evt


def benign_patching(rng):
    if rng.random() < 0.5:
        evt = _base(rng, 1, "Microsoft-Windows-Sysmon/Operational", "patching")
        evt["user"] = "NT AUTHORITY\\SYSTEM"
        evt["details"] = {
            "ProcessId": rng.randint(1000, 9000),
            "Image": "C:\\Windows\\System32\\msiexec.exe",
            "CommandLine": "msiexec.exe /i C:\\Windows\\Temp\\agent_update.msi /qn /norestart",
            "ParentImage": "C:\\Windows\\System32\\services.exe",
        }
        return evt
    evt = _base(rng, 4698, "Security", "patching")
    evt["user"] = "CORP\\svc_patch"
    task = rng.choice([
        ("\\Vendor\\AgentUpdateTask", "<Exec><Command>C:\\Program Files\\Vendor\\updater.exe</Command><Arguments>/silent</Arguments></Exec>"),
        ("\\IT\\WeeklyMaintenance", "<Exec><Command>powershell.exe</Command><Arguments>-NoProfile -File C:\\Scripts\\maintenance.ps1</Arguments></Exec>"),
    ])
    evt["details"] = {"TaskName": task[0], "TaskContent": task[1], "Principal": "NT AUTHORITY\\SYSTEM"}
    return evt


def benign_av_scan(rng):
    evt = _base(rng, 10, "Microsoft-Windows-Sysmon/Operational", "av_scanning")
    evt["user"] = "NT AUTHORITY\\SYSTEM"
    evt["details"] = {
        "SourceProcessId": rng.randint(2000, 4000),
        "SourceImage": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2400.1-0\\MsMpEng.exe",
        "TargetProcessId": 672,
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1410",
    }
    return evt


def benign_auth(rng):
    if rng.random() < 0.5:
        evt = _base(rng, 4625, "Security", "normal_auth")
        evt["details"] = {
            "LogonType": rng.choice([2, 3, 10]),
            "FailedAttemptsCount": rng.randint(1, 3),
            "TargetUserName": evt["user"].split("\\")[-1],
            "Status": "0xc000006d",
            "SubStatus": "0xc000006a",
        }
        return evt
    evt = _base(rng, 4769, "Security", "normal_auth")
    evt["details"] = {
        "ServiceName": rng.choice(["cifs/fs01.corp.local", "HTTP/intranet.corp.local", "MSSQLSvc/sql01.corp.local:1433"]),
        "TicketOptions": "0x40810000",
        "TicketEncryptionType": rng.choice(["0x12", "0x11"]),  # AES256 / AES128, not RC4
        "Status": "0x0",
    }
    return evt


def benign_cloud_ops(rng):
    evt = _base(rng, 9901, "aws:cloudtrail", "cloud_ops")
    evt["computer_name"] = "aws-lab-account-000000000000"
    evt["user"] = "ci-deploy-pipeline"
    evt["source_ip"] = "10.0.1.15"
    evt["details"] = {
        "eventName": "AssumeRole",
        "eventSource": "sts.amazonaws.com",
        "roleArn": "arn:aws:iam::000000000000:role/ci-deploy",
        "durationSeconds": 900,
        "knownAutomation": True,
    }
    return evt


BASELINE_CATEGORIES = [
    ("admin_scripts", benign_admin_script),
    ("backups", benign_backup),
    ("patching", benign_patching),
    ("av_scanning", benign_av_scan),
    ("normal_auth", benign_auth),
    ("cloud_ops", benign_cloud_ops),
]


def generate_baseline(count=600, seed=1337):
    """Return `count` benign events, spread evenly across categories (deterministic)."""
    rng = random.Random(seed)
    events = []
    for i in range(count):
        _name, generator = BASELINE_CATEGORIES[i % len(BASELINE_CATEGORIES)]
        events.append(generator(rng))
    return events


if __name__ == "__main__":
    import json
    print(json.dumps(generate_baseline(6), indent=2))
