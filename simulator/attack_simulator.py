"""
Adversary Telemetry & Attack Simulator for CyberPulse SOC Suite
Generates deterministic, schema-compliant Windows Event Logs and Sysmon records
covering MITRE ATT&CK enterprise tactics and adversary tradecraft.
"""

import json
import random
import time
from datetime import datetime, timezone

def simulate_t1003_lsass_dump():
    """T1003.001 - OS Credential Dumping: LSASS Memory Access"""
    return {
        "event_id": 10,
        "event_source": "Microsoft-Windows-Sysmon/Operational",
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "computer_name": "WIN-DC01.corp.local",
        "user": "CORP\\Administrator",
        "source_ip": "185.220.101.33",
        "details": {
            "SourceProcessId": 4812,
            "SourceImage": "C:\\Windows\\Temp\\mimikatz.exe",
            "TargetProcessId": 672,
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9a100|C:\\Windows\\System32\\KERNELBASE.dll+2c410",
            "FileHash_SHA256": "F058F9A5D60E36E4E2C79E89DCE9A32158814F23D6980D4181F54B00D499E0C1"
        }
    }

def simulate_t1110_brute_force():
    """T1110.001 - Brute Force: Password Guessing (RDP Authentication)"""
    return {
        "event_id": 4625,
        "event_source": "Security",
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "computer_name": "CORP-RDP-GW01",
        "user": "admin",
        "source_ip": "185.220.101.5",
        "details": {
            "LogonType": 10,
            "FailedAttemptsCount": 18,
            "TargetUserName": "admin",
            "TargetDomainName": "CORP",
            "Status": "0xc000006d",
            "SubStatus": "0xc000006a",
            "WorkstationName": "ATTACKER-BOX",
            "IpPort": 54122
        }
    }

def simulate_t1053_scheduled_task():
    """T1053.005 - Scheduled Task/Job: Scheduled Task Persistence"""
    return {
        "event_id": 4698,
        "event_source": "Security",
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task: Persistence Mechanism",
        "tactic": "Persistence",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "computer_name": "WIN-WORKSTATION09",
        "user": "CORP\\j.doe",
        "source_ip": "10.0.2.15",
        "details": {
            "TaskName": "\\Microsoft\\Windows\\SystemHealthUpdate",
            "TaskContent": "<Exec><Command>powershell.exe</Command><Arguments>-WindowStyle Hidden -Enc aW52b2tlLWV4cHJlc3Npb24=</Arguments></Exec>",
            "Principal": "NT AUTHORITY\\SYSTEM"
        }
    }

def simulate_t1059_powershell_execution():
    """T1059.001 - Command and Scripting Interpreter: PowerShell Execution"""
    return {
        "event_id": 1,
        "event_source": "Microsoft-Windows-Sysmon/Operational",
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting: PowerShell",
        "tactic": "Execution",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "computer_name": "CORP-FINANCE-02",
        "user": "CORP\\m.worker",
        "source_ip": "10.0.4.88",
        "details": {
            "ProcessId": 5912,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -nop -w hidden -encodedcommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "Hashes": "SHA256=F058F9A5D60E36E4E2C79E89DCE9A32158814F23D6980D4181F54B00D499E0C1"
        }
    }

def simulate_t1562_defender_tamper():
    """T1562.001 - Impair Defenses: Disable Windows Defender Real-Time Protection"""
    return {
        "event_id": 1,
        "event_source": "Microsoft-Windows-Sysmon/Operational",
        "technique_id": "T1562.001",
        "technique_name": "Impair Defenses: Disable Tools",
        "tactic": "Defense Evasion",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "computer_name": "WIN-WORKSTATION09",
        "user": "CORP\\j.doe",
        "source_ip": "91.240.118.172",
        "details": {
            "ProcessId": 5120,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ParentCommandLine": "cmd.exe /c start_update.bat"
        }
    }

def simulate_t1486_ransomware_canary():
    """T1486 - Data Encrypted for Impact: Rapid Canary File Encryption"""
    return {
        "event_id": 11,
        "event_source": "Microsoft-Windows-Sysmon/Operational",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "computer_name": "CORP-FINANCE-02",
        "user": "CORP\\finance_admin",
        "source_ip": "193.142.146.210",
        "details": {
            "ProcessId": 6104,
            "Image": "C:\\Users\\finance_admin\\AppData\\Local\\Temp\\locker.exe",
            "TargetFilename": "C:\\Users\\finance_admin\\Documents\\Decoy_Financials_Q3.xlsx.locked",
            "RansomNote": "C:\\Users\\finance_admin\\Documents\\HOW_TO_DECRYPT.txt",
            "FileHash_SHA256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
        }
    }

def simulate_t1558_kerberoasting():
    """T1558.001 - Steal or Forge Kerberos Tickets: Kerberoasting TGS Request"""
    return {
        "event_id": 4769,
        "event_source": "Security",
        "technique_id": "T1558.001",
        "technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "tactic": "Credential Access",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "computer_name": "WIN-DC01.corp.local",
        "user": "CORP\\j.doe",
        "source_ip": "10.0.0.45",
        "details": {
            "ServiceName": "MSSQLSvc/sql01.corp.local:1433",
            "TicketOptions": "0x40810000",
            "TicketEncryptionType": "0x17",
            "Status": "0x0"
        }
    }

def simulate_t1003_dcsync():
    """T1003.006 - OS Credential Dumping: DCSync Replication Abuse"""
    return {
        "event_id": 4662,
        "event_source": "Security",
        "technique_id": "T1003.006",
        "technique_name": "OS Credential Dumping: DCSync",
        "tactic": "Credential Access",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "computer_name": "WIN-DC01.corp.local",
        "user": "CORP\\compromised_admin",
        "source_ip": "194.26.29.112",
        "details": {
            "AccessMask": "0x100",
            "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}\n{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
            "SubjectUserName": "compromised_admin"
        }
    }

def generate_random_attack():
    """Selects and generates a random adversary emulation event"""
    generators = [
        simulate_t1003_lsass_dump,
        simulate_t1110_brute_force,
        simulate_t1053_scheduled_task,
        simulate_t1059_powershell_execution,
        simulate_t1562_defender_tamper,
        simulate_t1486_ransomware_canary,
        simulate_t1558_kerberoasting,
        simulate_t1003_dcsync
    ]
    chosen = random.choice(generators)
    return chosen()

if __name__ == "__main__":
    event = generate_random_attack()
    print(json.dumps(event, indent=2))
