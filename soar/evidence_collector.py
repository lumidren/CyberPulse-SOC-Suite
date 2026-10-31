import json
import datetime
import uuid

from soar.redaction import redact_deep

class VolatileEvidenceCollector:
    """
    Automated DFIR Volatile Evidence Collector (Pre-Containment Triage Packager)
    for CyberPulse SOC Suite.
    """
    def collect_volatile_evidence(self, event, containment_action):
        """
        Simulates gathering pre-containment volatile state from a Windows host.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        evidence_package = {
            "network_connections": [
                {"pid": 1024, "local_addr": "192.168.1.10:4444", "remote_addr": "10.0.0.5:8080", "state": "ESTABLISHED", "process_name": "malware.exe"},
                {"pid": 1024, "local_addr": "192.168.1.10:4445", "remote_addr": "10.0.0.6:443", "state": "ESTABLISHED", "process_name": "malware.exe"},
                {"pid": 2048, "local_addr": "192.168.1.10:3389", "remote_addr": "0.0.0.0:0", "state": "LISTENING", "process_name": "svchost.exe"},
                {"pid": 3072, "local_addr": "192.168.1.10:135", "remote_addr": "0.0.0.0:0", "state": "LISTENING", "process_name": "svchost.exe"},
                {"pid": 4096, "local_addr": "192.168.1.10:5555", "remote_addr": "10.10.10.10:80", "state": "TIME_WAIT", "process_name": "cmd.exe"}
            ],
            "loaded_dlls": [
                "C:\\Windows\\System32\\ntdll.dll",
                "C:\\Windows\\System32\\kernel32.dll",
                "C:\\Windows\\System32\\ws2_32.dll",
                "C:\\Windows\\System32\\advapi32.dll"
            ],
            "prefetch_entries": [
                {"executable_name": "MALWARE.EXE", "run_count": 5, "last_execution": now},
                {"executable_name": "CMD.EXE", "run_count": 120, "last_execution": now},
                {"executable_name": "POWERSHELL.EXE", "run_count": 45, "last_execution": now}
            ],
            "autoruns_persistence": [
                {"location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "malware.exe", "data": "C:\\Users\\Public\\malware.exe"},
                {"location": "Task Scheduler", "value": "UpdateService", "data": "C:\\Windows\\Temp\\update.vbs"},
                {"location": "Windows Service", "value": "MaliciousService", "data": "C:\\Windows\\System32\\mal_svc.exe"}
            ],
            "memory_strings": [
                "http://malicious-c2.com/payload.bin",
                "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA...",
                "Administrator:Password123!"
            ],
            "collection_metadata": {
                "collector_version": "1.0",
                "host": event.get("host", "unknown") if isinstance(event, dict) else "unknown",
                "timestamp": now,
                "total_artifacts_count": 18
            }
        }
        
        # Memory strings and command lines routinely contain credentials: redact before storing
        return redact_deep(evidence_package)

    def snapshot_process(self, host, pid, process_name, reason="pre-containment"):
        """Process + memory evidence captured immediately before a kill or isolation.

        Lab responders are simulated, so this records *what a real responder must
        collect and in which order*; no memory is actually acquired here.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return {
            "collected_at": now,
            "reason": reason,
            "host": host,
            "process": {"pid": pid, "image": process_name},
            "collected_items": [
                "process metadata (image path, command line, parent, user, start time, hashes)",
                "open handles and loaded modules",
                "active network connections for the PID",
            ],
            "memory_acquisition": {
                "order": [
                    "1. process memory dump of the target PID (before termination)",
                    "2. full physical memory image of the host (before network isolation, if policy allows)",
                ],
                "status": "SIMULATED",
                "note": "Lab responders are simulated; no memory was acquired.",
            },
        }

    def package_for_thehive(self, evidence_package):
        """
        Wraps the evidence into a TheHive 5 attachment-compatible structure.
        """
        return {
            "case_id": "CASE-" + str(uuid.uuid4())[:8],
            "attachment_name": "volatile_evidence.json",
            "mime_type": "application/json",
            "base64_placeholder": "base64_encoded_json_here"
        }

if __name__ == '__main__':
    collector = VolatileEvidenceCollector()
    event = {"host": "WIN-SRV-001"}
    evidence = collector.collect_volatile_evidence(event, "IsolateHost")
    packaged = collector.package_for_thehive(evidence)
    print("Evidence Package:")
    print(json.dumps(evidence, indent=2))
    print("\nPackaged for TheHive:")
    print(json.dumps(packaged, indent=2))
