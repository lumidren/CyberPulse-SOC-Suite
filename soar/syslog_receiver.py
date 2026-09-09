import socket
import threading
import json
import re
import time
from datetime import datetime, timezone

class SyslogReceiver:
    """
    Live Syslog Listener for CyberPulse.
    Listens for RFC 5424 syslog messages on a UDP port and normalizes them.
    """
    def __init__(self, host='0.0.0.0', port=5514):
        self.host = host
        self.port = port
        self.sock = None
        self.running = False
        self.thread = None
        
        self.events = []
        self.total_received = 0
        self.total_parsed = 0
        self.total_errors = 0
        self.start_time = None

    def _parse_syslog(self, message: str) -> dict:
        """
        Parse incoming syslog messages and normalize them into CyberPulse's event schema:
        (event_id, event_source, technique_id, timestamp, computer_name, user, source_ip, details dict).
        """
        try:
            # Basic attempt to parse RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID] MSG
            # or older format <PRI> TIMESTAMP HOSTNAME MSG
            match = re.match(r'<(\d+)>(?:1 )?(\S+) (\S+) (.*)', message)
            if match:
                pri = match.group(1)
                timestamp = match.group(2)
                hostname = match.group(3)
                rest = match.group(4)
                
                # Check if JSON payload is embedded in the message
                details = {}
                try:
                    idx = rest.find('{')
                    if idx != -1:
                        details = json.loads(rest[idx:])
                    else:
                        details = {"raw": rest}
                except json.JSONDecodeError:
                    details = {"raw": rest}
                    
                event_id = details.get("event_id", "syslog_generic")
                event_source = details.get("event_source", "syslog")
                technique_id = details.get("technique_id", "Unknown")
                user = details.get("user", "Unknown")
                source_ip = details.get("source_ip", "")
                
                return {
                    "event_id": event_id,
                    "event_source": event_source,
                    "technique_id": technique_id,
                    "timestamp": timestamp,
                    "computer_name": hostname,
                    "user": user,
                    "source_ip": source_ip,
                    "details": details
                }
            else:
                # Fallback for unrecognized formats
                return {
                    "event_id": "syslog_raw",
                    "event_source": "syslog",
                    "technique_id": "Unknown",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "computer_name": "Unknown",
                    "user": "Unknown",
                    "source_ip": "",
                    "details": {"raw": message}
                }
        except Exception as e:
            raise ValueError(f"Failed to parse syslog message: {e}")

    def _listen(self):
        """Background thread worker to listen for UDP packets."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(1.0)
        except Exception as e:
            print(f"Error binding to {self.host}:{self.port} - {e}")
            self.running = False
            return
            
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                self.total_received += 1
                message = data.decode('utf-8', errors='replace').strip()
                
                try:
                    event = self._parse_syslog(message)
                    # Automatically use sender's IP if it's missing in the message
                    if not event.get("source_ip"):
                        event["source_ip"] = addr[0]
                    self.events.append(event)
                    self.total_parsed += 1
                except Exception:
                    self.total_errors += 1
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.total_errors += 1
        
        self.sock.close()

    def start(self):
        """Begin listening for syslog messages in a background daemon thread."""
        if self.running:
            return
        self.running = True
        self.start_time = time.time()
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()

    def stop(self):
        """Terminate the listening thread."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

    def get_received_events(self) -> list:
        """Return a copy of all events received so far."""
        return list(self.events)

    def get_stats(self) -> dict:
        """Return operational statistics."""
        uptime = time.time() - self.start_time if self.start_time else 0.0
        return {
            "total_received": self.total_received,
            "total_parsed": self.total_parsed,
            "total_errors": self.total_errors,
            "uptime_seconds": round(uptime, 2),
            "listening_port": self.port
        }


class WebhookIngestionHandler:
    """
    Webhook Ingestion Listener for CyberPulse.
    Handles POST payloads, validates, and normalizes them into the common schema.
    """
    def handle_ingest(self, json_body: dict) -> dict:
        required_fields = ["event_id", "computer_name", "source_ip"]
        for field in required_fields:
            if field not in json_body:
                return {
                    "status": "ERROR",
                    "error": f"Missing required field: {field}"
                }
                
        event = {
            "event_id": json_body.get("event_id"),
            "event_source": json_body.get("event_source", "webhook"),
            "technique_id": json_body.get("technique_id", "Unknown"),
            "timestamp": json_body.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "computer_name": json_body.get("computer_name"),
            "user": json_body.get("user", "Unknown"),
            "source_ip": json_body.get("source_ip"),
            "details": json_body.get("details", {})
        }
        
        return {
            "status": "SUCCESS",
            "event_id": event["event_id"],
            "normalized_event": event
        }

if __name__ == '__main__':
    receiver = SyslogReceiver(port=5514)
    print(f"Starting SyslogReceiver on port {receiver.port}...")
    receiver.start()
    
    # Send a dummy syslog message for testing
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_msg = '<165>1 2026-09-09T12:00:00Z web-server my-app - - {"event_id": "4624", "user": "admin_user", "technique_id": "T1078"}'
    try:
        sock.sendto(test_msg.encode('utf-8'), ('127.0.0.1', 5514))
    except Exception as e:
        print("Failed to send test message:", e)
    
    print("Listening for 5 seconds...")
    time.sleep(5)
    
    print("--- Stats ---")
    print(json.dumps(receiver.get_stats(), indent=2))
    
    print("--- Received Events ---")
    print(json.dumps(receiver.get_received_events(), indent=2))
    
    print("Stopping SyslogReceiver...")
    receiver.stop()
    print("Stopped.")
