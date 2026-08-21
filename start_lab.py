#!/usr/bin/env python3
"""
CyberPulse SOC Suite - Interactive CLI Management & Operations Suite
Author: lumidren (https://github.com/lumidren/CyberPulse-SOC-Suite)
"""

import os
import sys
import time
import json
import unittest

# Ensure project root in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simulator.attack_simulator import generate_random_attack
from soar.soar_engine import SOAROrchestrator
from server import run_server

BANNER = r"""
  ______               __                 _______         __                 
 /      \             |  \               |       \       |  \                
|  $$$$$$\__    __  __| $$  ______   ____| $$$$$$$\__   _| $$  _______  ____ 
| $$   \$$  \  /  \|  \$$ |      \ /      \ $$__/  \ | | | $$ /       \/      \
| $$     \$$\/  $$$$$$| $$ \$$$$$$\  $$$$$$\ $$    $$ | | | $$|  $$$$$$$  $$$$$$\
| $$   __ >$$  $$ | $$| $$ /      $$ $$  | $$ $$$$$$$| | | | $$ \$$    \| $$    $$
| $$__/  /  $$$$\ | $$| $$|  $$$$$$$ $$__| $$ $$     | |_| | $$ _\$$$$$$\ $$$$$$$$
 \$$    $$  \$$\$$\$$$| $$ \$$    $$\$$    $$ $$      \$$$$$| $$|       $$ \$$     \
  \$$$$$$    \$$ \$$   \$$  \$$$$$$$ \$$$$$$$ \$$            \$$ \$$$$$$$   \$$$$$$$
                    CYBERPULSE AUTOMATED SIEM & SOAR LAB
"""

def print_banner():
    print("\033[96m" + BANNER + "\033[0m")
    print("=" * 78)
    print("  [✓] Detection Engineering (Sigma + Wazuh) | [✓] Sub-second SOAR Automation")
    print("  [✓] Dual Mode (IaC Lab + CI/CD Harness)  | [✓] Live GeoIP Threat Visualizer")
    print("=" * 78)
    print()

def menu():
    print("\033[93m[OPERATIONS MENU]\033[0m")
    print("  \033[92m[1]\033[0m Launch Web Operations Center Dashboard (http://localhost:5000)")
    print("  \033[92m[2]\033[0m Run Detection-as-Code (DaC) Automated Test Suite")
    print("  \033[92m[3]\033[0m Execute Real-Time Adversary Emulation Stream (Terminal Mode)")
    print("  \033[92m[4]\033[0m Test Live Discord / Slack Webhook Dispatch")
    print("  \033[92m[5]\033[0m Export Latest Incident Triage Report (Markdown/JSON)")
    print("  \033[91m[0]\033[0m Exit")
    print()

def run_tests():
    print("\n[*] Running Detection-as-Code Test Suite...")
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir='tests', pattern='test_*.py')
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n\033[92m[✓] All Sigma Detection Rules and SOAR Playbooks Passed Successfully!\033[0m\n")
    else:
        print("\n\033[91m[✗] Unit test failures detected.\033[0m\n")

def run_emulation_stream():
    print("\n[*] Starting Live Adversary Emulation Stream (5 Events)...")
    orchestrator = SOAROrchestrator()
    for i in range(1, 6):
        event = generate_random_attack()
        print(f"\n------------------------------------------------------------")
        print(f"[*] [Event #{i}] Simulating: {event.get('technique_id')} ({event.get('technique_name')})")
        print(f"    Source IP: {event.get('source_ip')} | Target: {event.get('computer_name')}")
        
        alert = orchestrator.process_event(event)
        if alert:
            timing = alert["pipeline_timing"]
            soar = alert["soar_response"]
            print(f"    \033[92m[✓] Matched Rule:\033[0m {alert['rule']['rule_name']} ({alert['rule']['severity']})")
            print(f"    \033[96m[⚡] Latency:\033[0m {timing['total_pipeline_sec']}s (Detection: {timing['stage1_detection_ms']}ms | Containment: {timing['stage3_containment_ms']}ms)")
            print(f"    \033[93m[🛡️] Containment Action:\033[0m {soar['execution_protocol']}")
            print(f"        Log: {soar['execution_log']}")
        time.sleep(1)
    print("\n\033[92m[*] Emulation stream complete.\033[0m\n")

def test_webhook():
    url = input("\n[?] Enter Discord or Slack Webhook URL: ").strip()
    if not url.startswith("http"):
        print("\033[91m[!] Invalid URL provided.\033[0m\n")
        return

    print("[*] Generating test security incident and dispatching webhook...")
    orchestrator = SOAROrchestrator(webhook_url=url)
    event = generate_random_attack()
    alert = orchestrator.process_event(event, custom_webhook_url=url)
    
    dispatch_res = alert.get("webhook_dispatch", {})
    if dispatch_res.get("status") == "SUCCESS":
        print("\033[92m[✓] Webhook dispatched successfully! Check your Discord/Slack channel.\033[0m\n")
    else:
        print(f"\033[91m[!] Webhook dispatch status: {dispatch_res}\033[0m\n")

def export_report():
    orchestrator = SOAROrchestrator()
    event = generate_random_attack()
    alert = orchestrator.process_event(event)
    
    filename = f"incident_{alert['alert_id']}.json"
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(alert, f, indent=2)
    print(f"\n\033[92m[✓] Incident Report exported to: {filepath}\033[0m\n")

def main():
    print_banner()
    while True:
        menu()
        choice = input("Enter choice [0-5]: ").strip()
        if choice == "1":
            print("\n[*] Starting Web Server on http://localhost:5000 ...")
            run_server(5000)
            break
        elif choice == "2":
            run_tests()
        elif choice == "3":
            run_emulation_stream()
        elif choice == "4":
            test_webhook()
        elif choice == "5":
            export_report()
        elif choice == "0":
            print("\nExiting CyberPulse. Stay secure!\n")
            break
        else:
            print("\n\033[91m[!] Invalid option. Please select 0-5.\033[0m\n")

if __name__ == "__main__":
    main()
