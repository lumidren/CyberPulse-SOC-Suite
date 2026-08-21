#!/usr/bin/env python3
"""
CyberPulse SOC Suite - Enterprise CLI Operations & Management Suite
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
from simulator.purple_team_runner import PurpleTeamRunner
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
                    CYBERPULSE ENTERPRISE SOC PLATFORM v2.4
"""

def print_banner():
    print("\033[96m" + BANNER + "\033[0m")
    print("=" * 80)
    print("  [✓] Closed-Loop Detection Engineering     | [✓] Multi-Factor Risk & Policy Engine")
    print("  [✓] Resilient SOAR Containment & Rollback | [✓] Purple Team Attack Replay Engine")
    print("  [✓] Unified Incident Timeline & TheHive 5 | [✓] Real-Time System Health Diagnostics")
    print("=" * 80)
    print()

def menu():
    print("\033[93m[ENTERPRISE SOC OPERATIONS MENU]\033[0m")
    print("  \033[92m[1]\033[0m Launch Enterprise Web Console (http://localhost:5000)")
    print("  \033[92m[2]\033[0m Run Detection & SOAR Automated Test Suite (11 Test Scenarios)")
    print("  \033[92m[3]\033[0m Execute APT29 / Cozy Bear Purple Team Validation Campaign")
    print("  \033[92m[4]\033[0m Execute LockBit 3.0 Ransomware Attack & Recovery Lifecycle")
    print("  \033[92m[5]\033[0m Run Active System Diagnostics & Integration Health Probe")
    print("  \033[92m[6]\033[0m Test Live Discord / Slack Webhook Incident Dispatch")
    print("  \033[92m[7]\033[0m Export Latest DFIR Incident Dossier (JSON/Markdown)")
    print("  \033[91m[0]\033[0m Exit")
    print()

def run_tests():
    print("\n[*] Running Enterprise Test Suite...")
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir='tests', pattern='test_*.py')
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n\033[92m[✓] All 11 Unit & Integration Test Scenarios Passed Successfully!\033[0m\n")
    else:
        print("\n\033[91m[✗] Test failures detected.\033[0m\n")

def run_purple_campaign(scenario_key):
    orchestrator = SOAROrchestrator()
    runner = PurpleTeamRunner(orchestrator)
    print(f"\n[*] Launching Purple Team Scenario: {scenario_key}...")
    res = runner.run_scenario(scenario_key)
    
    print("\n" + "="*80)
    print(f" 🛡️  PURPLE TEAM EXECUTION RESULT: {res['scenario_name']}")
    print("="*80)
    print(f"  • Threat Actor: {res['threat_actor']}")
    print(f"  • Status:       \033[92m{res['overall_status']}\033[0m ({res['passed_stages']}/{res['total_stages']} Stages Verified)")
    print("-" * 80)
    for s in res["stage_results"]:
        status_color = "\033[92m[PASS]\033[0m" if s["status"] == "PASS" else "\033[91m[FAIL]\033[0m"
        print(f"  Stage {s['sequence']}: {s['stage_name']} ({s['technique_id']}) -> {status_color}")
        print(f"    - Sensor: {s['expected_sensor']} | Rule: {s['matched_rule']} | Risk Score: {s['risk_score']}/100")
        print(f"    - Containment: {s['containment_action']} (Status: {s['containment_status']} in {s['latency_sec']}s)")
    print("="*80 + "\n")

def run_health_probe():
    orchestrator = SOAROrchestrator()
    print("\n[*] Probing all SOC Integrations & Endpoints...")
    health = orchestrator.health_monitor.check_all_integrations()
    print("\n" + "="*80)
    print(f" 🩺  INTEGRATION HEALTH & DIAGNOSTICS ({health['timestamp']})")
    print("="*80)
    for key, s in health["services"].items():
        status_str = f"\033[92m[{s['status']}]\033[0m" if s["status"] == "HEALTHY" else (f"\033[93m[{s['status']}]\033[0m" if s["status"] == "DEGRADED" else f"\033[94m[{s['status']}]\033[0m")
        print(f"  {s['name']:<38} {status_str:<20} Target: {s['target']}")
        print(f"    -> Message: {s['message']} (Latency: {s['latency_ms']}ms | Mode: {s['mode']})")
    print("="*80 + "\n")

def test_webhook():
    url = input("\n[?] Enter Discord or Slack Webhook URL: ").strip()
    if not url.startswith("http"):
        print("\033[91m[!] Invalid URL provided.\033[0m\n")
        return

    print("[*] Generating test security incident and dispatching webhook...")
    orchestrator = SOAROrchestrator(webhook_url=url)
    event = generate_random_attack()
    incident = orchestrator.process_event(event, custom_webhook_url=url)
    
    dispatch_res = incident.get("webhook_dispatch", {})
    if dispatch_res.get("status") == "SUCCESS":
        print("\033[92m[✓] Webhook dispatched successfully! Check your Discord/Slack channel.\033[0m\n")
    else:
        print(f"\033[91m[!] Webhook dispatch status: {dispatch_res}\033[0m\n")

def export_dossier():
    orchestrator = SOAROrchestrator()
    event = generate_random_attack()
    incident = orchestrator.process_event(event)
    
    filename = f"dossier_{incident['incident_id']}.json"
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(incident, f, indent=2)
    print(f"\n\033[92m[✓] DFIR Incident Dossier exported to: {filepath}\033[0m\n")

def main():
    print_banner()
    while True:
        menu()
        choice = input("Enter choice [0-7]: ").strip()
        if choice == "1":
            print("\n[*] Starting Enterprise Web Console on http://localhost:5000 ...")
            run_server(5000)
            break
        elif choice == "2":
            run_tests()
        elif choice == "3":
            run_purple_campaign("APT29_COZY_BEAR")
        elif choice == "4":
            run_purple_campaign("LOCKBIT_RANSOMWARE")
        elif choice == "5":
            run_health_probe()
        elif choice == "6":
            test_webhook()
        elif choice == "7":
            export_dossier()
        elif choice == "0":
            print("\nExiting CyberPulse. Stay secure!\n")
            break
        else:
            print("\n\033[91m[!] Invalid option. Please select 0-7.\033[0m\n")

if __name__ == "__main__":
    main()
