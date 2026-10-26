#!/usr/bin/env python3
"""
PlcSentinel - Unified Industrial OT SOC Incident Dashboard
Aggregates and visualizes live SIEM telemetry across multi-protocol environments:
- Modbus TCP (Port 502 / 5020) from 'logs/ot_security_events.jsonl'
- Siemens S7comm (Port 102 / 10200) from 'logs/s7_security_events.jsonl'
- MITRE ATT&CK for ICS Matrix Mapping
- Multi-protocol incident timeline
"""

import os
import json
import glob
from collections import Counter

LOG_FILES = [
    "logs/ot_security_events.jsonl",
    "logs/s7_security_events.jsonl",
    "logs/conduit_events.jsonl",
    "logs/iec104_security_events.jsonl",
]

def load_all_events():
    events = []
    for filepath in LOG_FILES:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except Exception:
                            pass
    # Sort chronologically
    events.sort(key=lambda x: x.get("@timestamp", ""))
    return events

def render_unified_dashboard(events):
    total = len(events)
    # "detected" = a violation seen by a gateway running in monitor mode.
    blocked = [e for e in events if e.get("event", {}).get("action") in ("blocked", "detected")]
    allowed = [e for e in events if e.get("event", {}).get("action") == "allowed"]

    severities = Counter([e.get("event", {}).get("severity_label", "info").upper() for e in events])
    proto_counts = Counter([e.get("network", {}).get("protocol", "unknown").upper() for e in events])

    mitre_counts = Counter([
        f"{e.get('rule', {}).get('mitre', {}).get('id')} - {e.get('rule', {}).get('mitre', {}).get('name')}"
        for e in blocked if e.get('rule', {}).get('mitre', {}).get('id')
    ])

    print("\033[H\033[J", end="")  # Clear screen
    print("+" + "=" * 78 + "+")
    print("|            PlcSentinel - UNIFIED MULTI-PROTOCOL OT SOC DASHBOARD             |")
    print("|             Monitoring: Modbus TCP (OpenPLC) & Siemens S7comm                |")
    print("+" + "=" * 78 + "+")
    print(f"|  TOTAL EVENTS: {total:05d}  |  ALLOWED: {len(allowed):05d}  |  BLOCKED INTRUSIONS: \033[91m{len(blocked):05d}\033[0m            |")
    print(f"|  PROTOCOLS MONITORED: Modbus TCP ({proto_counts['MODBUS_TCP']}) | Siemens S7comm ({proto_counts['S7COMM']})                      |")
    print("+" + "-" * 78 + "+")
    print("|  [SEVERITY BREAKDOWN]                                                        |")
    print(f"|  \033[91mCRITICAL:\033[0m {severities['CRITICAL']:03d}   |  \033[93mHIGH:\033[0m {severities['HIGH']:03d}   |  \033[94mMEDIUM:\033[0m {severities['MEDIUM']:03d}   |  INFO: {severities['INFORMATIONAL']:03d}           |")
    print("+" + "-" * 78 + "+")
    print("|  [MITRE ATT&CK FOR ICS - DETECTED THREAT TECHNIQUES]                         |")
    if mitre_counts:
        for tech, count in mitre_counts.items():
            print(f"|  - {tech:<57} : \033[91m{count:03d} hits\033[0m   |")
    else:
        print("|  - No active threats detected yet.                                           |")
    print("+" + "-" * 78 + "+")
    print("|  [RECENT SECURITY INCIDENTS (LAST 6 ACROSS ENTIRE PLANT)]                    |")
    recent = events[-6:]
    for e in reversed(recent):
        ts = e.get("@timestamp", "")[:19].replace("T", " ")
        action = e.get("event", {}).get("action", "").upper()
        color = {"BLOCKED": "\033[91m", "DETECTED": "\033[93m"}.get(action, "\033[92m")
        reset = "\033[0m"
        proto = e.get("network", {}).get("protocol", "").replace("_tcp", "").upper()
        
        # Extract function name from modbus or s7comm
        fc_name = (
            e.get("s7comm", {}).get("function_name") or
            e.get("modbus", {}).get("function_name") or
            "Unknown Operation"
        )
        src_ip = e.get("source", {}).get("ip", "")
        desc = e.get("rule", {}).get("description", "")[:48]
        print(f"| {ts} | {proto:^6} | {color}{action:^7}{reset} | {src_ip:<11} | {fc_name:<18} |")
        print(f"|    -> Policy: {desc:<61} |")
    print("+" + "=" * 78 + "+")

if __name__ == "__main__":
    import argparse
    import time
    parser = argparse.ArgumentParser(description="PlcSentinel OT SOC Dashboard")
    parser.add_argument("--watch", action="store_true", help="Continuously refresh dashboard")
    parser.add_argument("--interval", type=int, default=5, help="Refresh interval in seconds (default: 5)")
    args = parser.parse_args()

    if args.watch:
        try:
            while True:
                evts = load_all_events()
                render_unified_dashboard(evts)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nDashboard monitoring stopped.")
    else:
        evts = load_all_events()
        render_unified_dashboard(evts)
