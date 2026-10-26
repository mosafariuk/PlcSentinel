#!/usr/bin/env python3
"""
PlcSentinel - Day 6: OT Detection Engine & Threat Analyzer
Applies IEC 62443 / MITRE ATT&CK for ICS detection logic against PCAP traffic:
- Emulates Suricata / Zeek Layer 7 Modbus DPI inspection
- Evaluates function code authorization, boundary violations, and exceptions
- Generates structured incident alerts
"""

import sys
from scapy.all import rdpcap, TCP

def run_ids_inspection(pcap_path="data/modbus_lab_traffic.pcap", authorized_ews_ip="192.168.1.50"):
    print(f"[*] Starting ICS Intrusion Detection Engine on: {pcap_path}")
    print(f"[*] Authorized Engineering Station IP: {authorized_ews_ip}")
    print("=" * 80)

    packets = rdpcap(pcap_path)
    alerts = []

    for idx, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(TCP):
            continue

        raw = bytes(pkt[TCP].payload)
        if len(raw) < 8:
            continue

        # MBAP & PDU fields
        trans_id = int.from_bytes(raw[0:2], "big")
        proto_id = int.from_bytes(raw[2:4], "big")
        unit_id = raw[6]
        fc = raw[7]

        # Modbus/TCP always carries Protocol ID 0; skip other TCP payloads so
        # non-Modbus traffic on the segment does not generate false alerts.
        if proto_id != 0:
            continue

        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst
        is_client_to_plc = pkt[TCP].dport == 502

        # ----------------------------------------------------------------------
        # RULE 1000001: Unauthorized Write Single Coil (FC 05)
        # ----------------------------------------------------------------------
        if is_client_to_plc and fc == 5 and src_ip != authorized_ews_ip:
            coil_addr = int.from_bytes(raw[8:10], "big") if len(raw) >= 10 else -1
            coil_val = int.from_bytes(raw[10:12], "big") if len(raw) >= 12 else 0
            alerts.append({
                "pkt": idx, "sid": 1000001, "severity": "HIGH",
                "msg": f"OT-ATTACK: Unauthorized Write Single Coil (FC 05) targeting Coil {coil_addr} with Val 0x{coil_val:04X}",
                "src": src_ip, "dst": dst_ip, "mitre": "T0855 (Unauthorized Command Message)"
            })

        # ----------------------------------------------------------------------
        # RULE 1000002 & 1000003: Write Single Register & Setpoint Anomaly (FC 06)
        # ----------------------------------------------------------------------
        if is_client_to_plc and fc == 6:
            reg_addr = int.from_bytes(raw[8:10], "big") if len(raw) >= 10 else -1
            reg_val = int.from_bytes(raw[10:12], "big") if len(raw) >= 12 else 0

            # Out of bounds check on Holding Register 0 (High Threshold)
            if reg_addr == 0 and reg_val > 900:
                alerts.append({
                    "pkt": idx, "sid": 1000003, "severity": "CRITICAL",
                    "msg": f"OT-ANOMALY: High Tank Level Threshold Out-of-Bounds ({reg_val} > 900 max safe capacity)",
                    "src": src_ip, "dst": dst_ip, "mitre": "T0836 (Modify Parameter / Loss of Containment Hazard)"
                })

            if src_ip != authorized_ews_ip:
                alerts.append({
                    "pkt": idx, "sid": 1000002, "severity": "MEDIUM",
                    "msg": f"OT-POLICY: Unauthorized Write Single Register (FC 06) targeting Reg {reg_addr} Val {reg_val}",
                    "src": src_ip, "dst": dst_ip, "mitre": "T0855 (Unauthorized Command Message)"
                })

        # ----------------------------------------------------------------------
        # RULE 1000004: Exception Response (FC >= 0x80)
        # ----------------------------------------------------------------------
        if not is_client_to_plc and fc >= 0x80:
            exc_code = raw[8] if len(raw) > 8 else 0
            alerts.append({
                "pkt": idx, "sid": 1000004, "severity": "LOW",
                "msg": f"OT-RECON: PLC Generated Modbus Exception (Orig FC: {fc - 0x80}, Exception Code: 0x{exc_code:02X})",
                "src": src_ip, "dst": dst_ip, "mitre": "T0843 (Program / Memory Probing)"
            })

    # Summary Output
    print(f"[+] Total Security Events Detected: {len(alerts)}\n")
    for a in alerts:
        color = "\033[91m" if a["severity"] in ["HIGH", "CRITICAL"] else "\033[93m"
        reset = "\033[0m"
        print(f"{color}[ALERT #{a['sid']} - {a['severity']}]{reset} Packet #{a['pkt']:02d} | {a['src']} -> {a['dst']}")
        print(f"       Message: {a['msg']}")
        print(f"       ATT&CK:  {a['mitre']}")
        print("-" * 80)

if __name__ == "__main__":
    run_ids_inspection()
