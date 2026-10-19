#!/usr/bin/env python3
"""
PlcSentinel - Day 3: Modbus TCP Protocol Dissector
Parses 'modbus_lab_traffic.pcap' and displays detailed forensic packet dissection:
- Ethernet / IP / TCP layer parameters
- 7-Byte MBAP Header (Transaction ID, Protocol ID, Length, Unit ID)
- Modbus PDU (Function Code, Address, Values, Sub-codes)
"""

import sys
from scapy.all import rdpcap, TCP, Raw
import scapy.contrib.modbus as mb

FC_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
}

def dissect_pcap(pcap_path="modbus_lab_traffic.pcap"):
    print(f"[*] Reading PCAP capture: {pcap_path} ...\n")
    packets = rdpcap(pcap_path)
    print(f"Total Packets: {len(packets)}")
    print("=" * 80)

    for idx, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(TCP):
            continue

        raw_payload = bytes(pkt[TCP].payload)
        if len(raw_payload) < 7:
            continue

        # MBAP Header Parsing
        trans_id = int.from_bytes(raw_payload[0:2], "big")
        proto_id = int.from_bytes(raw_payload[2:4], "big")
        length = int.from_bytes(raw_payload[4:6], "big")
        unit_id = raw_payload[6]

        # PDU Parsing
        fc = raw_payload[7]
        is_exception = fc >= 0x80
        direction = "REQ -> PLC" if pkt[TCP].dport == 502 else "RES <- PLC"

        fc_desc = FC_NAMES.get(fc, f"Unknown/Vendor ({fc})")
        if is_exception:
            exc_code = raw_payload[8] if len(raw_payload) > 8 else -1
            fc_desc = f"EXCEPTION (Original FC: {fc - 0x80}, Code: {exc_code})"

        hex_dump = " ".join(f"{b:02X}" for b in raw_payload[:16])

        print(f"Packet #{idx:02d} | [{direction}] | TransID: {trans_id:04d} | Unit: {unit_id} | FC: {fc:02d} ({fc_desc})")
        print(f"       MBAP: Proto={proto_id:04X} Len={length:02d} | Hex: {hex_dump}")
        
        # Payload Details
        if not is_exception and len(raw_payload) > 8:
            if direction == "REQ -> PLC":
                addr = int.from_bytes(raw_payload[8:10], "big")
                val_or_qty = int.from_bytes(raw_payload[10:12], "big") if len(raw_payload) >= 12 else 0
                print(f"       Details: Reference/Start Address = {addr} (0x{addr:04X}), Value/Count = {val_or_qty}")
            else:
                byte_count = raw_payload[8] if len(raw_payload) > 8 else 0
                data_bytes = raw_payload[9:]
                print(f"       Details: Byte Count = {byte_count}, Data = {' '.join(f'{b:02X}' for b in data_bytes)}")
        print("-" * 80)

if __name__ == "__main__":
    dissect_pcap()
