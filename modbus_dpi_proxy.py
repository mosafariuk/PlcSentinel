#!/usr/bin/env python3
"""
PlcSentinel - Upgraded Layer-7 Modbus Deep Packet Inspection (DPI) Proxy with SIEM Logging
Enforces:
1. Role-Based Access Control (ACL)
2. Semantic Process Boundary Inspection (Overfill Prevention)
3. RFC-Compliant Exception Generation (0x01 Illegal Function, 0x03 Illegal Data Value)
4. Structured SIEM JSON/ECS Event Streaming (logs/ot_security_events.jsonl)
"""

import os
import sys
import json
import socket
import select
import logging
import argparse
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [DPI-GATEWAY] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ModbusDPI")

EXC_ILLEGAL_FUNCTION = 0x01
EXC_ILLEGAL_DATA_ADDRESS = 0x02
EXC_ILLEGAL_DATA_VALUE = 0x03
EXC_SLAVE_DEVICE_FAILURE = 0x04

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

class ModbusDPIProxy:
    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 5020,
        backend_host: str = "127.0.0.1",
        backend_port: int = 502,
        authorized_ews_ip: str = "192.168.1.50",
        max_safe_high_threshold: int = 900,
        log_file: str = "logs/ot_security_events.jsonl"
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.authorized_ews_ip = authorized_ews_ip
        self.max_safe_high_threshold = max_safe_high_threshold
        self.log_file = log_file
        self.strict_write_lockdown = True
        self.stats = {"inspected": 0, "allowed": 0, "blocked": 0}

        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def emit_siem_event(
        self,
        action: str,
        severity: str,
        reason: str,
        client_ip: str,
        client_port: int,
        trans_id: int,
        unit_id: int,
        fc: int,
        mitre_technique_id: Optional[str] = None,
        mitre_technique_name: Optional[str] = None,
        payload_details: Optional[Dict[str, Any]] = None
    ):
        """Emits an Elastic Common Schema (ECS) / Wazuh compliant JSON event."""
        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {
                "dataset": "ics.modbus",
                "action": action,
                "category": ["network", "intrusion_detection"],
                "type": ["access", "protocol"],
                "outcome": "success" if action == "allowed" else "failure",
                "severity_label": severity,
            },
            "source": {"ip": client_ip, "port": client_port},
            "destination": {"ip": self.listen_host, "port": self.listen_port},
            "network": {"transport": "tcp", "protocol": "modbus_tcp"},
            "modbus": {
                "transaction_id": trans_id,
                "unit_id": unit_id,
                "function_code": fc,
                "function_name": FC_NAMES.get(fc, f"Vendor/Unknown ({fc})"),
                "payload": payload_details or {}
            },
            "rule": {
                "description": reason,
                "mitre": {
                    "id": mitre_technique_id,
                    "name": mitre_technique_name,
                    "tactic": "Execution / Inhibit Response Function" if mitre_technique_id else None
                }
            }
        }

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def generate_exception_response(self, trans_id: int, unit_id: int, orig_fc: int, exc_code: int) -> bytes:
        mbap = trans_id.to_bytes(2, "big") + b"\x00\x00" + b"\x00\x03" + unit_id.to_bytes(1, "big")
        pdu = bytes([orig_fc | 0x80, exc_code])
        return mbap + pdu

    def inspect_request(self, raw_pkt: bytes, client_ip: str, client_port: int) -> Tuple[bool, Optional[bytes], str]:
        self.stats["inspected"] += 1
        if len(raw_pkt) < 8:
            return False, None, "Malformed packet: length shorter than MBAP + FC"

        trans_id = int.from_bytes(raw_pkt[0:2], "big")
        proto_id = int.from_bytes(raw_pkt[2:4], "big")
        length = int.from_bytes(raw_pkt[4:6], "big")
        unit_id = raw_pkt[6]
        fc = raw_pkt[7]

        if proto_id != 0:
            return False, None, f"Invalid Protocol ID 0x{proto_id:04X}"

        is_write_fc = fc in [5, 6, 15, 16]

        # ----------------------------------------------------------------------
        # TIER 1: Function Code & Role-Based Authorization
        # ----------------------------------------------------------------------
        if is_write_fc and self.strict_write_lockdown and client_ip != self.authorized_ews_ip:
            self.stats["blocked"] += 1
            reason = f"POLICY VIOLATION: Write Function Code {fc:02d} ({FC_NAMES.get(fc)}) denied from unauthorized IP {client_ip}"
            exc_resp = self.generate_exception_response(trans_id, unit_id, fc, EXC_ILLEGAL_FUNCTION)

            addr = int.from_bytes(raw_pkt[8:10], "big") if len(raw_pkt) >= 10 else 0
            val = int.from_bytes(raw_pkt[10:12], "big") if len(raw_pkt) >= 12 else 0

            self.emit_siem_event(
                action="blocked",
                severity="high",
                reason=reason,
                client_ip=client_ip,
                client_port=client_port,
                trans_id=trans_id,
                unit_id=unit_id,
                fc=fc,
                mitre_technique_id="T0855",
                mitre_technique_name="Unauthorized Command Message",
                payload_details={"target_address": addr, "target_value": val}
            )
            return False, exc_resp, reason

        # ----------------------------------------------------------------------
        # TIER 2: Semantic Process Boundary Inspection
        # ----------------------------------------------------------------------
        if fc == 6 and len(raw_pkt) >= 12:
            reg_addr = int.from_bytes(raw_pkt[8:10], "big")
            reg_val = int.from_bytes(raw_pkt[10:12], "big")

            if reg_addr == 0 and reg_val > self.max_safe_high_threshold:
                self.stats["blocked"] += 1
                reason = (
                    f"CRITICAL PROCESS HAZARD: High Setpoint {reg_val} exceeds safe capacity "
                    f"({self.max_safe_high_threshold}). Potential loss-of-containment attack."
                )
                exc_resp = self.generate_exception_response(trans_id, unit_id, fc, EXC_ILLEGAL_DATA_VALUE)

                self.emit_siem_event(
                    action="blocked",
                    severity="critical",
                    reason=reason,
                    client_ip=client_ip,
                    client_port=client_port,
                    trans_id=trans_id,
                    unit_id=unit_id,
                    fc=fc,
                    mitre_technique_id="T0836",
                    mitre_technique_name="Modify Parameter",
                    payload_details={"target_register": reg_addr, "attempted_value": reg_val, "safe_limit": self.max_safe_high_threshold}
                )
                return False, exc_resp, reason

        # Allowed Operation
        self.stats["allowed"] += 1
        addr = int.from_bytes(raw_pkt[8:10], "big") if len(raw_pkt) >= 10 else 0
        qty = int.from_bytes(raw_pkt[10:12], "big") if len(raw_pkt) >= 12 else 0
        self.emit_siem_event(
            action="allowed",
            severity="informational",
            reason=f"Legitimate {FC_NAMES.get(fc, 'Command')}",
            client_ip=client_ip,
            client_port=client_port,
            trans_id=trans_id,
            unit_id=unit_id,
            fc=fc,
            payload_details={"address": addr, "count_or_val": qty}
        )
        return True, None, "ALLOW"

    def handle_client_session(self, client_sock: socket.socket, client_addr: Tuple[str, int]):
        client_ip, client_port = client_addr
        try:
            backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_sock.settimeout(3.0)
            backend_sock.connect((self.backend_host, self.backend_port))
        except Exception as e:
            logger.error(f"Cannot reach OpenPLC ({self.backend_host}:{self.backend_port}): {e}")
            client_sock.close()
            return

        sockets = [client_sock, backend_sock]
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 10.0)
                if exceptional:
                    break
                if not readable:
                    continue

                for sock in readable:
                    data = sock.recv(4096)
                    if not data:
                        return

                    if sock is client_sock:
                        is_allowed, synthetic_resp, reason = self.inspect_request(data, client_ip, client_port)
                        if is_allowed:
                            backend_sock.sendall(data)
                        else:
                            logger.warning(f"[BLOCKED] Packet dropped! Reason: {reason}")
                            if synthetic_resp:
                                client_sock.sendall(synthetic_resp)
                    else:
                        client_sock.sendall(data)
        finally:
            client_sock.close()
            backend_sock.close()

    def start_proxy(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.listen_host, self.listen_port))
        server.listen(10)
        logger.info("=" * 70)
        logger.info(f"Modbus L7 DPI Proxy ACTIVE on {self.listen_host}:{self.listen_port}")
        logger.info(f"SIEM Structured Logging: {os.path.abspath(self.log_file)}")
        logger.info("=" * 70)

        try:
            while True:
                client_sock, client_addr = server.accept()
                self.handle_client_session(client_sock, client_addr)
        finally:
            server.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modbus Layer-7 DPI Gateway Proxy with SIEM Logging")
    parser.add_argument("--listen-port", type=int, default=5020)
    parser.add_argument("--backend-port", type=int, default=502)
    parser.add_argument("--authorized-ip", type=str, default="192.168.1.50")
    parser.add_argument("--log-file", type=str, default="logs/ot_security_events.jsonl")
    args = parser.parse_args()

    proxy = ModbusDPIProxy(
        listen_port=args.listen_port,
        backend_port=args.backend_port,
        authorized_ews_ip=args.authorized_ip,
        log_file=args.log_file
    )
    proxy.start_proxy()
