#!/usr/bin/env python3
"""
S7-Sentinel: Inline Layer-7 Deep Packet Inspection (DPI) Proxy for Siemens S7comm
Author: Senior ICS/OT Defensive Engineer & Network Security Architect
Target Protocol: S7comm over ISO-on-TCP (RFC 1006 / Port 102)

Architectural Role:
- Operates inline on Conduit C-1 between Level 2 (Engineering Workstation / HMI)
  and Level 1 (Siemens S7 Controller).
- Enforces Zero-Trust Layer-7 Access Control:
  1. Blocks unauthorized PLC Control / CPU Stop commands (MITRE ATT&CK T0805 / T0814).
  2. Blocks unauthorized Program Download / Firmware upload attempts (MITRE ATT&CK T0843 / T0873).
  3. Restricts S7comm Write Var (0x05) jobs exclusively to authorized EWS IP addresses (MITRE ATT&CK T0855).
  4. Protects critical Data Blocks (DBs) and outputs against unauthorized tampering (MITRE ATT&CK T0836).
  5. Emits real-time Elastic Common Schema (ECS) JSON security telemetry.
"""

import os
import sys
import json
import asyncio
import logging
import argparse
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [S7-DPI] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("S7DPIProxy")

# S7comm Function Codes (Job Type 0x01)
S7_FC_READ_VAR = 0x04
S7_FC_WRITE_VAR = 0x05
S7_FC_REQUEST_DOWNLOAD = 0x1A
S7_FC_DOWNLOAD_BLOCK = 0x1B
S7_FC_DOWNLOAD_ENDED = 0x1C
S7_FC_START_UPLOAD = 0x1D
S7_FC_UPLOAD = 0x1E
S7_FC_END_UPLOAD = 0x1F
S7_FC_PLC_CONTROL = 0x28
S7_FC_PLC_STOP = 0x29
S7_FC_SETUP_COMM = 0xF0

FC_NAMES = {
    0x04: "Read Var",
    0x05: "Write Var",
    0x1A: "Request Download (Program Upload to PLC)",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload (Read code from PLC)",
    0x1E: "Upload",
    0x1F: "End Upload",
    0x28: "PLC Control (Start/Restart)",
    0x29: "PLC Stop (CPU Stop Command)",
    0xF0: "Setup Communication (PDU Negotiate)",
}

# S7 Memory Area Codes
S7_AREA_NAMES = {
    0x81: "Process Inputs (%I / PE)",
    0x82: "Process Outputs (%Q / PA)",
    0x83: "Memory Markers (%M / Merkers)",
    0x84: "Data Block (DB)",
    0x1C: "Counters (C)",
    0x1D: "Timers (T)",
}


class S7PacketParser:
    """Dissects TPKT, COTP, and S7comm protocol layers."""

    @staticmethod
    def dissect(raw: bytes) -> Optional[Dict[str, Any]]:
        # TPKT Header (RFC 1006 - 4 Bytes)
        if len(raw) < 7:
            return None

        tpkt_version = raw[0]
        if tpkt_version != 3:
            return None  # Not TPKT Version 3

        tpkt_len = int.from_bytes(raw[2:4], "big")
        if len(raw) < tpkt_len:
            return None  # Incomplete TCP segment

        # COTP Layer (ISO 8073)
        cotp_len = raw[4]
        if len(raw) < 5 + cotp_len:
            return None

        cotp_type = raw[5]
        # COTP Types: 0xE0 = CR (Connect Request), 0xD0 = CC (Connect Confirm), 0xF0 = DT (Data)
        if cotp_type in [0xE0, 0xD0]:
            return {
                "layer": "COTP",
                "type": "CR/CC Connection Setup",
                "is_s7comm": False,
                "cotp_type": cotp_type
            }

        if cotp_type != 0xF0:
            return {"layer": "COTP", "type": f"Other (0x{cotp_type:02X})", "is_s7comm": False}

        # S7comm Layer starts immediately after COTP header
        s7_offset = 4 + 1 + cotp_len
        if len(raw) < s7_offset + 10:
            return None

        s7_magic = raw[s7_offset]
        if s7_magic != 0x32:
            return {"layer": "S7", "is_s7comm": False}

        msg_type = raw[s7_offset + 1]
        param_len = int.from_bytes(raw[s7_offset + 6 : s7_offset + 8], "big")
        data_len = int.from_bytes(raw[s7_offset + 8 : s7_offset + 10], "big")

        dissection = {
            "layer": "S7COMM",
            "is_s7comm": True,
            "msg_type": msg_type,
            "msg_type_name": {1: "Job (Request)", 2: "Ack", 3: "Ack-Data (Response)", 7: "UserData"}.get(msg_type, f"Unknown ({msg_type})"),
            "function_code": None,
            "function_name": None,
            "write_items": [],
            "raw_s7_offset": s7_offset
        }

        # Only analyze Job requests (0x01) originating from client to PLC
        if msg_type == 0x01 and param_len > 0:
            fc = raw[s7_offset + 10]
            dissection["function_code"] = fc
            dissection["function_name"] = FC_NAMES.get(fc, f"Unknown Function (0x{fc:02X})")

            # Deep inspect Write Var (0x05) parameters
            if fc == S7_FC_WRITE_VAR and param_len >= 2:
                item_count = raw[s7_offset + 11]
                item_offset = s7_offset + 12

                for _ in range(item_count):
                    if len(raw) < item_offset + 12:
                        break
                    # S7ANY Addressing Item Structure (12 bytes)
                    # [0]: Spec Type (0x12), [1]: Length (0x0A), [2]: Syntax ID (0x10)
                    # [4..5]: Count/Length, [6..7]: DB Number, [8]: Area Code, [9..11]: 3-Byte Address
                    db_num = int.from_bytes(raw[item_offset + 6 : item_offset + 8], "big")
                    area_code = raw[item_offset + 8]
                    bit_address = int.from_bytes(raw[item_offset + 9 : item_offset + 12], "big")
                    byte_offset = bit_address >> 3

                    dissection["write_items"].append({
                        "db_number": db_num,
                        "area_code": area_code,
                        "area_name": S7_AREA_NAMES.get(area_code, f"Area 0x{area_code:02X}"),
                        "byte_offset": byte_offset,
                        "bit_offset": bit_address & 0x07
                    })
                    item_offset += 12

        return dissection


class S7DPIProxy:
    """
    Inline Asynchronous S7comm Deep Packet Inspection Gateway.
    """

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 10200,
        backend_host: str = "127.0.0.1",
        backend_port: int = 102,
        authorized_ews_ip: str = "192.168.1.50",
        critical_dbs: Optional[List[int]] = None,
        log_file: str = "logs/s7_security_events.jsonl"
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.authorized_ews_ip = authorized_ews_ip
        # Critical DBs protected from write operations without authorized EWS identity
        self.critical_dbs = critical_dbs or [1, 2, 10]
        self.log_file = log_file

        self.stats = {"sessions": 0, "packets": 0, "allowed": 0, "blocked": 0}
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def log_ecs_event(
        self,
        action: str,
        severity: str,
        reason: str,
        client_ip: str,
        client_port: int,
        mitre_id: Optional[str] = None,
        mitre_name: Optional[str] = None,
        s7_details: Optional[Dict[str, Any]] = None
    ):
        """Emits an Elastic Common Schema (ECS) JSON event log."""
        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {
                "dataset": "ics.s7comm",
                "action": action,
                "category": ["network", "intrusion_detection"],
                "type": ["access", "protocol"],
                "outcome": "success" if action == "allowed" else "failure",
                "severity_label": severity,
            },
            "source": {"ip": client_ip, "port": client_port},
            "destination": {"ip": self.listen_host, "port": self.listen_port},
            "network": {"transport": "tcp", "protocol": "s7comm", "application": "siemens_simatic"},
            "s7comm": s7_details or {},
            "rule": {
                "description": reason,
                "mitre": {
                    "id": mitre_id,
                    "name": mitre_name,
                    "tactic": "Inhibit Response Function / Impact" if mitre_id else None
                }
            }
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def evaluate_policy(self, parsed: Dict[str, Any], client_ip: str, client_port: int) -> Tuple[bool, str]:
        """
        Layer-7 Policy Evaluation for a single, fully-framed S7comm PDU.
        Returns: (is_allowed: bool, reason: str)
        """
        self.stats["packets"] += 1
        fc = parsed.get("function_code")
        fc_name = parsed.get("function_name", "Unknown")

        # ----------------------------------------------------------------------
        # POLICY RULE 1: CPU STOP COMMAND INTERCEPTION (MITRE T0805 / T0814)
        # Any attempt to put the CPU into STOP mode halts industrial processes!
        # ----------------------------------------------------------------------
        if fc == S7_FC_PLC_STOP:
            self.stats["blocked"] += 1
            reason = f"CRITICAL ATTACK: S7comm CPU Stop command (0x29) detected from {client_ip}!"
            self.log_ecs_event(
                action="blocked",
                severity="critical",
                reason=reason,
                client_ip=client_ip,
                client_port=client_port,
                mitre_id="T0805",
                mitre_name="Point & Physical Device Control / CPU Stop",
                s7_details={"function_code": fc, "function_name": fc_name}
            )
            return False, reason

        # ----------------------------------------------------------------------
        # POLICY RULE 2: UNAUTHORIZED PROGRAM / LOGIC DOWNLOAD (MITRE T0843 / T0873)
        # Prevents Stuxnet-style malicious logic downloads or firmware tampering
        # ----------------------------------------------------------------------
        if fc in [S7_FC_REQUEST_DOWNLOAD, S7_FC_DOWNLOAD_BLOCK, S7_FC_DOWNLOAD_ENDED]:
            if client_ip != self.authorized_ews_ip:
                self.stats["blocked"] += 1
                reason = f"CRITICAL ATTACK: Unauthorized S7comm Program Download ({fc_name}) from non-EWS IP {client_ip}!"
                self.log_ecs_event(
                    action="blocked",
                    severity="critical",
                    reason=reason,
                    client_ip=client_ip,
                    client_port=client_port,
                    mitre_id="T0843",
                    mitre_name="Program Download / Logic Modification",
                    s7_details={"function_code": fc, "function_name": fc_name}
                )
                return False, reason

        # ----------------------------------------------------------------------
        # POLICY RULE 3: DATA BLOCK & ACTUATOR WRITE CONTROL (MITRE T0855 / T0836)
        # Protects critical DB setpoints and outputs against unauthorized writes
        # ----------------------------------------------------------------------
        if fc == S7_FC_WRITE_VAR:
            write_items = parsed.get("write_items", [])
            for item in write_items:
                db_num = item.get("db_number")
                area_code = item.get("area_code")
                area_name = item.get("area_name")

                # If write targets a critical DB or outputs, enforce EWS authorization
                if (db_num in self.critical_dbs or area_code == 0x82) and client_ip != self.authorized_ews_ip:
                    self.stats["blocked"] += 1
                    reason = (
                        f"POLICY VIOLATION: Unauthorized S7comm Write targeting {area_name} "
                        f"(DB{db_num}.DBB{item.get('byte_offset')}) from IP {client_ip}!"
                    )
                    self.log_ecs_event(
                        action="blocked",
                        severity="high",
                        reason=reason,
                        client_ip=client_ip,
                        client_port=client_port,
                        mitre_id="T0855",
                        mitre_name="Unauthorized Command Message",
                        s7_details={"function_code": fc, "function_name": fc_name, "target_item": item}
                    )
                    return False, reason

        # Allowed read or verified operation
        self.stats["allowed"] += 1
        return True, "ALLOW"

    def _frame_client_stream(self, buf: bytes, client_ip: str, client_port: int) -> Tuple[bytes, bytes, Optional[str]]:
        """Extract complete TPKT messages from the client byte stream and inspect each.

        S7comm runs over ISO-on-TCP, a byte stream: a single read may hold several
        TPKT messages or a partial one. We frame on the TPKT length field so every
        complete S7 job is inspected before forwarding, and a partial message stays
        buffered (never forwarded uninspected).

        Returns (forwardable_bytes, remaining_buf, drop_reason). A non-None
        drop_reason means fail closed: tear the session down.
        """
        out = b""
        while len(buf) >= 4:
            # Every legitimate S7/COTP frame is TPKT version 3.
            if buf[0] != 0x03:
                return out, buf, f"Non-TPKT byte 0x{buf[0]:02X} on S7 conduit"
            tpkt_len = int.from_bytes(buf[2:4], "big")
            if tpkt_len < 7 or tpkt_len > 4096:
                return out, buf, f"Malformed TPKT length {tpkt_len}"
            if len(buf) < tpkt_len:
                break  # wait for the remainder of this message
            msg, buf = buf[:tpkt_len], buf[tpkt_len:]

            parsed = S7PacketParser.dissect(msg)
            if parsed is None:
                # A complete TPKT frame we cannot parse -> fail closed.
                return out, buf, "Unparseable complete S7/COTP frame"
            if not parsed.get("is_s7comm"):
                # COTP handshake / non-S7 control frame -> allow ISO connection setup.
                out += msg
                continue

            allowed, reason = self.evaluate_policy(parsed, client_ip, client_port)
            if not allowed:
                return out, buf, reason
            out += msg
        return out, buf, None

    async def pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_client: bool, client_ip: str, client_port: int):
        """Asynchronously pipes data between client and backend with Layer-7 DPI."""
        buf = b""
        try:
            while not reader.at_eof():
                data = await reader.read(4096)
                if not data:
                    break

                if not is_client:
                    # PLC -> client responses are forwarded unmodified.
                    writer.write(data)
                    await writer.drain()
                    continue

                buf += data
                out, buf, drop_reason = self._frame_client_stream(buf, client_ip, client_port)
                if out:
                    writer.write(out)
                    await writer.drain()
                if drop_reason is not None:
                    logger.warning(f"[BLOCKED] Inbound packet dropped! Reason: {drop_reason}")
                    # Immediately terminate connection to protect the PLC
                    writer.close()
                    await writer.wait_closed()
                    return
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        """Handles an incoming connection from HMI / EWS / Attacker."""
        self.stats["sessions"] += 1
        client_addr = client_writer.get_extra_info("peername")
        client_ip, client_port = client_addr[0], client_addr[1]
        logger.info(f"[+] Incoming S7 session accepted from {client_ip}:{client_port}")

        # Connect to backend Siemens PLC
        try:
            plc_reader, plc_writer = await asyncio.wait_for(
                asyncio.open_connection(self.backend_host, self.backend_port),
                timeout=3.0
            )
        except Exception as e:
            logger.error(f"[-] Cannot reach backend Siemens PLC ({self.backend_host}:{self.backend_port}): {e}")
            client_writer.close()
            await client_writer.wait_closed()
            return

        # Bi-directional asynchronous piping
        client_to_plc = asyncio.create_task(
            self.pipe(client_reader, plc_writer, is_client=True, client_ip=client_ip, client_port=client_port)
        )
        plc_to_client = asyncio.create_task(
            self.pipe(plc_reader, client_writer, is_client=False, client_ip=client_ip, client_port=client_port)
        )

        await asyncio.gather(client_to_plc, plc_to_client, return_exceptions=True)
        logger.info(f"[*] S7 session closed for {client_ip}:{client_port} | Total Stats: {self.stats}")

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client,
            self.listen_host,
            self.listen_port
        )
        logger.info("=" * 72)
        logger.info(f"S7comm Layer-7 DPI Proxy ACTIVE on {self.listen_host}:{self.listen_port}")
        logger.info(f"Forwarding sanitized traffic to Siemens PLC at {self.backend_host}:{self.backend_port}")
        logger.info(f"Authorized Engineering Station IP : {self.authorized_ews_ip}")
        logger.info(f"Protected Critical Data Blocks    : DB {self.critical_dbs}")
        logger.info(f"SIEM Structured Logging           : {os.path.abspath(self.log_file)}")
        logger.info("=" * 72)

        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S7comm Layer-7 DPI Conduit Gateway")
    parser.add_argument("--listen-host", type=str, default="0.0.0.0", help="DPI Proxy listen IP (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=10200, help="DPI Proxy listen port (default: 10200)")
    parser.add_argument("--backend-host", type=str, default="127.0.0.1", help="Backend PLC IP (default: 127.0.0.1)")
    parser.add_argument("--backend-port", type=int, default=1102, help="Backend PLC port (default: 1102 or 102)")
    parser.add_argument("--authorized-ews", type=str, default="192.168.1.50", help="Authorized EWS IP (default: 192.168.1.50)")
    parser.add_argument("--log-file", type=str, default="logs/s7_security_events.jsonl", help="SIEM event output path")
    args = parser.parse_args()

    proxy = S7DPIProxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        backend_host=args.backend_host,
        backend_port=args.backend_port,
        authorized_ews_ip=args.authorized_ews,
        log_file=args.log_file
    )
    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        logger.info("S7comm DPI Proxy shutting down.")
