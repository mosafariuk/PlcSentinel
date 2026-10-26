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
  4. Restricts program upload (0x1D-0x1F) and PLC start/restart (0x28) to the authorized EWS (MITRE ATT&CK T0845 / T0858).
  5. Emits real-time Elastic Common Schema (ECS) JSON security telemetry.
"""

import os
import sys
import json
import ssl
import socket
import asyncio
import logging
import argparse
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any

from dpi_limits import SourceLimiter
from dpi_tls import server_context, peer_principal

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

# Functions that only the authorized Engineering Workstation may issue.
EWS_ONLY_FCS = {
    S7_FC_REQUEST_DOWNLOAD: ("T0843", "Program Download / Logic Modification"),
    S7_FC_DOWNLOAD_BLOCK: ("T0843", "Program Download / Logic Modification"),
    S7_FC_DOWNLOAD_ENDED: ("T0843", "Program Download / Logic Modification"),
    S7_FC_START_UPLOAD: ("T0845", "Program Upload / Logic Exfiltration"),
    S7_FC_UPLOAD: ("T0845", "Program Upload / Logic Exfiltration"),
    S7_FC_END_UPLOAD: ("T0845", "Program Upload / Logic Exfiltration"),
    S7_FC_PLC_CONTROL: ("T0858", "Change Operating Mode (PLC Start/Restart)"),
}

# Functions every host may issue: telemetry reads and the PDU negotiation that
# precedes them. Every other Job function is EWS-only.
OPEN_FCS = frozenset({S7_FC_READ_VAR, S7_FC_SETUP_COMM})
# UserData (message type 7) requests every host may issue, as (group, subfunction):
# group 4 "CPU functions", subfunction 1 "Read SZL" (status / identification).
OPEN_USERDATA = frozenset({(4, 1)})

# JSON policy file keys and their types; CLI flags override file values.
POLICY_KEYS = {
    "authorized_ews_ips": list,
    "authorized_ews_identities": list,
    "open_functions": list,
    "open_userdata": list,
    "max_sessions_per_source": int,
    "max_requests_per_second": int,
    "enforce": bool,
}


def load_policy(path: str) -> Dict[str, Any]:
    """Read and validate a JSON policy file. Any problem is fatal at startup:
    a gateway must never run on a policy it only half understood."""
    try:
        with open(path, encoding="utf-8") as f:
            policy = json.load(f)
    except (OSError, ValueError) as e:
        raise SystemExit(f"[FATAL] Cannot read policy file {path}: {e}")
    if not isinstance(policy, dict) or set(policy) - set(POLICY_KEYS):
        raise SystemExit(f"[FATAL] Policy file {path}: expected an object with keys {sorted(POLICY_KEYS)}")
    for key, typ in POLICY_KEYS.items():
        if key in policy and (not isinstance(policy[key], typ) or (typ is int and isinstance(policy[key], bool))):
            raise SystemExit(f"[FATAL] Policy file {path}: {key!r} must be a JSON {typ.__name__}")
    try:
        if "open_functions" in policy:
            policy["open_functions"] = [int(v) for v in policy["open_functions"]]
        if "open_userdata" in policy:
            policy["open_userdata"] = {(int(g), int(s)) for g, s in policy["open_userdata"]}
    except (TypeError, ValueError) as e:
        raise SystemExit(f"[FATAL] Policy file {path}: open_functions must be integers and open_userdata [group, subfunction] pairs ({e})")
    return policy

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
                    # S7ANY Addressing Item Structure (12 bytes)
                    # [0]: Spec Type (0x12), [1]: Length (0x0A), [2]: Syntax ID (0x10)
                    # [4..5]: Count/Length, [6..7]: DB Number, [8]: Area Code, [9..11]: 3-Byte Address
                    # Truncated or non-S7ANY items are unparseable -> fail closed
                    # (a different item length would desync the fixed 12-byte stride).
                    if len(raw) < item_offset + 12 or raw[item_offset:item_offset + 3] != b"\x12\x0a\x10":
                        return None
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
        elif msg_type == 0x07 and param_len >= 8 and len(raw) >= s7_offset + 17:
            # UserData parameter: 00 01 12 | len | method | type<<4 | group | subfunction | seq
            group, subfunction = raw[s7_offset + 15] & 0x0F, raw[s7_offset + 16]
            dissection["userdata"] = (group, subfunction)
            dissection["function_name"] = f"UserData group {group} subfunction {subfunction}"

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
        authorized_ews_ips=("192.168.1.50",),
        authorized_ews_identities=(),
        open_fcs=OPEN_FCS,
        open_userdata=OPEN_USERDATA,
        log_file: str = "logs/s7_security_events.jsonl",
        enforce: bool = True,
        max_sessions_per_source: int = 8,
        max_requests_per_second: int = 200,
        siem_udp: Optional[Tuple[str, int]] = None,
        tls_port: Optional[int] = None,
        tls_cert: str = "certs/gateway_cert.pem",
        tls_key: str = "certs/gateway_key.pem",
        tls_ca: str = "certs/gateway_ca_cert.pem"
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        # A principal is a source IP (plain listener) or "cn:<CommonName>" of a
        # client certificate issued by the lab CA (mutual-TLS listener).
        self.authorized_principals = frozenset(authorized_ews_ips) | frozenset(f"cn:{c}" for c in authorized_ews_identities)
        self.open_fcs = frozenset(open_fcs)
        self.open_userdata = frozenset(tuple(x) for x in open_userdata)
        self.log_file = log_file
        # Monitor mode: violations are inspected and logged but forwarded.
        self.enforce = enforce
        self.limiter = SourceLimiter(max_sessions_per_source, max_requests_per_second)
        self._siem_udp = siem_udp
        self._siem_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if siem_udp else None
        self.tls_port = tls_port
        try:
            self._tls_ctx = server_context(tls_cert, tls_key, tls_ca) if tls_port is not None else None
        except (OSError, ssl.SSLError) as e:
            raise SystemExit(f"[FATAL] Cannot load TLS material for the mutual-TLS listener: {e}")

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
        s7_details: Optional[Dict[str, Any]] = None,
        principal: Optional[str] = None
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
        if principal and principal.startswith("cn:"):
            event["user"] = {"name": principal[3:]}
        line = json.dumps(event) + "\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(line)
        if self._siem_sock:
            try:
                self._siem_sock.sendto(line.encode("utf-8"), self._siem_udp)
            except OSError as e:
                logger.warning(f"SIEM UDP forward to {self._siem_udp} failed: {e}")

    def _deny_action(self) -> str:
        return "blocked" if self.enforce else "detected"

    def _emit_limit_event(self, client_ip: str, client_port: int, reason: str):
        """Resource caps protect the gateway and controller, so they apply in both modes."""
        logger.warning(f"[BLOCKED] {reason}")
        self.log_ecs_event(
            action="blocked", severity="high", reason=reason, client_ip=client_ip, client_port=client_port,
            mitre_id="T0814", mitre_name="Denial of Service",
            s7_details={"max_sessions": self.limiter.max_sessions, "max_requests_per_second": self.limiter.max_rps}
        )

    def evaluate_policy(self, parsed: Dict[str, Any], client_ip: str, client_port: int,
                        principal: Optional[str] = None) -> Tuple[bool, str]:
        """
        Layer-7 Policy Evaluation for a single, fully-framed S7comm PDU.
        Returns: (is_allowed: bool, reason: str)
        """
        principal = principal or client_ip
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
                action=self._deny_action(),
                severity="critical",
                reason=reason,
                client_ip=client_ip,
                client_port=client_port,
                mitre_id="T0805",
                mitre_name="Point & Physical Device Control / CPU Stop",
                s7_details={"function_code": fc, "function_name": fc_name},
                principal=principal
            )
            return False, reason

        # The authorized Engineering Workstation may issue anything but CPU Stop.
        if principal in self.authorized_principals:
            self.stats["allowed"] += 1
            return True, "ALLOW"

        # ----------------------------------------------------------------------
        # POLICY RULE 2: EWS-ONLY FUNCTIONS (MITRE T0843 / T0845 / T0858)
        # Logic download (Stuxnet-style), logic upload (exfiltration) and
        # run-mode changes are restricted to the authorized Engineering Workstation.
        # ----------------------------------------------------------------------
        if fc in EWS_ONLY_FCS:
            mitre_id, mitre_name = EWS_ONLY_FCS[fc]
            self.stats["blocked"] += 1
            reason = f"CRITICAL ATTACK: Unauthorized S7comm {fc_name} from unauthorized principal {principal}!"
            self.log_ecs_event(
                action=self._deny_action(),
                severity="critical",
                reason=reason,
                client_ip=client_ip,
                client_port=client_port,
                mitre_id=mitre_id,
                mitre_name=mitre_name,
                s7_details={"function_code": fc, "function_name": fc_name},
                principal=principal
            )
            return False, reason

        # ----------------------------------------------------------------------
        # POLICY RULE 3: WRITE CONTROL (MITRE T0855 / T0836)
        # Default-deny: every Write Var (any DB, outputs, markers, timers,
        # counters) requires the authorized EWS identity. Reads stay open.
        # ----------------------------------------------------------------------
        if fc == S7_FC_WRITE_VAR:
            item = (parsed.get("write_items") or [{}])[0]
            self.stats["blocked"] += 1
            reason = (
                f"POLICY VIOLATION: Unauthorized S7comm Write targeting {item.get('area_name', 'unknown area')} "
                f"(DB{item.get('db_number')}.DBB{item.get('byte_offset')}) from unauthorized principal {principal}!"
            )
            self.log_ecs_event(
                action=self._deny_action(),
                severity="high",
                reason=reason,
                client_ip=client_ip,
                client_port=client_port,
                mitre_id="T0855",
                mitre_name="Unauthorized Command Message",
                s7_details={"function_code": fc, "function_name": fc_name, "target_item": item},
                principal=principal
            )
            return False, reason

        # ----------------------------------------------------------------------
        # POLICY RULE 4: READ ALLOWLIST
        # Only Read Var, Setup Communication and SZL status reads are open to
        # non-EWS hosts; unknown Job functions and other UserData are denied.
        # ----------------------------------------------------------------------
        if fc in self.open_fcs or parsed.get("userdata") in self.open_userdata:
            self.stats["allowed"] += 1
            return True, "ALLOW"

        self.stats["blocked"] += 1
        reason = (
            f"POLICY VIOLATION: S7comm {fc_name or parsed.get('msg_type_name')} is not a read operation; "
            f"denied for unauthorized principal {principal}!"
        )
        self.log_ecs_event(
            action=self._deny_action(),
            severity="high",
            reason=reason,
            client_ip=client_ip,
            client_port=client_port,
            mitre_id="T0855",
            mitre_name="Unauthorized Command Message",
            s7_details={"function_code": fc, "function_name": fc_name, "msg_type": parsed.get("msg_type")},
            principal=principal
        )
        return False, reason

    def _frame_client_stream(self, buf: bytes, client_ip: str, client_port: int,
                             principal: Optional[str] = None) -> Tuple[bytes, bytes, Optional[str]]:
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
            if not self.limiter.allow_request(client_ip):
                self._emit_limit_event(client_ip, client_port,
                                       f"Request rate cap: over {self.limiter.max_rps} frames/s from {client_ip}; dropping session")
                return out, buf, "Request rate cap exceeded"

            parsed = S7PacketParser.dissect(msg)
            if parsed is None:
                # A complete TPKT frame we cannot parse -> fail closed.
                return out, buf, "Unparseable complete S7/COTP frame"
            if not parsed.get("is_s7comm"):
                # COTP handshake / non-S7 control frame -> allow ISO connection setup.
                out += msg
                continue

            allowed, reason = self.evaluate_policy(parsed, client_ip, client_port, principal)
            if not allowed and self.enforce:
                return out, buf, reason
            if not allowed:
                logger.warning(f"[MONITOR] Would block, forwarding anyway. Reason: {reason}")
            out += msg
        return out, buf, None

    async def pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_client: bool,
                   client_ip: str, client_port: int, principal: Optional[str] = None):
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
                out, buf, drop_reason = self._frame_client_stream(buf, client_ip, client_port, principal)
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
        principal = None
        ssl_object = client_writer.get_extra_info("ssl_object")
        if ssl_object is not None:
            principal = peer_principal(ssl_object.getpeercert())
            if principal is None:
                logger.warning(f"[BLOCKED] TLS client {client_ip}:{client_port} presented a certificate without a Common Name")
                client_writer.close()
                await client_writer.wait_closed()
                return
        logger.info(f"[+] Incoming S7 session accepted from {client_ip}:{client_port}" + (f" as {principal}" if principal else ""))
        if not self.limiter.open_session(client_ip):
            self._emit_limit_event(client_ip, client_port,
                                   f"Session cap: {self.limiter.max_sessions} sessions already open from {client_ip}; refusing another")
            client_writer.close()
            await client_writer.wait_closed()
            return
        try:
            await self._serve_session(client_reader, client_writer, client_ip, client_port, principal)
        finally:
            self.limiter.close_session(client_ip)

    async def _serve_session(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                             client_ip: str, client_port: int, principal: Optional[str] = None):
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
            self.pipe(client_reader, plc_writer, is_client=True, client_ip=client_ip, client_port=client_port, principal=principal)
        )
        plc_to_client = asyncio.create_task(
            self.pipe(plc_reader, client_writer, is_client=False, client_ip=client_ip, client_port=client_port)
        )

        await asyncio.gather(client_to_plc, plc_to_client, return_exceptions=True)
        logger.info(f"[*] S7 session closed for {client_ip}:{client_port} | Total Stats: {self.stats}")

    async def start(self):
        servers = [await asyncio.start_server(self.handle_client, self.listen_host, self.listen_port)]
        if self._tls_ctx:
            servers.append(await asyncio.start_server(self.handle_client, self.listen_host, self.tls_port, ssl=self._tls_ctx))
        logger.info("=" * 72)
        logger.info(f"S7comm Layer-7 DPI Proxy ACTIVE on {self.listen_host}:{self.listen_port}")
        if self._tls_ctx:
            logger.info(f"Mutual-TLS listener (reach it with ews_tls_tunnel.py) on {self.listen_host}:{self.tls_port}")
        logger.info(f"Forwarding sanitized traffic to Siemens PLC at {self.backend_host}:{self.backend_port}")
        logger.info(f"Authorized principals             : {sorted(self.authorized_principals)}")
        logger.info(f"Open to every host                : jobs {sorted(f'0x{x:02X}' for x in self.open_fcs)}, userdata {sorted(self.open_userdata)}")
        logger.info(f"SIEM Structured Logging           : {os.path.abspath(self.log_file)}")
        logger.info(f"Mode                              : {'ENFORCE' if self.enforce else 'MONITOR (violations logged as detected, traffic forwarded)'}")
        logger.info("=" * 72)

        try:
            await asyncio.gather(*(s.serve_forever() for s in servers))
        finally:
            for s in servers:
                s.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S7comm Layer-7 DPI Conduit Gateway")
    parser.add_argument("--listen-host", type=str, default="0.0.0.0", help="DPI Proxy listen IP (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=10200, help="DPI Proxy listen port (default: 10200)")
    parser.add_argument("--backend-host", type=str, default="127.0.0.1", help="Backend PLC IP (default: 127.0.0.1)")
    parser.add_argument("--backend-port", type=int, default=1102, help="Backend PLC port (default: 1102 or 102)")
    parser.add_argument("--policy", type=str, help="JSON policy file (see s7_policy.json); explicit CLI flags override it")
    parser.add_argument("--authorized-ews", action="append", default=None, help="Authorized EWS IP; repeatable (default: 192.168.1.50)")
    parser.add_argument("--log-file", type=str, default="logs/s7_security_events.jsonl", help="SIEM event output path")
    parser.add_argument("--monitor", action="store_true", help="Log policy violations but forward all traffic (observe inline before enforcing)")
    parser.add_argument("--siem-udp", type=str, metavar="HOST:PORT", help="Also send every event as a JSON datagram to this collector (Elastic/Logstash/Wazuh)")
    parser.add_argument("--tls-port", type=int, default=None, help="Also listen for mutual-TLS sessions (ews_tls_tunnel.py) on this port, e.g. 10202; client certificate CN is the principal")
    parser.add_argument("--tls-cert", type=str, default="certs/gateway_cert.pem", help="Gateway certificate (PEM)")
    parser.add_argument("--tls-key", type=str, default="certs/gateway_key.pem", help="Gateway private key (PEM)")
    parser.add_argument("--tls-ca", type=str, default="certs/gateway_ca_cert.pem", help="CA that issues client certificates (PEM)")
    args = parser.parse_args()

    policy = load_policy(args.policy) if args.policy else {}
    siem_udp = None
    if args.siem_udp:
        host, _, port = args.siem_udp.rpartition(":")
        siem_udp = (host, int(port))
    proxy = S7DPIProxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        backend_host=args.backend_host,
        backend_port=args.backend_port,
        authorized_ews_ips=args.authorized_ews or policy.get("authorized_ews_ips", ["192.168.1.50"]),
        authorized_ews_identities=policy.get("authorized_ews_identities", []),
        open_fcs=policy.get("open_functions", OPEN_FCS),
        open_userdata=policy.get("open_userdata", OPEN_USERDATA),
        log_file=args.log_file,
        enforce=policy.get("enforce", True) and not args.monitor,
        max_sessions_per_source=policy.get("max_sessions_per_source", 8),
        max_requests_per_second=policy.get("max_requests_per_second", 200),
        siem_udp=siem_udp,
        tls_port=args.tls_port,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        tls_ca=args.tls_ca
    )
    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        logger.info("S7comm DPI Proxy shutting down.")
