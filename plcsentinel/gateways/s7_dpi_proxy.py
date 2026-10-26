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

import asyncio
import logging
import argparse
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any

from plcsentinel.core.dpi_stream import StreamDPIProxy, COMMON_POLICY_KEYS, load_policy_file, add_common_arguments, common_kwargs

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
    **COMMON_POLICY_KEYS,
    "open_functions": list,
    "open_userdata": list,
    "change_windows": list,
    "protected_db_words": list,
}


def _parse_window(w: Any) -> Dict[str, Any]:
    """One change window: ISO-8601 start/end with timezone, the principal it is
    for, and a different principal who approved it (two-person rule)."""
    try:
        start, end = datetime.fromisoformat(w["start"]), datetime.fromisoformat(w["end"])
        principal, approver = str(w["principal"]), str(w["approved_by"])
    except (KeyError, TypeError, ValueError) as e:
        raise SystemExit(f"[FATAL] change window {w!r}: needs start, end (ISO-8601 with timezone), principal, approved_by ({e})")
    if start.tzinfo is None or end.tzinfo is None or end <= start:
        raise SystemExit(f"[FATAL] change window {w!r}: start/end must carry a timezone and end must be after start")
    if approver == principal:
        raise SystemExit(f"[FATAL] change window {w!r}: approved_by must differ from principal (two-person rule)")
    return {"start": start, "end": end, "principal": principal, "approved_by": approver}


def _convert_policy(policy: Dict[str, Any]) -> None:
    if "open_functions" in policy:
        policy["open_functions"] = [int(v) for v in policy["open_functions"]]
    if "open_userdata" in policy:
        policy["open_userdata"] = {(int(g), int(s)) for g, s in policy["open_userdata"]}
    if "change_windows" in policy:
        policy["change_windows"] = [_parse_window(w) for w in policy["change_windows"]]
    if "protected_db_words" in policy:
        policy["protected_db_words"] = [
            {"db": int(w["db"]), "offset": int(w["offset"]), "min": int(w.get("min", 0)), "max": int(w["max"])}
            for w in policy["protected_db_words"]]


def load_policy(path: str) -> Dict[str, Any]:
    return load_policy_file(path, POLICY_KEYS, _convert_policy,
                            "open_functions must be integers, open_userdata [group, subfunction] pairs, "
                            "protected_db_words objects with db, offset, max (and optional min)")


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

                # Data section, one entry per item: reserved, transport size,
                # length (bits for sizes 3..6, bytes otherwise), payload, even padding.
                d = s7_offset + 10 + param_len
                for item in dissection["write_items"]:
                    if len(raw) < d + 4:
                        return None
                    transport, length = raw[d + 1], int.from_bytes(raw[d + 2:d + 4], "big")
                    nbytes = (length + 7) // 8 if transport in (3, 4, 5, 6) else length
                    if len(raw) < d + 4 + nbytes:
                        return None
                    item["data"] = raw[d + 4:d + 4 + nbytes]
                    d += 4 + nbytes + (nbytes & 1)
        elif msg_type == 0x07 and param_len >= 8 and len(raw) >= s7_offset + 17:
            # UserData parameter: 00 01 12 | len | method | type<<4 | group | subfunction | seq
            group, subfunction = raw[s7_offset + 15] & 0x0F, raw[s7_offset + 16]
            dissection["userdata"] = (group, subfunction)
            dissection["function_name"] = f"UserData group {group} subfunction {subfunction}"

        return dissection


class S7DPIProxy(StreamDPIProxy):
    """
    Inline Asynchronous S7comm Deep Packet Inspection Gateway.
    """
    DATASET = "ics.s7comm"
    PROTOCOL = "s7comm"
    DETAILS_KEY = "s7comm"
    NAME = "S7comm"
    APPLICATION = "siemens_simatic"

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
        change_windows=None,
        protected_db_words=(),
        log_file: str = "logs/s7_security_events.jsonl",
        **common
    ):
        super().__init__(listen_host, listen_port, backend_host, backend_port,
                         authorized_ews_ips, authorized_ews_identities, log_file, **common)
        self.open_fcs = frozenset(open_fcs)
        self.open_userdata = frozenset(tuple(x) for x in open_userdata)
        # None: logic transfers by the EWS are only logged. A list (even empty):
        # they are refused unless a window for that principal is open now.
        self.change_windows = None if change_windows is None else list(change_windows)
        # Signed 16-bit DB words that may not leave [min, max], whoever writes them.
        self.protected_db_words = [dict(w) for w in protected_db_words]

    def _banner_lines(self):
        return [
            f"Open to every host                : jobs {sorted(f'0x{x:02X}' for x in self.open_fcs)}, userdata {sorted(self.open_userdata)}",
            f"Protected DB words                : {self.protected_db_words or 'none'}",
            f"Change windows                    : {'not enforced (logic transfers logged only)' if self.change_windows is None else f'{len(self.change_windows)} declared, two-person rule'}",
        ]

    def _check_db_word_hazard(self, items) -> Optional[Tuple[Dict[str, int], int]]:
        """Return (rule, value) for the first protected DB word a write would push out of range."""
        for item in items:
            data = item.get("data")
            if item.get("area_code") != 0x84 or data is None:
                continue
            for rule in self.protected_db_words:
                rel = rule["offset"] - item["byte_offset"]
                if rule["db"] == item["db_number"] and 0 <= rel and rel + 2 <= len(data):
                    value = int.from_bytes(data[rel:rel + 2], "big", signed=True)
                    if not (rule["min"] <= value <= rule["max"]):
                        return rule, value
        return None

    def _window_open(self, principal: str, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return any(w["principal"] == principal and w["start"] <= now <= w["end"] for w in self.change_windows)

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
                details={"function_code": fc, "function_name": fc_name},
                principal=principal
            )
            return False, reason

        # ----------------------------------------------------------------------
        # POLICY RULE 1b: SETPOINT BOUNDS (MITRE T0836), for every principal.
        # A protected DB word may not leave its safe range, whoever writes it.
        # ----------------------------------------------------------------------
        if fc == S7_FC_WRITE_VAR:
            hazard = self._check_db_word_hazard(parsed.get("write_items", []))
            if hazard is not None:
                rule, value = hazard
                self.stats["blocked"] += 1
                reason = (f"CRITICAL PROCESS HAZARD: DB{rule['db']}.DBW{rule['offset']} = {value} is outside the safe range "
                          f"[{rule['min']} .. {rule['max']}] (requested by {principal})")
                self.log_ecs_event(
                    action=self._deny_action(), severity="critical", reason=reason, client_ip=client_ip, client_port=client_port,
                    mitre_id="T0836", mitre_name="Modify Parameter",
                    details={"function_code": fc, "function_name": fc_name, "target": rule, "attempted_value": value},
                    principal=principal
                )
                return False, reason

        # The authorized Engineering Workstation may issue anything but CPU Stop.
        # Logic transfers and run-mode changes additionally need an open change
        # window approved by someone else, when the policy declares windows.
        if principal in self.authorized_principals:
            if fc in EWS_ONLY_FCS and self.change_windows is not None and not self._window_open(principal):
                mitre_id, mitre_name = EWS_ONLY_FCS[fc]
                self.stats["blocked"] += 1
                reason = f"POLICY VIOLATION: {fc_name} by {principal} outside an approved change window!"
                self.log_ecs_event(
                    action=self._deny_action(), severity="critical", reason=reason, client_ip=client_ip, client_port=client_port,
                    mitre_id=mitre_id, mitre_name=mitre_name,
                    details={"function_code": fc, "function_name": fc_name, "declared_windows": len(self.change_windows)},
                    principal=principal
                )
                return False, reason
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
                details={"function_code": fc, "function_name": fc_name},
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
                details={"function_code": fc, "function_name": fc_name, "target_item": item},
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
            details={"function_code": fc, "function_name": fc_name, "msg_type": parsed.get("msg_type")},
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S7comm Layer-7 DPI Conduit Gateway")
    add_common_arguments(parser, listen_port=10200, backend_port=1102, log_file="logs/s7_security_events.jsonl",
                         policy_example="s7_policy.json",
                         tls_port_hint="Also listen for mutual-TLS sessions (ews_tls_tunnel.py) on this port, e.g. 10202; client certificate CN is the principal")
    args = parser.parse_args()

    policy = load_policy(args.policy) if args.policy else {}
    proxy = S7DPIProxy(
        open_fcs=policy.get("open_functions", OPEN_FCS),
        open_userdata=policy.get("open_userdata", OPEN_USERDATA),
        change_windows=policy.get("change_windows"),
        protected_db_words=policy.get("protected_db_words", []),
        **common_kwargs(args, policy)
    )
    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        logger.info("S7comm DPI Proxy shutting down.")
