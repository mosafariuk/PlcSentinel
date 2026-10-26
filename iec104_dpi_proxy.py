#!/usr/bin/env python3
"""
PlcSentinel - Inline Layer-7 DPI gateway for IEC 60870-5-104 (telecontrol)

IEC 104 drives substations, grid and pipeline RTUs and has no authentication:
anyone who reaches TCP port 2404 can open breakers, move set-points or reset
an outstation. This is the protocol behind the 2016 Industroyer attack.

The gateway mirrors the Modbus and S7 model on the shared asyncio transport
(dpi_stream.StreamDPIProxy):
  - Monitoring-direction ASDUs and the S/U supervisory frames flow freely.
  - Control-direction commands (process commands 45-51 / 58-64 and system
    commands 100-107) require the authorized engineering identity.
  - Reset-process (C_RP_NA_1, type 105) is refused for everyone, as CPU Stop is
    on the S7 gateway: resetting an outstation over the wire is never routine.
  - Set-point commands (C_SE_NA/NB/NC, types 48/49/50) to a protected object
    address may not leave their safe range, whoever sends them (MITRE T0836).
  - Anything that does not parse cleanly fails closed (session dropped).
"""

import logging
import argparse
from typing import Any, Dict, List, Optional, Tuple

from dpi_stream import (StreamDPIProxy, COMMON_POLICY_KEYS, load_policy_file,
                        add_common_arguments, common_kwargs)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [IEC104-DPI] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("IEC104DPIProxy")

# Control-direction ASDU type identifications (commands that change outstation state).
PROCESS_COMMAND_TYPES = frozenset({45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 61, 62, 63, 64})
SYSTEM_COMMAND_TYPES = frozenset({100, 101, 103, 105, 106})  # interrogation, counter, clock sync, reset, delay
CONTROL_TYPES = PROCESS_COMMAND_TYPES | SYSTEM_COMMAND_TYPES
IEC_RESET_PROCESS = 105
# Set-point command -> (value bytes, signed int or float) excluding the trailing qualifier octet.
SETPOINT_TYPES = {48: ("int", 2), 49: ("int", 2), 50: ("float", 4)}

TYPE_NAMES = {
    45: "C_SC_NA_1 Single command", 46: "C_DC_NA_1 Double command", 47: "C_RC_NA_1 Regulating step",
    48: "C_SE_NA_1 Set-point normalized", 49: "C_SE_NB_1 Set-point scaled", 50: "C_SE_NC_1 Set-point short float",
    51: "C_BO_NA_1 Bitstring 32", 100: "C_IC_NA_1 Interrogation", 101: "C_CI_NA_1 Counter interrogation",
    103: "C_CS_NA_1 Clock sync", 105: "C_RP_NA_1 Reset process", 106: "C_CD_NA_1 Delay acquisition",
}

POLICY_KEYS = {**COMMON_POLICY_KEYS, "protected_setpoints": list}


def _convert_policy(policy: Dict[str, Any]) -> None:
    if "protected_setpoints" in policy:
        policy["protected_setpoints"] = [
            {"ca": int(w["ca"]), "ioa": int(w["ioa"]), "min": float(w.get("min", float("-inf"))), "max": float(w["max"])}
            for w in policy["protected_setpoints"]]


def load_policy(path: str) -> Dict[str, Any]:
    return load_policy_file(path, POLICY_KEYS, _convert_policy,
                            "protected_setpoints must be objects with ca, ioa, max (and optional min)")


class IEC104Parser:
    """Dissects an IEC 60870-5-104 APDU (APCI + optional ASDU header + set-points)."""

    @staticmethod
    def dissect(apdu: bytes) -> Optional[Dict[str, Any]]:
        if len(apdu) < 6 or apdu[0] != 0x68:
            return None
        cf1 = apdu[2]
        if cf1 & 0x01 == 0:
            fmt = "I"
        elif cf1 & 0x03 == 0x01:
            fmt = "S"
        else:
            fmt = "U"
        d: Dict[str, Any] = {"frame_format": fmt, "type_id": None, "cot": None,
                             "common_address": None, "setpoints": []}
        if fmt != "I":
            return d  # supervisory / connection-control frame: no ASDU

        if len(apdu) < 12:
            return None  # I-frame must carry a 6-byte ASDU header
        type_id = apdu[6]
        vsq = apdu[7]
        sq, num = vsq & 0x80, vsq & 0x7F
        d.update(type_id=type_id, type_name=TYPE_NAMES.get(type_id, f"Type {type_id}"),
                 cot=apdu[8] & 0x3F, common_address=int.from_bytes(apdu[10:12], "little"),
                 sq=bool(sq), num_objects=num)

        if type_id in SETPOINT_TYPES and not sq:
            kind, vlen = SETPOINT_TYPES[type_id]
            off = 12
            import struct
            for _ in range(num):
                if off + 3 + vlen + 1 > len(apdu):  # 3-byte IOA + value + 1-byte qualifier
                    return None
                ioa = int.from_bytes(apdu[off:off + 3], "little")
                raw = apdu[off + 3:off + 3 + vlen]
                value = struct.unpack("<f", raw)[0] if kind == "float" else int.from_bytes(raw, "little", signed=True)
                d["setpoints"].append({"ca": d["common_address"], "ioa": ioa, "type_id": type_id, "value": value})
                off += 3 + vlen + 1
        return d


class IEC104DPIProxy(StreamDPIProxy):
    DATASET = "ics.iec104"
    PROTOCOL = "iec104"
    DETAILS_KEY = "iec104"
    NAME = "IEC104"
    APPLICATION = "iec_60870_5_104"

    def __init__(self, listen_host="127.0.0.1", listen_port=2404, backend_host="127.0.0.1", backend_port=2404,
                 authorized_ews_ips=("192.168.1.50",), authorized_ews_identities=(), protected_setpoints=(),
                 log_file="logs/iec104_security_events.jsonl", **common):
        super().__init__(listen_host, listen_port, backend_host, backend_port,
                         authorized_ews_ips, authorized_ews_identities, log_file, **common)
        self.protected_setpoints = [dict(w) for w in protected_setpoints]

    def _banner_lines(self) -> List[str]:
        return [
            f"Control commands require EWS   : process {sorted(PROCESS_COMMAND_TYPES)}, system {sorted(SYSTEM_COMMAND_TYPES)}",
            f"Refused for everyone           : C_RP_NA_1 (reset process, type 105)",
            f"Protected set-points           : {self.protected_setpoints or 'none'}",
        ]

    def _check_setpoint_hazard(self, setpoints) -> Optional[Tuple[Dict[str, Any], float]]:
        for sp in setpoints:
            for rule in self.protected_setpoints:
                if rule["ca"] == sp["ca"] and rule["ioa"] == sp["ioa"] and not (rule["min"] <= sp["value"] <= rule["max"]):
                    return rule, sp["value"]
        return None

    def evaluate_policy(self, parsed: Dict[str, Any], client_ip: str, client_port: int,
                        principal: Optional[str] = None) -> Tuple[bool, str]:
        principal = principal or client_ip
        self.stats["packets"] += 1
        type_id = parsed.get("type_id")

        # Supervisory / connection-control frames and monitoring-direction ASDUs: open.
        if parsed.get("frame_format") != "I" or type_id not in CONTROL_TYPES:
            self.stats["allowed"] += 1
            return True, "ALLOW"

        name = parsed.get("type_name", f"Type {type_id}")

        # Rule 1: reset process is refused for everyone.
        if type_id == IEC_RESET_PROCESS:
            self.stats["blocked"] += 1
            reason = f"CRITICAL ATTACK: IEC 104 Reset Process (type 105) from {principal}!"
            self.log_ecs_event(action=self._deny_action(), severity="critical", reason=reason,
                               client_ip=client_ip, client_port=client_port, mitre_id="T0806",
                               mitre_name="Brute Force I/O / Reset", details={"type_id": type_id, "type_name": name}, principal=principal)
            return False, reason

        # Rule 1b: a protected set-point may not leave its range, whoever sends it.
        hazard = self._check_setpoint_hazard(parsed.get("setpoints", []))
        if hazard is not None:
            rule, value = hazard
            self.stats["blocked"] += 1
            reason = (f"CRITICAL PROCESS HAZARD: set-point CA{rule['ca']}/IOA{rule['ioa']} = {value} outside "
                      f"[{rule['min']} .. {rule['max']}] (requested by {principal})")
            self.log_ecs_event(action=self._deny_action(), severity="critical", reason=reason,
                               client_ip=client_ip, client_port=client_port, mitre_id="T0836",
                               mitre_name="Modify Parameter", details={"type_id": type_id, "target": rule, "attempted_value": value},
                               principal=principal)
            return False, reason

        # Rule 2: any other control command requires the authorized identity.
        if principal not in self.authorized_principals:
            self.stats["blocked"] += 1
            reason = f"POLICY VIOLATION: IEC 104 control command {name} from unauthorized principal {principal}!"
            self.log_ecs_event(action=self._deny_action(), severity="high", reason=reason,
                               client_ip=client_ip, client_port=client_port, mitre_id="T0855",
                               mitre_name="Unauthorized Command Message",
                               details={"type_id": type_id, "type_name": name, "common_address": parsed.get("common_address")},
                               principal=principal)
            return False, reason

        self.stats["allowed"] += 1
        return True, "ALLOW"

    def _frame_client_stream(self, buf: bytes, client_ip: str, client_port: int,
                             principal: Optional[str] = None) -> Tuple[bytes, bytes, Optional[str]]:
        out = b""
        while len(buf) >= 2:
            if buf[0] != 0x68:
                return out, buf, f"Non-IEC104 start byte 0x{buf[0]:02X}"
            length = buf[1]
            if length < 4 or length > 253:
                return out, buf, f"Malformed IEC104 length {length}"
            total = 2 + length
            if len(buf) < total:
                break  # wait for the rest of this APDU
            apdu, buf = buf[:total], buf[total:]
            if not self.limiter.allow_request(client_ip):
                self._emit_limit_event(client_ip, client_port,
                                       f"Request rate cap: over {self.limiter.max_rps} APDUs/s from {client_ip}; dropping session")
                return out, buf, "Request rate cap exceeded"
            parsed = IEC104Parser.dissect(apdu)
            if parsed is None:
                return out, buf, "Unparseable IEC104 APDU"
            allowed, reason = self.evaluate_policy(parsed, client_ip, client_port, principal)
            if not allowed and self.enforce:
                return out, buf, reason
            if not allowed:
                logger.warning(f"[MONITOR] Would block, forwarding anyway. Reason: {reason}")
            out += apdu
        return out, buf, None


if __name__ == "__main__":
    import asyncio
    parser = argparse.ArgumentParser(description="IEC 60870-5-104 Layer-7 DPI Gateway")
    add_common_arguments(parser, listen_port=2404, backend_port=24040, log_file="logs/iec104_security_events.jsonl",
                         policy_example="iec104_policy.json",
                         tls_port_hint="Also listen for mutual-TLS sessions (ews_tls_tunnel.py) on this port; client certificate CN is the principal")
    args = parser.parse_args()
    policy = load_policy(args.policy) if args.policy else {}
    proxy = IEC104DPIProxy(protected_setpoints=policy.get("protected_setpoints", []), **common_kwargs(args, policy))
    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        logger.info("IEC104 DPI Proxy shutting down.")
