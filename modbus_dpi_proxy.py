#!/usr/bin/env python3
"""
PlcSentinel - Upgraded Layer-7 Modbus Deep Packet Inspection (DPI) Proxy with SIEM Logging
Enforces:
1. Read-only allowlist for every host; all other function codes are EWS-only
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
import threading
import ssl
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any

from dpi_limits import SourceLimiter
from dpi_tls import server_context, peer_principal

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
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    43: "Read Device Identification",
}

# Only plain reads are open to every host. Writes, FC22/23 masked and combined
# writes, FC08 diagnostics and vendor codes all require the EWS identity.
READ_FCS = frozenset({1, 2, 3, 4})

# Protected holding registers -> maximum safe value. Registers 0 (High) and
# 1 (Low) are the tank setpoints, scaled 0..1000.
PROTECTED_SETPOINT_REGS = {0: 900, 1: 900}

# JSON policy file keys and their types; CLI flags override file values.
POLICY_KEYS = {
    "authorized_ews_ips": list,
    "authorized_ews_identities": list,
    "read_function_codes": list,
    "protected_registers": dict,
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
        if "protected_registers" in policy:
            policy["protected_registers"] = {int(k): int(v) for k, v in policy["protected_registers"].items()}
        if "read_function_codes" in policy:
            policy["read_function_codes"] = [int(v) for v in policy["read_function_codes"]]
    except (TypeError, ValueError) as e:
        raise SystemExit(f"[FATAL] Policy file {path}: register addresses, limits and function codes must be integers ({e})")
    return policy

class ModbusDPIProxy:
    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 5020,
        backend_host: str = "127.0.0.1",
        backend_port: int = 502,
        authorized_ews_ips=("192.168.1.50",),
        authorized_ews_identities=(),
        read_fcs=READ_FCS,
        protected_registers: Optional[Dict[int, int]] = None,
        log_file: str = "logs/ot_security_events.jsonl",
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
        # client certificate issued by the lab CA (Modbus/TCP Security listener).
        self.authorized_principals = frozenset(authorized_ews_ips) | frozenset(f"cn:{c}" for c in authorized_ews_identities)
        self.read_fcs = frozenset(read_fcs)
        self.protected_registers = dict(PROTECTED_SETPOINT_REGS if protected_registers is None else protected_registers)
        self.log_file = log_file
        # Monitor mode: every violation is still inspected and logged, but the
        # frame is forwarded, so a site can observe inline before enforcing.
        self.enforce = enforce
        self.limiter = SourceLimiter(max_sessions_per_source, max_requests_per_second)
        # One thread per session: the lock keeps JSONL lines and counters intact.
        self._lock = threading.Lock()
        self._siem_udp = siem_udp
        self._siem_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if siem_udp else None
        self.tls_port = tls_port
        try:
            self._tls_ctx = server_context(tls_cert, tls_key, tls_ca) if tls_port is not None else None
        except (OSError, ssl.SSLError) as e:
            raise SystemExit(f"[FATAL] Cannot load TLS material for the Modbus/TCP Security listener: {e}")
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
        payload_details: Optional[Dict[str, Any]] = None,
        principal: Optional[str] = None
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

        if principal and principal.startswith("cn:"):
            event["user"] = {"name": principal[3:]}
        line = json.dumps(event) + "\n"
        with self._lock:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line)
        if self._siem_sock:
            try:
                self._siem_sock.sendto(line.encode("utf-8"), self._siem_udp)
            except OSError as e:
                logger.warning(f"SIEM UDP forward to {self._siem_udp} failed: {e}")

    def _count(self, key: str):
        with self._lock:
            self.stats[key] += 1

    def _deny_action(self) -> str:
        return "blocked" if self.enforce else "detected"

    def _emit_limit_event(self, client_ip: str, client_port: int, reason: str):
        """Resource caps protect the gateway and controller, so they apply in both modes."""
        logger.warning(f"[BLOCKED] {reason}")
        self.emit_siem_event(
            action="blocked", severity="high", reason=reason, client_ip=client_ip, client_port=client_port,
            trans_id=0, unit_id=0, fc=0, mitre_technique_id="T0814", mitre_technique_name="Denial of Service",
            payload_details={"max_sessions": self.limiter.max_sessions, "max_requests_per_second": self.limiter.max_rps}
        )

    def generate_exception_response(self, trans_id: int, unit_id: int, orig_fc: int, exc_code: int) -> bytes:
        mbap = trans_id.to_bytes(2, "big") + b"\x00\x00" + b"\x00\x03" + unit_id.to_bytes(1, "big")
        pdu = bytes([orig_fc | 0x80, exc_code])
        return mbap + pdu

    def _written_registers(self, fc: int, raw_pkt: bytes):
        """Yield (register, value) pairs a write PDU would commit.

        FC6 carries one register; FC16 and FC23 carry a block (FC23 after its
        read-range fields). The whole block is scanned so a protected register
        cannot be hidden inside a bulk write.
        """
        if fc == 6:
            if len(raw_pkt) >= 12:
                yield int.from_bytes(raw_pkt[8:10], "big"), int.from_bytes(raw_pkt[10:12], "big")
            return
        hdr = {16: 8, 23: 12}.get(fc)
        if hdr is None or len(raw_pkt) < hdr + 5:
            return
        start = int.from_bytes(raw_pkt[hdr:hdr + 2], "big")
        qty = int.from_bytes(raw_pkt[hdr + 2:hdr + 4], "big")
        data = raw_pkt[hdr + 5:hdr + 5 + raw_pkt[hdr + 4]]
        for i in range(min(qty, len(data) // 2)):
            yield start + i, int.from_bytes(data[2 * i:2 * i + 2], "big")

    def _check_setpoint_hazard(self, fc: int, raw_pkt: bytes) -> Optional[Tuple[int, Optional[int]]]:
        """Return (register, value) if a write pushes a protected setpoint
        register above the safe threshold, else None.

        A masked write (FC22) to a protected register returns (register, None):
        its result depends on the current value, which the gateway cannot see,
        so it is refused outright.
        """
        if fc == 22 and len(raw_pkt) >= 10:
            reg = int.from_bytes(raw_pkt[8:10], "big")
            if reg in self.protected_registers:
                return reg, None
        for reg, val in self._written_registers(fc, raw_pkt):
            limit = self.protected_registers.get(reg)
            if limit is not None and val > limit:
                return reg, val
        return None

    def inspect_request(self, raw_pkt: bytes, client_ip: str, client_port: int,
                        principal: Optional[str] = None) -> Tuple[bool, Optional[bytes], str]:
        principal = principal or client_ip
        self._count("inspected")
        if len(raw_pkt) < 8:
            return False, None, "Malformed packet: length shorter than MBAP + FC"

        trans_id = int.from_bytes(raw_pkt[0:2], "big")
        proto_id = int.from_bytes(raw_pkt[2:4], "big")
        length = int.from_bytes(raw_pkt[4:6], "big")
        unit_id = raw_pkt[6]
        fc = raw_pkt[7]

        if proto_id != 0:
            return False, None, f"Invalid Protocol ID 0x{proto_id:04X}"

        # ----------------------------------------------------------------------
        # TIER 1: Function Code & Role-Based Authorization
        # Read allowlist: only FC 01-04 are open to every host. Everything else
        # requires the authorized EWS identity.
        # ----------------------------------------------------------------------
        if fc not in self.read_fcs and principal not in self.authorized_principals:
            self._count("blocked")
            reason = f"POLICY VIOLATION: Non-read Function Code {fc:02d} ({FC_NAMES.get(fc, 'Vendor/Unknown')}) denied for unauthorized principal {principal}"
            exc_resp = self.generate_exception_response(trans_id, unit_id, fc, EXC_ILLEGAL_FUNCTION)

            addr = int.from_bytes(raw_pkt[8:10], "big") if len(raw_pkt) >= 10 else 0
            val = int.from_bytes(raw_pkt[10:12], "big") if len(raw_pkt) >= 12 else 0

            self.emit_siem_event(
                action=self._deny_action(),
                severity="high",
                reason=reason,
                client_ip=client_ip,
                client_port=client_port,
                trans_id=trans_id,
                unit_id=unit_id,
                fc=fc,
                mitre_technique_id="T0855",
                mitre_technique_name="Unauthorized Command Message",
                payload_details={"target_address": addr, "target_value": val},
                principal=principal
            )
            return False, exc_resp, reason

        # ----------------------------------------------------------------------
        # TIER 2: Semantic Process Boundary Inspection
        # Covers FC6, FC16 and FC23 writes to the protected setpoint registers
        # and refuses FC22 masked writes to them, so the bulk, combined and
        # masked paths cannot poison a setpoint either.
        # ----------------------------------------------------------------------
        hazard = self._check_setpoint_hazard(fc, raw_pkt)
        if hazard is not None:
            reg_addr, reg_val = hazard
            self._count("blocked")
            if reg_val is None:
                reason = (
                    f"CRITICAL PROCESS HAZARD: Masked write to protected setpoint register {reg_addr} refused; "
                    "the resulting value cannot be verified."
                )
            else:
                reason = (
                    f"CRITICAL PROCESS HAZARD: Setpoint register {reg_addr} = {reg_val} exceeds safe capacity "
                    f"({self.protected_registers[reg_addr]}). Potential loss-of-containment attack."
                )
            exc_resp = self.generate_exception_response(trans_id, unit_id, fc, EXC_ILLEGAL_DATA_VALUE)

            self.emit_siem_event(
                action=self._deny_action(),
                severity="critical",
                reason=reason,
                client_ip=client_ip,
                client_port=client_port,
                trans_id=trans_id,
                unit_id=unit_id,
                fc=fc,
                mitre_technique_id="T0836",
                mitre_technique_name="Modify Parameter",
                payload_details={"target_register": reg_addr, "attempted_value": reg_val, "safe_limit": self.protected_registers[reg_addr]},
                principal=principal
            )
            return False, exc_resp, reason

        # Allowed Operation
        self._count("allowed")
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
            payload_details={"address": addr, "count_or_val": qty},
            principal=principal
        )
        return True, None, "ALLOW"

    def handle_client_session(self, client_sock: socket.socket, client_addr: Tuple[str, int], principal: Optional[str] = None):
        client_ip, client_port = client_addr
        if not self.limiter.open_session(client_ip):
            self._emit_limit_event(client_ip, client_port,
                                   f"Session cap: {self.limiter.max_sessions} sessions already open from {client_ip}; refusing another")
            client_sock.close()
            return
        try:
            self._serve_session(client_sock, client_addr, principal)
        finally:
            self.limiter.close_session(client_ip)

    def _serve_session(self, client_sock: socket.socket, client_addr: Tuple[str, int], principal: Optional[str] = None):
        client_ip, client_port = client_addr
        try:
            backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_sock.settimeout(3.0)
            backend_sock.connect((self.backend_host, self.backend_port))
        except Exception as e:
            logger.error(f"Cannot reach OpenPLC ({self.backend_host}:{self.backend_port}): {e}")
            client_sock.close()
            return

        client_buf = b""
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
                    # A TLS record can decrypt to more than one recv; drain it,
                    # or select() never wakes for the buffered remainder.
                    while isinstance(sock, ssl.SSLSocket) and sock.pending():
                        data += sock.recv(sock.pending())

                    if sock is client_sock:
                        # Modbus/TCP is a byte stream: a single recv may hold
                        # several ADUs (pipelining) or a partial one. Frame on the
                        # MBAP length field and inspect every complete ADU before
                        # forwarding it, so nothing reaches the PLC uninspected.
                        client_buf += data
                        client_buf = self._process_client_stream(
                            client_buf, client_sock, backend_sock, client_ip, client_port, principal
                        )
                        if client_buf is None:
                            return
                    else:
                        client_sock.sendall(data)
        finally:
            client_sock.close()
            backend_sock.close()

    def _process_client_stream(
        self,
        buf: bytes,
        client_sock: socket.socket,
        backend_sock: socket.socket,
        client_ip: str,
        client_port: int,
        principal: Optional[str] = None,
    ) -> Optional[bytes]:
        """Extract and inspect complete Modbus ADUs from the client byte stream.

        Returns the unconsumed tail (a partial ADU awaiting more bytes), or None
        to signal the session must be torn down (fail-closed on a malformed MBAP).
        """
        while len(buf) >= 6:
            length = int.from_bytes(buf[4:6], "big")
            # MBAP length counts unit id + PDU; bound it to reject garbage/smuggling.
            if length < 2 or length > 253:
                logger.warning(
                    f"[BLOCKED] Malformed MBAP length={length} from {client_ip}; dropping session"
                )
                return None
            total = 6 + length
            if len(buf) < total:
                break  # wait for the remainder of this ADU
            adu, buf = buf[:total], buf[total:]
            if not self.limiter.allow_request(client_ip):
                self._emit_limit_event(client_ip, client_port,
                                       f"Request rate cap: over {self.limiter.max_rps} requests/s from {client_ip}; dropping session")
                return None
            is_allowed, synthetic_resp, reason = self.inspect_request(adu, client_ip, client_port, principal)
            if is_allowed:
                backend_sock.sendall(adu)
            elif not self.enforce:
                logger.warning(f"[MONITOR] Would block, forwarding anyway. Reason: {reason}")
                backend_sock.sendall(adu)
            else:
                logger.warning(f"[BLOCKED] Packet dropped! Reason: {reason}")
                if synthetic_resp:
                    client_sock.sendall(synthetic_resp)
        return buf

    def _tls_listener(self, port: Optional[int] = None) -> socket.socket:
        """Bind the Modbus/TCP Security (mutual TLS) listener; TLS is wrapped per connection."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.listen_host, self.tls_port if port is None else port))
        listener.listen(10)
        return listener

    def _tls_accept_loop(self, listener: socket.socket):
        while True:
            conn, addr = listener.accept()
            threading.Thread(target=self._tls_session, args=(conn, addr), daemon=True).start()

    def _tls_session(self, conn: socket.socket, addr: Tuple[str, int]):
        """Handshake (client certificate required), derive the principal, then serve as usual."""
        try:
            tls = self._tls_ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as e:
            logger.warning(f"[BLOCKED] TLS handshake from {addr[0]}:{addr[1]} failed: {e}")
            conn.close()
            return
        principal = peer_principal(tls.getpeercert())
        if principal is None:
            logger.warning(f"[BLOCKED] TLS client {addr[0]}:{addr[1]} presented a certificate without a Common Name")
            tls.close()
            return
        logger.info(f"[+] Modbus/TCP Security session from {addr[0]}:{addr[1]} as {principal}")
        self.handle_client_session(tls, addr, principal)

    def start_proxy(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.listen_host, self.listen_port))
        server.listen(10)
        if self._tls_ctx:
            threading.Thread(target=self._tls_accept_loop, args=(self._tls_listener(),), daemon=True).start()
        logger.info("=" * 70)
        logger.info(f"Modbus L7 DPI Proxy ACTIVE on {self.listen_host}:{self.listen_port}")
        if self._tls_ctx:
            logger.info(f"Modbus/TCP Security (mutual TLS) listener on {self.listen_host}:{self.tls_port}")
        logger.info(f"SIEM Structured Logging: {os.path.abspath(self.log_file)}")
        logger.info(f"Authorized principals: {sorted(self.authorized_principals)} | open FCs: {sorted(self.read_fcs)} | protected registers: {self.protected_registers}")
        logger.info(f"Mode: {'ENFORCE' if self.enforce else 'MONITOR (violations logged as detected, traffic forwarded)'}")
        logger.info("=" * 70)

        try:
            while True:
                client_sock, client_addr = server.accept()
                # One thread per session so a slow or idle client cannot block
                # inspection of every other connection.
                threading.Thread(
                    target=self.handle_client_session,
                    args=(client_sock, client_addr),
                    daemon=True,
                ).start()
        finally:
            server.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modbus Layer-7 DPI Gateway Proxy with SIEM Logging")
    parser.add_argument("--listen-host", type=str, default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=5020, help="Listen port (default: 5020)")
    parser.add_argument("--backend-host", type=str, default="127.0.0.1", help="Backend PLC IP (default: 127.0.0.1)")
    parser.add_argument("--backend-port", type=int, default=502, help="Backend PLC port (default: 502)")
    parser.add_argument("--policy", type=str, help="JSON policy file (see modbus_policy.json); explicit CLI flags override it")
    parser.add_argument("--authorized-ip", action="append", default=None, help="Authorized EWS IP; repeatable (default: 192.168.1.50)")
    parser.add_argument("--log-file", type=str, default="logs/ot_security_events.jsonl", help="SIEM event log path")
    parser.add_argument("--monitor", action="store_true", help="Log policy violations but forward all traffic (observe inline before enforcing)")
    parser.add_argument("--siem-udp", type=str, metavar="HOST:PORT", help="Also send every event as a JSON datagram to this collector (Elastic/Logstash/Wazuh)")
    parser.add_argument("--tls-port", type=int, default=None, help="Also listen for Modbus/TCP Security (mutual TLS) on this port, e.g. 802; client certificate CN is the principal")
    parser.add_argument("--tls-cert", type=str, default="certs/gateway_cert.pem", help="Gateway certificate (PEM)")
    parser.add_argument("--tls-key", type=str, default="certs/gateway_key.pem", help="Gateway private key (PEM)")
    parser.add_argument("--tls-ca", type=str, default="certs/gateway_ca_cert.pem", help="CA that issues client certificates (PEM)")
    args = parser.parse_args()

    policy = load_policy(args.policy) if args.policy else {}
    siem_udp = None
    if args.siem_udp:
        host, _, port = args.siem_udp.rpartition(":")
        siem_udp = (host, int(port))
    proxy = ModbusDPIProxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        backend_host=args.backend_host,
        backend_port=args.backend_port,
        authorized_ews_ips=args.authorized_ip or policy.get("authorized_ews_ips", ["192.168.1.50"]),
        authorized_ews_identities=policy.get("authorized_ews_identities", []),
        read_fcs=policy.get("read_function_codes", READ_FCS),
        protected_registers=policy.get("protected_registers"),
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
    proxy.start_proxy()
