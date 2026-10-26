#!/usr/bin/env python3
"""
PlcSentinel - Transport shared by the asyncio Layer-7 gateways

A gateway is a framer plus a policy. Everything else is the same for every
stream protocol and lives here: the plain and mutual-TLS listeners, the
principal model (source address or client-certificate CN), per-source caps,
monitor mode, ECS event writing with optional SIEM forwarding, the policy
file loader and the common command-line flags.

Subclasses set DATASET / PROTOCOL / DETAILS_KEY / NAME / APPLICATION and
implement _frame_client_stream(buf, client_ip, client_port, principal)
-> (forwardable_bytes, remaining_buf, drop_reason).
"""

import os
import ssl
import json
import socket
import asyncio
import logging
import argparse
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from dpi_limits import SourceLimiter
from dpi_tls import server_context, peer_principal

logger = logging.getLogger("StreamDPI")

COMMON_POLICY_KEYS = {
    "authorized_ews_ips": list,
    "authorized_ews_identities": list,
    "max_sessions_per_source": int,
    "max_requests_per_second": int,
    "enforce": bool,
}


def load_policy_file(path: str, keys: Dict[str, type], convert: Optional[Callable[[Dict[str, Any]], None]] = None,
                     hint: str = "") -> Dict[str, Any]:
    """Read and validate a JSON policy file. Any problem is fatal at startup:
    a gateway must never run on a policy it only half understood."""
    try:
        with open(path, encoding="utf-8") as f:
            policy = json.load(f)
    except (OSError, ValueError) as e:
        raise SystemExit(f"[FATAL] Cannot read policy file {path}: {e}")
    if not isinstance(policy, dict) or set(policy) - set(keys):
        raise SystemExit(f"[FATAL] Policy file {path}: expected an object with keys {sorted(keys)}")
    for key, typ in keys.items():
        if key in policy and (not isinstance(policy[key], typ) or (typ is int and isinstance(policy[key], bool))):
            raise SystemExit(f"[FATAL] Policy file {path}: {key!r} must be a JSON {typ.__name__}")
    try:
        if convert:
            convert(policy)
    except (TypeError, ValueError, KeyError) as e:
        raise SystemExit(f"[FATAL] Policy file {path}: {hint} ({e})")
    return policy


def add_common_arguments(parser: argparse.ArgumentParser, listen_port: int, backend_port: int, log_file: str,
                         policy_example: str, tls_port_hint: str) -> None:
    parser.add_argument("--listen-host", type=str, default="0.0.0.0", help="Gateway listen IP (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=listen_port, help=f"Gateway listen port (default: {listen_port})")
    parser.add_argument("--backend-host", type=str, default="127.0.0.1", help="Controller IP (default: 127.0.0.1)")
    parser.add_argument("--backend-port", type=int, default=backend_port, help=f"Controller port (default: {backend_port})")
    parser.add_argument("--policy", type=str, help=f"JSON policy file (see {policy_example}); explicit CLI flags override it")
    parser.add_argument("--authorized-ews", action="append", default=None, help="Authorized EWS IP; repeatable (default: 192.168.1.50)")
    parser.add_argument("--log-file", type=str, default=log_file, help="SIEM event output path")
    parser.add_argument("--monitor", action="store_true", help="Log policy violations but forward all traffic (observe inline before enforcing)")
    parser.add_argument("--siem-udp", type=str, metavar="HOST:PORT", help="Also send every event as a JSON datagram to this collector (Elastic/Logstash/Wazuh)")
    parser.add_argument("--tls-port", type=int, default=None, help=tls_port_hint)
    parser.add_argument("--tls-cert", type=str, default="certs/gateway_cert.pem", help="Gateway certificate (PEM)")
    parser.add_argument("--tls-key", type=str, default="certs/gateway_key.pem", help="Gateway private key (PEM)")
    parser.add_argument("--tls-ca", type=str, default="certs/gateway_ca_cert.pem", help="CA that issues client certificates (PEM)")


def common_kwargs(args: argparse.Namespace, policy: Dict[str, Any]) -> Dict[str, Any]:
    siem_udp = None
    if args.siem_udp:
        host, _, port = args.siem_udp.rpartition(":")
        siem_udp = (host, int(port))
    return dict(
        listen_host=args.listen_host, listen_port=args.listen_port,
        backend_host=args.backend_host, backend_port=args.backend_port,
        authorized_ews_ips=args.authorized_ews or policy.get("authorized_ews_ips", ["192.168.1.50"]),
        authorized_ews_identities=policy.get("authorized_ews_identities", []),
        log_file=args.log_file,
        enforce=policy.get("enforce", True) and not args.monitor,
        max_sessions_per_source=policy.get("max_sessions_per_source", 8),
        max_requests_per_second=policy.get("max_requests_per_second", 200),
        siem_udp=siem_udp,
        tls_port=args.tls_port, tls_cert=args.tls_cert, tls_key=args.tls_key, tls_ca=args.tls_ca,
    )


class StreamDPIProxy:
    DATASET = "ics.stream"
    PROTOCOL = "tcp"
    DETAILS_KEY = "details"
    NAME = "Stream"
    APPLICATION: Optional[str] = None
    TACTIC = "Inhibit Response Function / Impact"

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        backend_host: str = "127.0.0.1",
        backend_port: int = 0,
        authorized_ews_ips=("192.168.1.50",),
        authorized_ews_identities=(),
        log_file: str = "logs/events.jsonl",
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
        os.makedirs(os.path.dirname(self.log_file) or ".", exist_ok=True)

    # ------------------------------------------------------------------ events
    def log_ecs_event(self, action: str, severity: str, reason: str, client_ip: str, client_port: int,
                      mitre_id: Optional[str] = None, mitre_name: Optional[str] = None,
                      details: Optional[Dict[str, Any]] = None, principal: Optional[str] = None):
        """Emits an Elastic Common Schema (ECS) JSON event log."""
        network = {"transport": "tcp", "protocol": self.PROTOCOL}
        if self.APPLICATION:
            network["application"] = self.APPLICATION
        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {
                "dataset": self.DATASET,
                "action": action,
                "category": ["network", "intrusion_detection"],
                "type": ["access", "protocol"],
                "outcome": "success" if action == "allowed" else "failure",
                "severity_label": severity,
            },
            "source": {"ip": client_ip, "port": client_port},
            "destination": {"ip": self.listen_host, "port": self.listen_port},
            "network": network,
            self.DETAILS_KEY: details or {},
            "rule": {"description": reason, "mitre": {"id": mitre_id, "name": mitre_name, "tactic": self.TACTIC if mitre_id else None}},
        }
        if principal and principal.startswith("cn:"):
            event["user"] = {"name": principal[3:]}
        # Protocol details may carry raw payload bytes; log them as hex.
        line = json.dumps(event, default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else str(o)) + "\n"
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
        self.log_ecs_event(action="blocked", severity="high", reason=reason, client_ip=client_ip, client_port=client_port,
                           mitre_id="T0814", mitre_name="Denial of Service",
                           details={"max_sessions": self.limiter.max_sessions, "max_requests_per_second": self.limiter.max_rps})

    # ------------------------------------------------------------------ protocol hooks
    def _frame_client_stream(self, buf: bytes, client_ip: str, client_port: int,
                             principal: Optional[str] = None) -> Tuple[bytes, bytes, Optional[str]]:
        raise NotImplementedError

    def _banner_lines(self) -> List[str]:
        return []

    # ------------------------------------------------------------------ transport
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
                    # Controller -> client responses are forwarded unmodified.
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
                    # Immediately terminate connection to protect the controller
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
        """Handles an incoming connection from HMI / EWS / attacker."""
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
        logger.info(f"[+] Incoming {self.NAME} session accepted from {client_ip}:{client_port}" + (f" as {principal}" if principal else ""))
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
        try:
            plc_reader, plc_writer = await asyncio.wait_for(
                asyncio.open_connection(self.backend_host, self.backend_port), timeout=3.0)
        except Exception as e:
            logger.error(f"[-] Cannot reach backend controller ({self.backend_host}:{self.backend_port}): {e}")
            client_writer.close()
            await client_writer.wait_closed()
            return
        client_to_plc = asyncio.create_task(
            self.pipe(client_reader, plc_writer, is_client=True, client_ip=client_ip, client_port=client_port, principal=principal))
        plc_to_client = asyncio.create_task(
            self.pipe(plc_reader, client_writer, is_client=False, client_ip=client_ip, client_port=client_port))
        await asyncio.gather(client_to_plc, plc_to_client, return_exceptions=True)
        logger.info(f"[*] {self.NAME} session closed for {client_ip}:{client_port} | Total Stats: {self.stats}")

    async def start(self):
        servers = [await asyncio.start_server(self.handle_client, self.listen_host, self.listen_port)]
        if self._tls_ctx:
            servers.append(await asyncio.start_server(self.handle_client, self.listen_host, self.tls_port, ssl=self._tls_ctx))
        logger.info("=" * 72)
        logger.info(f"{self.NAME} Layer-7 DPI Proxy ACTIVE on {self.listen_host}:{self.listen_port}")
        if self._tls_ctx:
            logger.info(f"Mutual-TLS listener (reach it with ews_tls_tunnel.py) on {self.listen_host}:{self.tls_port}")
        logger.info(f"Forwarding sanitized traffic to controller at {self.backend_host}:{self.backend_port}")
        logger.info(f"Authorized principals             : {sorted(self.authorized_principals)}")
        for line in self._banner_lines():
            logger.info(line)
        logger.info(f"SIEM Structured Logging           : {os.path.abspath(self.log_file)}")
        logger.info(f"Mode                              : {'ENFORCE' if self.enforce else 'MONITOR (violations logged as detected, traffic forwarded)'}")
        logger.info("=" * 72)
        try:
            await asyncio.gather(*(s.serve_forever() for s in servers))
        finally:
            for s in servers:
                s.close()
