#!/usr/bin/env python3
"""
PlcSentinel - Generic identity-gated conduit (any TCP protocol)

For controllers whose protocol the gateways do not yet parse (EtherNet/IP,
Unitronics PCOM, vendor engineering protocols), this conduit still removes
their exposure: it terminates mutual TLS, admits only client certificates
whose Common Name is on the allow list, caps sessions and connection rate per
source, logs every admission and refusal as an ECS event, and relays bytes
unchanged to the controller. This is authentication without inspection: a
compromised authorized station still gets through, which is why protocol-aware
gateways remain the goal.

    python3 tls_conduit.py --listen 0.0.0.0:44818 --backend 10.0.1.30:44818 --allow ews-01
Clients that cannot speak TLS reach it through ews_tls_tunnel.py.
"""

import os
import ssl
import json
import socket
import logging
import argparse
import threading
from datetime import datetime, timezone
from typing import Optional, Tuple

from dpi_tls import server_context, peer_principal
from dpi_limits import SourceLimiter
from ews_tls_tunnel import relay

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [TLS-CONDUIT] %(message)s")
logger = logging.getLogger("TlsConduit")


class TlsConduit:
    def __init__(self, listen: Tuple[str, int], backend: Tuple[str, int], allowed_cns, tls_cert: str, tls_key: str,
                 tls_ca: str, log_file: str = "logs/conduit_events.jsonl", max_sessions_per_source: int = 8,
                 max_connections_per_second: int = 20, siem_udp: Optional[Tuple[str, int]] = None, name: str = "conduit"):
        self.listen, self.backend, self.name = listen, backend, name
        self.allowed = frozenset(f"cn:{c}" for c in allowed_cns)
        try:
            self.ctx = server_context(tls_cert, tls_key, tls_ca)
        except (OSError, ssl.SSLError) as e:
            raise SystemExit(f"[FATAL] Cannot load TLS material: {e}")
        self.limiter = SourceLimiter(max_sessions_per_source, max_connections_per_second)
        self.log_file = log_file
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._siem_udp = siem_udp
        self._siem_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if siem_udp else None

    def _log(self, action: str, severity: str, reason: str, ip: str, port: int, principal: Optional[str],
             mitre_id: Optional[str] = None, mitre_name: Optional[str] = None):
        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {"dataset": "ics.conduit", "action": action, "category": ["network", "intrusion_detection"],
                      "type": ["access", "connection"], "outcome": "success" if action == "allowed" else "failure",
                      "severity_label": severity},
            "source": {"ip": ip, "port": port},
            "destination": {"ip": self.backend[0], "port": self.backend[1]},
            "network": {"transport": "tcp", "protocol": "tcp", "name": self.name},
            "rule": {"description": reason, "mitre": {"id": mitre_id, "name": mitre_name}},
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
                logger.warning(f"SIEM UDP forward failed: {e}")

    def listener(self, port: Optional[int] = None) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.listen[0], self.listen[1] if port is None else port))
        s.listen(10)
        return s

    def accept_loop(self, listener: socket.socket):
        while True:
            conn, addr = listener.accept()
            threading.Thread(target=self._session, args=(conn, addr), daemon=True).start()

    def _session(self, conn: socket.socket, addr: Tuple[str, int]):
        ip, port = addr
        if not self.limiter.allow_request(ip) or not self.limiter.open_session(ip):
            self._log("blocked", "high", f"Source cap reached for {ip}", ip, port, None, "T0814", "Denial of Service")
            conn.close()
            return
        try:
            try:
                tls = self.ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError) as e:
                self._log("blocked", "high", f"TLS handshake failed: {e}", ip, port, None, "T0855", "Unauthorized Command Message")
                conn.close()
                return
            principal = peer_principal(tls.getpeercert())
            if principal not in self.allowed:
                self._log("blocked", "high", f"Certificate {principal or 'without CN'} is not on the allow list", ip, port, principal,
                          "T0855", "Unauthorized Command Message")
                tls.close()
                return
            try:
                backend = socket.create_connection(self.backend, timeout=5)
            except OSError as e:
                logger.error(f"Cannot reach backend {self.backend[0]}:{self.backend[1]}: {e}")
                tls.close()
                return
            self._log("allowed", "informational", f"Session admitted to {self.backend[0]}:{self.backend[1]}", ip, port, principal)
            logger.info(f"[+] {ip}:{port} as {principal} -> {self.backend[0]}:{self.backend[1]}")
            relay(tls, backend)
        finally:
            self.limiter.close_session(ip)

    def serve_forever(self):
        logger.info("=" * 70)
        logger.info(f"Identity-gated conduit '{self.name}' on {self.listen[0]}:{self.listen[1]} -> {self.backend[0]}:{self.backend[1]}")
        logger.info(f"Admitted principals: {sorted(self.allowed)} | no protocol inspection")
        logger.info("=" * 70)
        self.accept_loop(self.listener())


def hostport(s: str) -> Tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host, int(port)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Identity-gated TCP conduit for protocols without a dedicated gateway")
    parser.add_argument("--listen", required=True, metavar="HOST:PORT", help="Mutual-TLS listener")
    parser.add_argument("--backend", required=True, metavar="HOST:PORT", help="Controller address (plain TCP)")
    parser.add_argument("--allow", action="append", required=True, metavar="CN", help="Admitted certificate Common Name; repeatable")
    parser.add_argument("--name", default="conduit", help="Conduit name recorded in events")
    parser.add_argument("--tls-cert", default="certs/gateway_cert.pem")
    parser.add_argument("--tls-key", default="certs/gateway_key.pem")
    parser.add_argument("--tls-ca", default="certs/gateway_ca_cert.pem")
    parser.add_argument("--log-file", default="logs/conduit_events.jsonl")
    parser.add_argument("--siem-udp", metavar="HOST:PORT")
    parser.add_argument("--max-sessions", type=int, default=8, help="Concurrent sessions per source (default 8)")
    parser.add_argument("--max-connections-per-second", type=int, default=20, help="New connections per source per second (default 20)")
    args = parser.parse_args()
    conduit = TlsConduit(hostport(args.listen), hostport(args.backend), args.allow, args.tls_cert, args.tls_key, args.tls_ca,
                         args.log_file, args.max_sessions, args.max_connections_per_second,
                         hostport(args.siem_udp) if args.siem_udp else None, args.name)
    try:
        conduit.serve_forever()
    except KeyboardInterrupt:
        logger.info("Conduit stopped.")
