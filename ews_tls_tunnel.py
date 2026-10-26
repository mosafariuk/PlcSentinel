#!/usr/bin/env python3
"""
PlcSentinel - EWS-side TLS tunnel for protocols without native TLS (S7comm)

Listens on a local plain port and, for every connection, opens a mutual-TLS
session to a gateway's TLS listener with the engineering workstation's
certificate, then relays bytes both ways. snap7 / TIA tools connect to
localhost; the gateway authorizes the certificate's Common Name, not the
source address. Works for Modbus too, though Modbus clients can speak
Modbus/TCP Security directly.

    python3 ews_tls_tunnel.py --listen 127.0.0.1:1102 --gateway 127.0.0.1:10202
"""

import ssl
import socket
import select
import logging
import argparse
import threading
from typing import Tuple

from dpi_tls import client_context

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [EWS-TUNNEL] %(message)s")
logger = logging.getLogger("EWSTunnel")


def _relay(a: socket.socket, b: socket.socket) -> None:
    """Pump bytes between two sockets until either side closes."""
    pairs = {a: b, b: a}
    try:
        while True:
            readable, _, errored = select.select([a, b], [], [a, b], 30)
            if errored:
                return
            for s in readable:
                data = s.recv(4096)
                if not data:
                    return
                while isinstance(s, ssl.SSLSocket) and s.pending():
                    data += s.recv(s.pending())
                pairs[s].sendall(data)
    except OSError:
        return
    finally:
        a.close()
        b.close()


class Tunnel:
    def __init__(self, listen: Tuple[str, int], gateway: Tuple[str, int], ctx: ssl.SSLContext):
        self.gateway = gateway
        self.ctx = ctx
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(listen)
        self.listener.listen(10)
        self.port = self.listener.getsockname()[1]

    def _handle(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            raw = socket.create_connection(self.gateway, timeout=5)
            tls = self.ctx.wrap_socket(raw, server_hostname=self.gateway[0])
        except (OSError, ssl.SSLError) as e:
            logger.error(f"Cannot open TLS session to gateway {self.gateway[0]}:{self.gateway[1]}: {e}")
            conn.close()
            return
        logger.info(f"[+] {addr[0]}:{addr[1]} -> TLS -> {self.gateway[0]}:{self.gateway[1]}")
        _relay(conn, tls)

    def serve_forever(self) -> None:
        while True:
            conn, addr = self.listener.accept()
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        return t


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EWS-side mutual-TLS tunnel to a PlcSentinel gateway")
    parser.add_argument("--listen", default="127.0.0.1:1102", metavar="HOST:PORT", help="Local plain listener (default: 127.0.0.1:1102)")
    parser.add_argument("--gateway", required=True, metavar="HOST:PORT", help="Gateway TLS listener, e.g. 192.168.1.101:10202")
    parser.add_argument("--cert", default="certs/ews_cert.pem", help="EWS certificate (PEM)")
    parser.add_argument("--key", default="certs/ews_key.pem", help="EWS private key (PEM)")
    parser.add_argument("--ca", default="certs/gateway_ca_cert.pem", help="CA that issued the gateway certificate (PEM)")
    args = parser.parse_args()

    def hostport(s: str) -> Tuple[str, int]:
        host, _, port = s.rpartition(":")
        return host, int(port)

    tunnel = Tunnel(hostport(args.listen), hostport(args.gateway), client_context(args.cert, args.key, args.ca))
    logger.info(f"Tunnel listening on {args.listen}, forwarding over mutual TLS to {args.gateway}")
    try:
        tunnel.serve_forever()
    except KeyboardInterrupt:
        logger.info("Tunnel stopped.")
