#!/usr/bin/env python3
"""
PlcSentinel - Mutual-TLS helpers shared by the DPI gateways and the EWS tunnel.

Modbus TCP and S7comm carry no identity, so the gateways terminate mutual TLS
on the supervisory side: a client is authenticated by a certificate issued by
the lab CA, and its Common Name becomes the principal the policy authorizes
("cn:<name>"). Behind the gateway the controller still speaks plain Modbus or
S7comm, which is the point of the conduit. Modbus/TCP Security (port 802)
specifies exactly this TLS wrapping; S7comm has no equivalent, so engineering
stations reach the S7 gateway through ews_tls_tunnel.py.
"""

import ssl
from typing import Optional


def server_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    """TLS 1.2+ server context that requires a client certificate from the CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    ctx.load_verify_locations(ca)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def client_context(cert: str, key: str, ca: str, check_hostname: bool = True) -> ssl.SSLContext:
    """TLS 1.2+ client context presenting our certificate and pinning the CA.

    check_hostname=False is for libraries that wrap sockets without a
    server_hostname (pymodbus' sync TLS client); the chain is still verified
    against the pinned CA, only the SAN binding is skipped.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(ca)
    ctx.load_cert_chain(cert, key)
    ctx.check_hostname = check_hostname
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def peer_principal(peercert: Optional[dict]) -> Optional[str]:
    """'cn:<CommonName>' from a verified peer certificate (ssl getpeercert()), else None."""
    for rdn in (peercert or {}).get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return f"cn:{value}"
    return None
