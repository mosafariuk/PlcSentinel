#!/usr/bin/env python3
"""
PlcSentinel - Lab PKI for the mutual-TLS conduits

Creates, under certs/:
  gateway_ca_cert.pem / gateway_ca_key.pem   lab certificate authority
  gateway_cert.pem    / gateway_key.pem      server identity of both DPI gateways (IP and DNS SANs)
  ews_cert.pem        / ews_key.pem          client identity of the engineering workstation

The EWS certificate's Common Name is the principal the gateways authorize
(policy key authorized_ews_identities). Lab material only: regenerate freely.
"""

import os
import ipaddress
import argparse
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT_SANS = ("127.0.0.1", "192.168.1.100", "192.168.1.101", "modbus-dpi-proxy", "s7-dpi-proxy")


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PlcSentinel OT Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _write(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def _save(out_dir: str, stem: str, key, cert) -> None:
    _write(os.path.join(out_dir, f"{stem}_key.pem"), key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    _write(os.path.join(out_dir, f"{stem}_cert.pem"), cert.public_bytes(serialization.Encoding.PEM))


def make_gateway_pki(out_dir: str = "certs", ews_cn: str = "ews-01", sans=DEFAULT_SANS, days: int = 365) -> dict:
    """Generate CA, gateway and EWS material; returns {name: path}."""
    os.makedirs(out_dir, exist_ok=True)
    now = datetime.now(timezone.utc)

    def build(subject_cn, key, issuer_name, issuer_key, ca=False, sans=(), eku=()):
        b = (x509.CertificateBuilder()
             .subject_name(_name(subject_cn)).issuer_name(issuer_name)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(now + timedelta(days=days))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
        if ca:
            b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                              content_commitment=False, key_encipherment=False, data_encipherment=False,
                                              key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        else:
            b = b.add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False,
                                              crl_sign=False, content_commitment=False, data_encipherment=False,
                                              key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            b = b.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
        if sans:
            entries = []
            for s in sans:
                try:
                    entries.append(x509.IPAddress(ipaddress.ip_address(s)))
                except ValueError:
                    entries.append(x509.DNSName(s))
            b = b.add_extension(x509.SubjectAlternativeName(entries), critical=False)
        return b.sign(issuer_key, hashes.SHA256())

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = build("PlcSentinel Lab CA", ca_key, _name("PlcSentinel Lab CA"), ca_key, ca=True)
    gw_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    gw_cert = build("plcsentinel-gateway", gw_key, ca_cert.subject, ca_key, sans=sans, eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    ews_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ews_cert = build(ews_cn, ews_key, ca_cert.subject, ca_key, eku=[ExtendedKeyUsageOID.CLIENT_AUTH])

    _save(out_dir, "gateway_ca", ca_key, ca_cert)
    _save(out_dir, "gateway", gw_key, gw_cert)
    _save(out_dir, "ews", ews_key, ews_cert)
    return {stem: os.path.join(out_dir, f"{stem}_{kind}.pem")
            for stem in ("gateway_ca", "gateway", "ews") for kind in ("cert",)} | {
            f"{stem}_key": os.path.join(out_dir, f"{stem}_key.pem") for stem in ("gateway_ca", "gateway", "ews")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate the lab CA, gateway and EWS certificates")
    parser.add_argument("--out", default="certs", help="Output directory (default: certs)")
    parser.add_argument("--ews-cn", default="ews-01", help="EWS certificate Common Name = authorized principal (default: ews-01)")
    parser.add_argument("--san", action="append", help="Gateway SAN (IP or DNS); repeatable. Default covers the compose topology")
    parser.add_argument("--if-missing", action="store_true", help="Do nothing when the CA already exists")
    args = parser.parse_args()
    if args.if_missing and os.path.exists(os.path.join(args.out, "gateway_ca_cert.pem")):
        print("[=] Gateway PKI already present; keeping it.")
    else:
        for name, path in sorted(make_gateway_pki(args.out, args.ews_cn, args.san or DEFAULT_SANS).items()):
            print(f"[+] {name:16} {path}")
