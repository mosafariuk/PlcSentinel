#!/usr/bin/env python3
"""
PlcSentinel - X.509 Certificate Generator for OPC UA (IEC 62541)
Generates RSA 2048-bit keys and self-signed X.509 certificates with
standard OPC UA Subject Alternative Name (URI and IP SANs).
"""

import os
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_cert_and_key(name: str, uri: str, ip_str: str = "127.0.0.1"):
    cert_dir = "certs"
    os.makedirs(cert_dir, exist_ok=True)

    # 1. Generate RSA Private Key (2048-bit)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2. Build X.509 Certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PlcSentinel OT Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"PlcSentinel {name}"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(uri),
                x509.IPAddress(ip_str if isinstance(ip_str, bytes) else __import__("ipaddress").ip_address(ip_str))
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # OPC UA (IEC 62541) requires these for application-instance certificates;
        # strict stacks reject certs without them.
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,   # non-repudiation
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Save Private Key (PEM)
    key_path = os.path.join(cert_dir, f"{name}_key.pem")
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save Certificate (DER - required by OPC UA standard)
    der_path = os.path.join(cert_dir, f"{name}_cert.der")
    with open(der_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))

    # Save Certificate (PEM - for inspectability)
    pem_path = os.path.join(cert_dir, f"{name}_cert.pem")
    with open(pem_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Generated {name} assets:")
    print(f"    - Key : {key_path}")
    print(f"    - DER : {der_path}")
    print(f"    - PEM : {pem_path}")

if __name__ == "__main__":
    generate_cert_and_key("opcua_server", "urn:plcsentinel:opcua:server")
    generate_cert_and_key("opcua_client", "urn:plcsentinel:opcua:client")
