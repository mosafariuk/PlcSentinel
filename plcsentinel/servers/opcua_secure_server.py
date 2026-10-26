#!/usr/bin/env python3
"""
PlcSentinel - Secure Industrial OPC UA Server (IEC 62541)
Contrasting unauthenticated Modbus TCP with modern encrypted OT communications:
- Enforces Basic256Sha256 with SignAndEncrypt
- Mutual authentication via X.509 certificates
- Industrial Tank Process Information Model (Address Space)
"""

import os
import argparse
import asyncio
import logging
from asyncua import Server, ua
from asyncua.server.user_managers import CertificateUserManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [OPCUA-SERVER] %(message)s")
logger = logging.getLogger("OPCUAServer")

CLIENT_CERT = "certs/opcua_client_cert.der"


async def main(insecure_demo: bool = False):
    cert_path = "certs/opcua_server_cert.der"
    key_path = "certs/opcua_server_key.pem"

    # Trust store: only the known engineering-workstation client certificate is
    # accepted as a user identity. This is what makes the "mutual authentication"
    # claim real — an attacker without this certificate's private key is rejected.
    user_manager = CertificateUserManager()
    if not insecure_demo:
        if not os.path.exists(CLIENT_CERT):
            raise SystemExit(
                f"[FATAL] Trusted client certificate {CLIENT_CERT} not found. "
                "Run generate_opcua_certs.py first."
            )
        await user_manager.add_user(CLIENT_CERT, name="authorized_engineer")

    server = Server(user_manager=user_manager)
    await server.init()

    endpoint = "opc.tcp://0.0.0.0:4840/plcsentinel/server/"
    server.set_endpoint(endpoint)
    server.set_server_name("PlcSentinel Secure OPC UA Substation")
    # ApplicationUri MUST match the URI SAN in the server certificate, or strict
    # OPC UA clients reject the certificate.
    await server.set_application_uri("urn:plcsentinel:opcua:server")

    # Load X.509 Cryptographic Identity
    await server.load_certificate(cert_path)
    await server.load_private_key(key_path)

    # Configure Security Policies.
    # Secure default: encrypted/signed channels ONLY, and user identity must be a
    # trusted X.509 certificate (anonymous + cleartext are rejected).
    policies = [
        ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
        ua.SecurityPolicyType.Basic256Sha256_Sign,
    ]
    if insecure_demo:
        # Opt-in ONLY for the Modbus-vs-OPC-UA comparative lesson: exposes an
        # unauthenticated cleartext endpoint. Never use outside the lab.
        logger.warning("!" * 65)
        logger.warning("INSECURE DEMO MODE: NoSecurity endpoint + anonymous access ENABLED.")
        logger.warning("This allows unauthenticated cleartext writes. Lab use only.")
        logger.warning("!" * 65)
        policies.append(ua.SecurityPolicyType.NoSecurity)

    server.set_security_policy(policies)
    if not insecure_demo:
        # Reject the Anonymous user token entirely; require X.509 certificate identity.
        server.set_identity_tokens([ua.X509IdentityToken])

    # Setup OPC UA Information Model (Address Space)
    uri = "urn:plcsentinel:opcua:tank"
    idx = await server.register_namespace(uri)

    objects = server.nodes.objects
    tank_folder = await objects.add_folder(idx, "TankLevelSystem")

    # Process Variables
    var_level = await tank_folder.add_variable(idx, "TankLevelRaw", 150.0)
    var_pump = await tank_folder.add_variable(idx, "PumpMotorState", False)
    var_drain = await tank_folder.add_variable(idx, "DrainValveState", False)
    var_high = await tank_folder.add_variable(idx, "HighThreshold", 850)
    var_low = await tank_folder.add_variable(idx, "LowThreshold", 200)

    # Grant write access to setpoints & overrides
    await var_high.set_writable()
    await var_low.set_writable()
    await var_drain.set_writable()

    logger.info("=" * 65)
    logger.info(f"Secure OPC UA Server ACTIVE on {endpoint}")
    logger.info("Security Policy: Basic256Sha256 (Sign & Encrypt Enabled)")
    logger.info(f"Auth: {'ANONYMOUS/CLEARTEXT (insecure demo)' if insecure_demo else 'X.509 Certificate identity REQUIRED'}")
    logger.info(f"Server Certificate: {cert_path}")
    logger.info("Address Space: ns=2;s=TankLevelSystem")
    logger.info("=" * 65)

    async with server:
        while True:
            # Simple process loop simulation
            level = await var_level.get_value()
            pump = await var_pump.get_value()
            drain = await var_drain.get_value()

            # Physical change
            delta = 0.0
            if pump:
                delta += 2.5
            if drain:
                delta -= 5.0
            new_level = max(0.0, min(1000.0, level + delta))
            await var_level.set_value(new_level)

            await asyncio.sleep(1.0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PlcSentinel Secure OPC UA Server")
    parser.add_argument(
        "--insecure-demo",
        action="store_true",
        help="Lab only: also expose an unauthenticated NoSecurity/cleartext endpoint "
             "for the Modbus-vs-OPC-UA comparison. Off by default.",
    )
    args = parser.parse_args()
    try:
        asyncio.run(main(insecure_demo=args.insecure_demo))
    except KeyboardInterrupt:
        logger.info("OPC UA Server stopped.")
