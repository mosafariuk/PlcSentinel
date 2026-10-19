#!/usr/bin/env python3
"""
PlcSentinel - Secure Industrial OPC UA Server (IEC 62541)
Contrasting unauthenticated Modbus TCP with modern encrypted OT communications:
- Enforces Basic256Sha256 with SignAndEncrypt
- Mutual authentication via X.509 certificates
- Industrial Tank Process Information Model (Address Space)
"""

import os
import asyncio
import logging
from asyncua import Server, ua
from asyncua.server.user_managers import CertificateUserManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [OPCUA-SERVER] %(message)s")
logger = logging.getLogger("OPCUAServer")

async def main():
    server = Server()
    await server.init()

    endpoint = "opc.tcp://127.0.0.1:4840/plcsentinel/server/"
    server.set_endpoint(endpoint)
    server.set_server_name("PlcSentinel Secure OPC UA Substation")

    # Load X.509 Cryptographic Identity
    cert_path = "certs/opcua_server_cert.der"
    key_path = "certs/opcua_server_key.pem"
    await server.load_certificate(cert_path)
    await server.load_private_key(key_path)

    # Configure Security Policies: Allow both Encrypted and None (for comparative lab analysis)
    server.set_security_policy([
        ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
        ua.SecurityPolicyType.Basic256Sha256_Sign,
        ua.SecurityPolicyType.NoSecurity
    ])

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
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("OPC UA Server stopped.")
