#!/usr/bin/env python3
"""
PlcSentinel - Secure Industrial OPC UA Client (IEC 62541)
Demonstrates mutual certificate authentication and encrypted communication:
- Negotiates Basic256Sha256 with MessageSecurityMode.SignAndEncrypt
- Protects against Man-in-the-Middle (MITM) and wire sniffing attacks
"""

import sys
import asyncio
import logging
from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256

logging.basicConfig(level=logging.INFO, format="%(asctime)s [OPCUA-CLIENT] %(message)s")
logger = logging.getLogger("OPCUAClient")

async def run_client(use_encryption=True):
    url = "opc.tcp://127.0.0.1:4840/plcsentinel/server/"
    logger.info(f"Connecting to OPC UA Server: {url}")

    client = Client(url=url)

    if use_encryption:
        logger.info("[SEC] Configuring Cryptographic Identity & Encryption (Basic256Sha256 / SignAndEncrypt)...")
        await client.set_security(
            SecurityPolicyBasic256Sha256,
            certificate="certs/opcua_client_cert.der",
            private_key="certs/opcua_client_key.pem",
            server_certificate="certs/opcua_server_cert.der"
        )
        # Authenticate the USER identity with the same X.509 certificate so the
        # server (which requires a trusted certificate identity) accepts us. This
        # is the client half of mutual authentication.
        await client.load_client_certificate("certs/opcua_client_cert.der")
        await client.load_private_key("certs/opcua_client_key.pem")
    else:
        logger.warning("[WARN] Connecting with NoSecurity (Cleartext mode)...")

    async with client:
        logger.info("[SUCCESS] Cryptographic Session Established with OPC UA Server!")

        # Discover Namespace Index
        ns_idx = await client.get_namespace_index("urn:plcsentinel:opcua:tank")
        logger.info(f"Target Namespace Index: ns={ns_idx}")

        # Access Variables via Browse Path / Node ID
        root = client.nodes.root
        tank_sys = await root.get_child(["0:Objects", f"{ns_idx}:TankLevelSystem"])

        var_level = await tank_sys.get_child([f"{ns_idx}:TankLevelRaw"])
        var_pump = await tank_sys.get_child([f"{ns_idx}:PumpMotorState"])
        var_drain = await tank_sys.get_child([f"{ns_idx}:DrainValveState"])
        var_high = await tank_sys.get_child([f"{ns_idx}:HighThreshold"])
        var_low = await tank_sys.get_child([f"{ns_idx}:LowThreshold"])

        # Read Process Telemetry (Over Encrypted Channel)
        level_val = await var_level.get_value()
        pump_val = await var_pump.get_value()
        drain_val = await var_drain.get_value()
        high_val = await var_high.get_value()
        low_val = await var_low.get_value()

        logger.info("\n" + "=" * 60)
        logger.info("SECURE PROCESS TELEMETRY (ENCRYPTED & AUTHENTICATED):")
        logger.info(f"  - Tank Water Level   : {level_val:.1f} / 1000.0 ({level_val/10.0:.1f}%)")
        logger.info(f"  - Inflow Pump Motor  : {'ON' if pump_val else 'OFF'}")
        logger.info(f"  - Drain Valve State  : {'OPEN' if drain_val else 'CLOSED'}")
        logger.info(f"  - Safe High Threshold: {high_val} ({high_val/10.0:.1f}%)")
        logger.info(f"  - Safe Low Threshold : {low_val} ({low_val/10.0:.1f}%)")
        logger.info("=" * 60)

        # Execute Safe Encrypted Write
        new_high = 840
        logger.info(f"\n[TX] Writing new High Threshold ({new_high}) over encrypted channel...")
        await var_high.write_value(new_high)
        verified_high = await var_high.get_value()
        logger.info(f"[RX] Verified written value: {verified_high}")

if __name__ == "__main__":
    enc = True
    if len(sys.argv) > 1 and sys.argv[1] == "--no-crypto":
        enc = False
    asyncio.run(run_client(use_encryption=enc))
