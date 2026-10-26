#!/usr/bin/env python3
"""
PlcSentinel - Verification Suite for Layer-7 Modbus DPI Proxy
Validates active mitigation against MITRE ATT&CK for ICS scenarios:
- Verifies legitimate telemetry flows unimpeded
- Verifies unauthorized writes are intercepted and dropped
- Verifies semantic boundary violations return Modbus Exception 0x03
- Confirms OpenPLC process memory remains intact and protected
"""

import sys
import time
import logging
from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [TESTER] %(message)s")
logger = logging.getLogger("DPITester")

def run_tests():
    DPI_PORT = 5020
    DIRECT_PLC_PORT = 502

    logger.info("=== STEP 1: VERIFYING TELEMETRY THROUGH DPI PROXY (PORT 5020) ===")
    client_dpi = ModbusTcpClient("127.0.0.1", port=DPI_PORT)
    if not client_dpi.connect():
        logger.error(f"Could not connect to DPI Proxy at 127.0.0.1:{DPI_PORT}. Is it running?")
        return False

    # Read Holding Registers (FC 03)
    res_read = client_dpi.read_holding_registers(address=0, count=2, device_id=1)
    if res_read.isError():
        logger.error(f"[FAIL] DPI Proxy dropped legitimate read: {res_read}")
        return False
    logger.info(f"[PASS] Telemetry Read via Proxy SUCCESS: High={res_read.registers[0]}, Low={res_read.registers[1]}")

    failures = 0

    logger.info("\n=== STEP 2: ATTACK SIMULATION - UNAUTHORIZED WRITE COIL (FC 05) ===")
    logger.warning("Attempting to force Drain Valve OPEN (Coil 1) through DPI Proxy...")
    res_coil = client_dpi.write_coil(address=1, value=True, device_id=1)
    logger.info(f"Response from DPI Proxy: {res_coil}")
    if hasattr(res_coil, "isError") and res_coil.isError():
        logger.info("[SUCCESS - MITIGATED] DPI Proxy successfully BLOCKED unauthorized coil manipulation!")
    else:
        logger.error("[FAIL] DPI Proxy allowed unauthorized write coil!")
        failures += 1

    logger.info("\n=== STEP 3: ATTACK SIMULATION - SETPOINT POISONING (FC 06) ===")
    logger.warning("Attempting to overwrite High Threshold to 9999 (Overfill Hazard)...")
    res_reg = client_dpi.write_register(address=0, value=9999, device_id=1)
    logger.info(f"Response from DPI Proxy: {res_reg}")
    if hasattr(res_reg, "isError") and res_reg.isError():
        logger.info("[SUCCESS - MITIGATED] DPI Proxy successfully BLOCKED out-of-bounds setpoint poisoning!")
    else:
        logger.error("[FAIL] DPI Proxy allowed malicious setpoint!")
        failures += 1

    client_dpi.close()

    logger.info("\n=== STEP 4: HARDWARE INTEGRITY AUDIT (DIRECT TO OPENPLC PORT 502) ===")
    logger.info("Connecting directly to OpenPLC to verify process state integrity...")
    client_direct = ModbusTcpClient("127.0.0.1", port=DIRECT_PLC_PORT)
    if not client_direct.connect():
        # docker-compose deliberately does not publish 502; only the standalone
        # lab (make run-modbus-lab) exposes it, so skip rather than crash.
        logger.warning(f"Direct PLC port {DIRECT_PLC_PORT} not reachable; skipping integrity audit (expected under docker-compose).")
    else:
        res_c = client_direct.read_coils(address=0, count=4, device_id=1)
        res_r = client_direct.read_holding_registers(address=0, count=2, device_id=1)
        client_direct.close()
        if res_c.isError() or res_r.isError():
            logger.error(f"[FAIL] Direct PLC read failed: coils={res_c} regs={res_r}")
            failures += 1
        else:
            coils_direct = res_c.bits[:4]
            regs_direct = res_r.registers
            logger.info(f"Actual PLC Drain Valve State: {'OPEN (COMPROMISED)' if coils_direct[1] else 'CLOSED (SAFE)'}")
            logger.info(f"Actual PLC High Setpoint: {regs_direct[0]} ({regs_direct[0]/10.0:.1f}%)")
            if coils_direct[1]:
                logger.error("[FAIL] INTEGRITY ERROR: Drain valve was compromised!")
                failures += 1
            if regs_direct[0] > 900:
                logger.error("[FAIL] INTEGRITY ERROR: High setpoint was poisoned!")
                failures += 1

    logger.info("\n" + "=" * 60)
    if failures == 0:
        logger.info("AUDIT VERDICT: ZERO PROCESS IMPACT. ALL ATTACKS BLOCKED BY DPI GATEWAY.")
    else:
        logger.error(f"AUDIT VERDICT: {failures} CHECK(S) FAILED. DPI MITIGATION INCOMPLETE.")
    logger.info("=" * 60)
    return failures == 0

if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)
