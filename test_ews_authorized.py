#!/usr/bin/env python3
"""
PlcSentinel - Authorized Engineering Workstation (EWS) Path Test

Runs from the EWS host (192.168.1.50, the one address the DPI gateways trust
for writes) and proves the ALLOW side of the conduit policy end to end:
- Modbus: an in-range setpoint write is forwarded and read back; an
  out-of-range write is still answered with Exception 0x03 even from the EWS.
- S7comm: a DB1 setpoint write is forwarded and read back.

    make test-ews          (executes this inside the ews container)
"""

import os
import sys
import logging
from pymodbus.client import ModbusTcpClient
from snap7.client import Client
from snap7.util import set_int
from s7_sentinel import S7Sentinel

MODBUS_PROXY = os.environ.get("MODBUS_PROXY", "192.168.1.100")
S7_PROXY = os.environ.get("S7_PROXY", "192.168.1.101")

# force: s7_sentinel configures logging on import, which would otherwise win.
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [EWS-TESTER] %(message)s", force=True)
logger = logging.getLogger("EWSTester")


def run_tests():
    failures = 0

    logger.info("=== STEP 1: AUTHORIZED MODBUS SETPOINT WRITES VIA DPI PROXY (PORT 5020) ===")
    client = ModbusTcpClient(MODBUS_PROXY, port=5020)
    if not client.connect():
        logger.error(f"[FAIL] Cannot reach Modbus DPI proxy at {MODBUS_PROXY}:5020")
        return False
    try:
        for value, expect_allowed in ((840, True), (9999, False), (850, True)):
            res = client.write_register(address=0, value=value, device_id=1)
            if res.isError() == expect_allowed:
                logger.error(f"[FAIL] reg0={value}: expected {'allowed' if expect_allowed else 'blocked'}, got {res}")
                failures += 1
            elif expect_allowed:
                back = client.read_holding_registers(address=0, count=1, device_id=1).registers[0]
                if back == value:
                    logger.info(f"[PASS] reg0={value} forwarded to the PLC and read back")
                else:
                    logger.error(f"[FAIL] reg0={value} accepted but PLC reads {back}")
                    failures += 1
            elif getattr(res, "exception_code", None) == 3:
                logger.info(f"[SUCCESS - MITIGATED] reg0={value} rejected with Exception 0x03 even from the EWS")
            else:
                logger.error(f"[FAIL] reg0={value}: expected Exception 0x03, got {res}")
                failures += 1
    finally:
        client.close()

    logger.info("\n=== STEP 2: AUTHORIZED S7COMM DB WRITE VIA DPI PROXY (PORT 10200) ===")
    sentinel = S7Sentinel(ip=S7_PROXY, tcp_port=10200)
    if not sentinel.connect():
        logger.error(f"[FAIL] Cannot reach S7 DPI proxy at {S7_PROXY}:10200")
        return False
    try:
        if sentinel.write_safe_setpoint(db_number=1, byte_offset=0, new_value=820):
            logger.info("[PASS] DB1.DBW0=820 forwarded to the controller and read back")
        else:
            logger.error("[FAIL] Authorized S7 write was not forwarded or did not verify")
            failures += 1
        sentinel.write_safe_setpoint(db_number=1, byte_offset=0, new_value=850)  # restore baseline
    finally:
        sentinel.disconnect()

    logger.info("\n=== STEP 3: EWS WRITE OUTSIDE THE SAFE RANGE (DB1.DBW0 = 9999) IS STILL REFUSED ===")
    raw = Client()
    try:
        raw.connect(S7_PROXY, 0, 1, tcp_port=10200)
        buf = bytearray(2)
        set_int(buf, 0, 9999)
        raw.db_write(1, 0, buf)
        logger.error("[FAIL] Gateway forwarded an out-of-range setpoint from the EWS")
        failures += 1
    except Exception as e:
        logger.info(f"[SUCCESS - MITIGATED] Out-of-range EWS write refused and session closed ({e})")
    finally:
        try:
            raw.disconnect()
        except Exception:
            pass

    logger.info("\n" + "=" * 65)
    if failures == 0:
        logger.info("AUDIT VERDICT: AUTHORIZED EWS WRITES FORWARDED; BOUNDARY STILL ENFORCED.")
    else:
        logger.error(f"AUDIT VERDICT: {failures} CHECK(S) FAILED. AUTHORIZED PATH BROKEN.")
    logger.info("=" * 65)
    return failures == 0


if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)
