#!/usr/bin/env python3
"""
PlcSentinel - Live test of the IEC 104 gateway against the mock outstation.

Runs from the host (127.0.0.1, not an authorized station) and proves:
- STARTDT handshake is forwarded and confirmed by the outstation (monitoring open);
- a single command (C_SC_NA_1, type 45) from the unauthorized host is dropped;
- a set-point to the protected object outside its range is dropped.
Needs `make docker-up` (gateway on 2404 -> mock on 24040).

    make test-iec104
"""

import sys
import socket
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [IEC104-TESTER] %(message)s")
logger = logging.getLogger("IEC104Tester")

GATEWAY = ("127.0.0.1", 2404)
STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])


def apci(cf1, asdu=b""):
    body = bytes([cf1, 0, 0, 0]) + asdu
    return bytes([0x68, len(body)]) + body


def single_command():
    asdu = bytes([45, 1, 6, 0]) + (1).to_bytes(2, "little") + b"\x05\x00\x00\x01"
    return apci(0x00, asdu)


def out_of_range_setpoint():
    asdu = bytes([49, 1, 6, 0]) + (1).to_bytes(2, "little") + (100).to_bytes(3, "little") + (9999).to_bytes(2, "little", signed=True) + b"\x00"
    return apci(0x00, asdu)


def run_tests():
    failures = 0

    logger.info("=== STEP 1: STARTDT HANDSHAKE IS FORWARDED (MONITORING OPEN) ===")
    try:
        s = socket.create_connection(GATEWAY, timeout=3)
        s.settimeout(3)
        s.sendall(STARTDT_ACT)
        resp = s.recv(16)
        s.close()
        if resp[:3] == bytes([0x68, 0x04, 0x0B]):
            logger.info("[PASS] Outstation confirmed STARTDT through the gateway")
        else:
            logger.error(f"[FAIL] Unexpected STARTDT reply: {resp!r}")
            failures += 1
    except Exception as e:
        logger.error(f"[FAIL] Cannot reach IEC 104 gateway on 127.0.0.1:2404 ({e})")
        return False

    for label, apdu in [("UNAUTHORIZED SINGLE COMMAND (type 45)", single_command()),
                        ("OUT-OF-RANGE SET-POINT (CA1/IOA100 = 9999)", out_of_range_setpoint())]:
        logger.info(f"\n=== STEP: {label} IS DROPPED ===")
        try:
            s = socket.create_connection(GATEWAY, timeout=3)
            s.settimeout(3)
            s.sendall(STARTDT_ACT)
            s.recv(16)
            s.sendall(apdu)
            tail = s.recv(16)
            s.close()
            if tail == b"":
                logger.info("[SUCCESS - MITIGATED] Gateway dropped the session on the control command")
            else:
                logger.error(f"[FAIL] Gateway forwarded/answered a control command (resp={tail!r})")
                failures += 1
        except (ConnectionResetError, socket.timeout) as e:
            logger.info(f"[SUCCESS - MITIGATED] Session severed by the gateway ({e})")

    logger.info("\n" + "=" * 65)
    if failures == 0:
        logger.info("AUDIT VERDICT: IEC 104 MONITORING OPEN; CONTROL COMMANDS BLOCKED AT THE CONDUIT.")
    else:
        logger.error(f"AUDIT VERDICT: {failures} CHECK(S) FAILED.")
    logger.info("=" * 65)
    return failures == 0


if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)
