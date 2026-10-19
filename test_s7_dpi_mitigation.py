#!/usr/bin/env python3
"""
PlcSentinel - Test Suite for S7comm Layer-7 DPI Proxy
Validates active mitigation of:
- Allowed: Read DB telemetry (FC 0x04)
- Blocked: Unauthorized Write to DB1 (FC 0x05)
- Blocked: Unauthorized CPU Stop Command (FC 0x29)
"""

import sys
import time
import socket
import logging
from snap7.client import Client
from snap7.util import get_int, set_int

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [S7-TESTER] %(message)s")
logger = logging.getLogger("S7DPITester")

def run_tests():
    DPI_PORT = 10200
    failures = 0

    logger.info("=== STEP 1: VERIFYING TELEMETRY READ VIA S7 DPI PROXY (PORT 1020) ===")
    client = Client()
    try:
        client.connect("127.0.0.1", 0, 1, tcp_port=DPI_PORT)
        if client.get_connected():
            data = client.db_read(1, 0, 4)
            val = get_int(data, 0)
            logger.info(f"[PASS] Successfully read DB1.DBW0 through S7 DPI Proxy: {val}")
        else:
            logger.error("[FAIL] Could not connect to S7 DPI Proxy.")
            return False
    except Exception as e:
        logger.error(f"[FAIL] Read error: {e}")
        return False
    finally:
        client.disconnect()

    logger.info("\n=== STEP 2: ATTACK SIMULATION - UNAUTHORIZED WRITE TO DB1 (FC 0x05) ===")
    logger.warning("Attempting unauthorized write to DB1.DBW0 via S7 DPI Proxy...")
    client = Client()
    try:
        client.connect("127.0.0.1", 0, 1, tcp_port=DPI_PORT)
        buf = bytearray(2)
        set_int(buf, 0, 999)
        # Attempt to write to DB1
        client.db_write(1, 0, buf)
        logger.error("[FAIL] DPI Proxy permitted unauthorized write to DB1!")
        failures += 1
    except Exception as e:
        logger.info(f"[SUCCESS - MITIGATED] DPI Proxy dropped connection on unauthorized write! ({e})")
    finally:
        try:
            client.disconnect()
        except Exception:
            pass

    logger.info("\n=== STEP 3: ATTACK SIMULATION - S7COMM CPU STOP INJECTION (FC 0x29) ===")
    logger.warning("Injecting raw S7comm CPU Stop command (0x29) into DPI Proxy...")
    # Raw TPKT + COTP + S7comm CPU Stop packet:
    # TPKT: 03 00 00 21 (Len 33)
    # COTP: 02 f0 80 (Data TPDU)
    # S7: 32 01 00 00 00 01 00 05 00 00 (Header, Type=1 Job, ParamLen=5, DataLen=0)
    # Parameter: 29 00 00 00 00 (Function 0x29: CPU Stop)
    # Data: (P_PROGRAM string)
    stop_pdu = (
        b"\x03\x00\x00\x21"  # TPKT Header
        b"\x02\xf0\x80"      # COTP DT
        b"\x32\x01\x00\x00\x00\x01\x00\x05\x00\x00"  # S7 Header (FC 0x29 Job)
        b"\x29\x00\x00\x00\x00"                      # Param: Function 0x29 (CPU Stop)
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # Padding
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", DPI_PORT))
        s.sendall(stop_pdu)
        time.sleep(0.1)
        resp = s.recv(1024)
        if not resp:
            logger.info("[SUCCESS - MITIGATED] DPI Proxy dropped socket on CPU Stop attempt!")
        else:
            logger.error(f"[FAIL] DPI Proxy forwarded/answered a CPU Stop command! (resp={resp!r})")
            failures += 1
        s.close()
    except Exception as e:
        logger.info(f"[SUCCESS - MITIGATED] Connection severed by DPI Proxy on CPU Stop! ({e})")

    logger.info("\n" + "=" * 65)
    if failures == 0:
        logger.info("AUDIT VERDICT: ALL DANGEROUS S7COMM COMMANDS BLOCKED BY DPI CONDUIT.")
    else:
        logger.error(f"AUDIT VERDICT: {failures} CHECK(S) FAILED. S7 DPI MITIGATION INCOMPLETE.")
    logger.info("=" * 65)
    return failures == 0

if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)
