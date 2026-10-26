#!/usr/bin/env python3
"""
PlcSentinel - Live test of the certificate-identity path through both gateways

Runs on the host, whose address (127.0.0.1) is NOT an authorized station, and
proves that the engineering-workstation certificate alone authorizes writes:
- Modbus/TCP Security (port 802): pymodbus TLS client with the EWS certificate;
  an in-range setpoint write is forwarded and read back, an out-of-range one is
  still refused with Exception 0x03, and plain Modbus from the same host stays blocked.
- S7comm (port 10202): snap7 through ews_tls_tunnel.py; a DB1 write is forwarded
  and read back.
Needs `make docker-up` (the gateway-pki service populates certs/).

    make test-identity
"""

import sys
import logging
from pymodbus.client import ModbusTcpClient, ModbusTlsClient

import dpi_tls
from ews_tls_tunnel import Tunnel
from s7_sentinel import S7Sentinel

# force: s7_sentinel configures logging on import, which would otherwise win.
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [IDENTITY-TESTER] %(message)s", force=True)
logger = logging.getLogger("IdentityTester")

CERT, KEY, CA = "certs/ews_cert.pem", "certs/ews_key.pem", "certs/gateway_ca_cert.pem"


def run_tests():
    failures = 0
    ctx = dpi_tls.client_context(CERT, KEY, CA)

    logger.info("=== STEP 1: MODBUS/TCP SECURITY (PORT 802) WITH THE EWS CERTIFICATE FROM AN UNTRUSTED ADDRESS ===")
    # pymodbus wraps the socket without a server_hostname, so SAN binding is off for this client only.
    tls = ModbusTlsClient("127.0.0.1", port=802, sslctx=dpi_tls.client_context(CERT, KEY, CA, check_hostname=False))
    if not tls.connect():
        logger.error("[FAIL] Cannot establish a mutual-TLS Modbus session on 127.0.0.1:802")
        return False
    try:
        res = tls.write_register(address=0, value=830, device_id=1)
        back = tls.read_holding_registers(address=0, count=1, device_id=1)
        if res.isError() or back.isError() or back.registers[0] != 830:
            logger.error(f"[FAIL] Certificate-authorized write not forwarded: write={res} read={back}")
            failures += 1
        else:
            logger.info("[PASS] reg0=830 forwarded on certificate identity alone and read back")
        bad = tls.write_register(address=0, value=9999, device_id=1)
        if bad.isError() and getattr(bad, "exception_code", None) == 3:
            logger.info("[SUCCESS - MITIGATED] reg0=9999 still rejected with Exception 0x03 over TLS")
        else:
            logger.error(f"[FAIL] Boundary not enforced over TLS: {bad}")
            failures += 1
        tls.write_register(address=0, value=850, device_id=1)   # restore baseline
    finally:
        tls.close()

    logger.info("\n=== STEP 2: PLAIN MODBUS FROM THE SAME HOST (PORT 5020) STAYS REFUSED ===")
    plain = ModbusTcpClient("127.0.0.1", port=5020)
    if not plain.connect():
        logger.error("[FAIL] Cannot reach the plain Modbus listener on 127.0.0.1:5020")
        return False
    try:
        res = plain.write_register(address=0, value=850, device_id=1)
    finally:
        plain.close()
    if res.isError():
        logger.info("[SUCCESS - MITIGATED] Same host without a certificate is still denied writes")
    else:
        logger.error("[FAIL] Plain write from an untrusted address was forwarded")
        failures += 1

    logger.info("\n=== STEP 3: S7COMM THROUGH THE EWS TLS TUNNEL (PORT 10202) ===")
    tunnel = Tunnel(("127.0.0.1", 0), ("127.0.0.1", 10202), ctx)
    tunnel.start()
    sentinel = S7Sentinel(ip="127.0.0.1", tcp_port=tunnel.port)
    if not sentinel.connect():
        logger.error("[FAIL] Cannot reach the S7 gateway through the tunnel")
        return False
    try:
        if sentinel.write_safe_setpoint(db_number=1, byte_offset=0, new_value=830):
            logger.info("[PASS] DB1.DBW0=830 forwarded through the TLS tunnel on certificate identity and read back")
        else:
            logger.error("[FAIL] S7 write through the tunnel was not forwarded or did not verify")
            failures += 1
        sentinel.write_safe_setpoint(db_number=1, byte_offset=0, new_value=850)   # restore baseline
    finally:
        sentinel.disconnect()

    logger.info("\n" + "=" * 65)
    if failures == 0:
        logger.info("AUDIT VERDICT: CERTIFICATE IDENTITY AUTHORIZES; ADDRESS ALONE DOES NOT.")
    else:
        logger.error(f"AUDIT VERDICT: {failures} CHECK(S) FAILED. IDENTITY PATH BROKEN.")
    logger.info("=" * 65)
    return failures == 0


if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)
