#!/usr/bin/env python3
"""
PlcSentinel - Offline unit tests for both Layer-7 DPI policy engines.

Runs with no PLC, proxy or third-party package (the proxies are stdlib-only):
    python3 -m unittest -v test_dpi_policy

Unlike test_dpi_firewall.py / test_s7_dpi_mitigation.py (which always connect
from 127.0.0.1 and are therefore stopped by the source-IP ACL), these tests
drive the inspection code directly and exercise the authorized-EWS path, the
semantic setpoint boundary and the bulk-write (FC16) scan.
"""

import os
import socket
import tempfile
import unittest

from modbus_dpi_proxy import ModbusDPIProxy, EXC_ILLEGAL_FUNCTION, EXC_ILLEGAL_DATA_VALUE
from s7_dpi_proxy import S7DPIProxy, S7PacketParser

EWS = "192.168.1.50"
ATTACKER = "10.0.0.9"


def adu(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr.replace(" ", ""))


def s7_job(param: bytes) -> bytes:
    """Wrap an S7comm Job parameter block in S7 header + COTP DT + TPKT."""
    s7hdr = bytes([0x32, 0x01, 0, 0, 0, 1]) + len(param).to_bytes(2, "big") + b"\x00\x00"
    body = b"\x02\xf0\x80" + s7hdr + param
    return b"\x03\x00" + (len(body) + 4).to_bytes(2, "big") + body


def s7any_item(db: int, area: int = 0x84) -> bytes:
    return bytes([0x12, 0x0A, 0x10, 0x02, 0x00, 0x01]) + db.to_bytes(2, "big") + bytes([area]) + b"\x00\x00\x00"


class ModbusPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proxy = ModbusDPIProxy(authorized_ews_ip=EWS, log_file=os.path.join(self.tmp.name, "m.jsonl"))

    def tearDown(self):
        self.tmp.cleanup()

    def inspect(self, hexstr, ip):
        return self.proxy.inspect_request(adu(hexstr), ip, 1)

    def test_read_allowed_from_anyone(self):
        ok, resp, _ = self.inspect("0001 0000 0006 01 03 0000 0002", ATTACKER)
        self.assertTrue(ok); self.assertIsNone(resp)

    def test_unauthorized_write_gets_illegal_function(self):
        ok, resp, _ = self.inspect("0002 0000 0006 01 06 0000 01F4", ATTACKER)
        self.assertFalse(ok)
        self.assertEqual(resp[7:9], bytes([0x86, EXC_ILLEGAL_FUNCTION]))

    def test_authorized_in_range_write_allowed(self):
        ok, _, _ = self.inspect("0003 0000 0006 01 06 0000 01F4", EWS)
        self.assertTrue(ok)

    def test_boundary_900_allowed_901_blocked(self):
        self.assertTrue(self.inspect("0004 0000 0006 01 06 0000 0384", EWS)[0])
        ok, resp, _ = self.inspect("0005 0000 0006 01 06 0000 0385", EWS)
        self.assertFalse(ok)
        self.assertEqual(resp[7:9], bytes([0x86, EXC_ILLEGAL_DATA_VALUE]))

    def test_low_setpoint_register_also_bounded(self):
        self.assertFalse(self.inspect("0006 0000 0006 01 06 0001 270F", EWS)[0])

    def test_fc16_bulk_write_covering_setpoint_blocked(self):
        # start 0, qty 2, bytecount 4: reg0=500 (ok), reg1=9999 (hazard)
        ok, resp, _ = self.inspect("0007 0000 000B 01 10 0000 0002 04 01F4 270F", EWS)
        self.assertFalse(ok)
        self.assertEqual(resp[7:9], bytes([0x90, EXC_ILLEGAL_DATA_VALUE]))

    def test_fc16_bulk_write_elsewhere_allowed(self):
        self.assertTrue(self.inspect("0008 0000 0009 01 10 0005 0001 02 270F", EWS)[0])

    def test_stream_framing_pipelined_and_partial(self):
        """Two ADUs in one recv (read + unauthorized write) plus a partial tail."""
        client, client_peer = socket.socketpair()
        backend, backend_peer = socket.socketpair()
        try:
            read = adu("0001 0000 0006 01 03 0000 0002")
            write = adu("0002 0000 0006 01 06 0000 270F")
            partial = adu("0003 0000 0006 01")
            rest = self.proxy._process_client_stream(read + write + partial, client_peer, backend_peer, ATTACKER, 1)
            self.assertEqual(rest, partial)
            backend.settimeout(1); client.settimeout(1)
            self.assertEqual(backend.recv(1024), read)           # only the read reached the PLC
            self.assertEqual(client.recv(1024)[7:9], bytes([0x86, EXC_ILLEGAL_FUNCTION]))
            self.assertIsNone(self.proxy._process_client_stream(adu("0004 0000 0001"), client_peer, backend_peer, ATTACKER, 1))
        finally:
            for s in (client, client_peer, backend, backend_peer):
                s.close()


class S7PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proxy = S7DPIProxy(authorized_ews_ip=EWS, log_file=os.path.join(self.tmp.name, "s.jsonl"))

    def tearDown(self):
        self.tmp.cleanup()

    def policy(self, frame, ip):
        parsed = S7PacketParser.dissect(frame)
        self.assertIsNotNone(parsed)
        return self.proxy.evaluate_policy(parsed, ip, 1)[0]

    def test_cpu_stop_blocked_for_everyone(self):
        stop = s7_job(b"\x29\x00\x00\x00\x00")
        self.assertFalse(self.policy(stop, ATTACKER))
        self.assertFalse(self.policy(stop, EWS))

    def test_read_var_allowed_from_anyone(self):
        self.assertTrue(self.policy(s7_job(b"\x04\x01" + s7any_item(1)), ATTACKER))

    def test_write_any_db_default_denied_for_non_ews(self):
        for db in (1, 5, 99):
            self.assertFalse(self.policy(s7_job(b"\x05\x01" + s7any_item(db)), ATTACKER))
        self.assertFalse(self.policy(s7_job(b"\x05\x01" + s7any_item(0, area=0x83)), ATTACKER))  # markers

    def test_write_allowed_for_ews(self):
        self.assertTrue(self.policy(s7_job(b"\x05\x01" + s7any_item(5)), EWS))

    def test_download_upload_control_ews_only(self):
        for fc in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28):
            frame = s7_job(bytes([fc]))
            self.assertFalse(self.policy(frame, ATTACKER), f"fc 0x{fc:02X} should be blocked for non-EWS")
            self.assertTrue(self.policy(frame, EWS), f"fc 0x{fc:02X} should be allowed for EWS")

    def test_non_s7any_or_truncated_write_item_fails_closed(self):
        odd_syntax = s7_job(b"\x05\x01" + b"\x12\x0A\x11" + s7any_item(1)[3:])
        truncated = s7_job(b"\x05\x01" + s7any_item(1)[:6])
        self.assertIsNone(S7PacketParser.dissect(odd_syntax))
        self.assertIsNone(S7PacketParser.dissect(truncated))

    def test_cotp_connect_passes_through(self):
        cr = b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
        out, rest, reason = self.proxy._frame_client_stream(cr, ATTACKER, 1)
        self.assertEqual(out, cr); self.assertEqual(rest, b""); self.assertIsNone(reason)


if __name__ == "__main__":
    unittest.main()
