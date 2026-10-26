#!/usr/bin/env python3
"""
PlcSentinel - Offline tests for the IEC 60870-5-104 DPI gateway.

    python3 -m unittest -v test_iec104
"""

import os
import json
import struct
import tempfile
import unittest

from plcsentinel.gateways import iec104_dpi_proxy
from plcsentinel.gateways.iec104_dpi_proxy import IEC104DPIProxy, IEC104Parser

EWS = "192.168.1.50"
ATTACKER = "10.0.0.9"


def apci(cf1, cf2=0, cf3=0, cf4=0, asdu=b""):
    body = bytes([cf1, cf2, cf3, cf4]) + asdu
    return bytes([0x68, len(body)]) + body


def i_frame(type_id, cot=6, ca=1, objects=b"", num=1, sq=0):
    asdu = bytes([type_id, (sq << 7) | num, cot & 0x3F, 0]) + ca.to_bytes(2, "little") + objects
    return apci(0x00, 0x00, 0x00, 0x00, asdu)   # SSN/RSN zero; irrelevant to policy


def setpoint(type_id, ioa, value):
    if type_id == 50:
        raw = struct.pack("<f", value)
    else:
        raw = int(value).to_bytes(2, "little", signed=True)
    return ioa.to_bytes(3, "little") + raw + b"\x00"   # value + qualifier octet


class IEC104PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proxy = IEC104DPIProxy(authorized_ews_ips=[EWS], protected_setpoints=[{"ca": 1, "ioa": 100, "min": 0, "max": 900}],
                                    log_file=os.path.join(self.tmp.name, "iec.jsonl"))

    def tearDown(self):
        self.tmp.cleanup()

    def allow(self, apdu, who):
        return self.proxy.evaluate_policy(IEC104Parser.dissect(apdu), who, 1)[0]

    def test_startdt_and_supervisory_frames_open(self):
        self.assertTrue(self.allow(apci(0x07), ATTACKER))   # STARTDT ACT (U-format)
        self.assertTrue(self.allow(apci(0x01), ATTACKER))   # S-format ack

    def test_monitoring_asdu_open(self):
        self.assertTrue(self.allow(i_frame(1, objects=b"\x01\x00\x00\x00"), ATTACKER))   # M_SP_NA_1 single point

    def test_single_command_requires_ews(self):
        cmd = i_frame(45, objects=b"\x05\x00\x00\x01")        # C_SC_NA_1
        self.assertFalse(self.allow(cmd, ATTACKER))
        self.assertTrue(self.allow(cmd, EWS))
        with open(os.path.join(self.tmp.name, "iec.jsonl"), encoding="utf-8") as f:
            self.assertEqual(json.loads(f.readline())["rule"]["mitre"]["id"], "T0855")

    def test_reset_process_refused_for_everyone(self):
        reset = i_frame(105, objects=b"\x00\x00\x00\x00")
        self.assertFalse(self.allow(reset, ATTACKER))
        self.assertFalse(self.allow(reset, EWS))
        with open(os.path.join(self.tmp.name, "iec.jsonl"), encoding="utf-8") as f:
            self.assertEqual(json.loads(f.readlines()[-1])["rule"]["mitre"]["id"], "T0806")

    def test_setpoint_bounds_apply_to_everyone(self):
        self.assertTrue(self.allow(i_frame(49, objects=setpoint(49, 100, 840)), EWS))     # in range
        self.assertFalse(self.allow(i_frame(49, objects=setpoint(49, 100, 9999)), EWS))   # scaled, out of range, even for EWS
        self.assertFalse(self.allow(i_frame(50, objects=setpoint(50, 100, 5000.0)), EWS)) # short float, out of range
        self.assertTrue(self.allow(i_frame(49, objects=setpoint(49, 200, 9999)), EWS))    # IOA 200 is not protected
        with open(os.path.join(self.tmp.name, "iec.jsonl"), encoding="utf-8") as f:
            self.assertEqual(json.loads(f.readlines()[-1])["rule"]["mitre"]["id"], "T0836")

    def test_framing_pipelined_and_blocked(self):
        startdt = apci(0x07)
        cmd = i_frame(45, objects=b"\x05\x00\x00\x01")
        out, rest, reason = self.proxy._frame_client_stream(startdt + cmd, ATTACKER, 1)
        self.assertEqual(out, startdt)                 # STARTDT forwarded, command stopped the stream
        self.assertIn("control command", reason)

    def test_malformed_apdu_fails_closed(self):
        out, rest, reason = self.proxy._frame_client_stream(b"\x00\x04\x07\x00\x00\x00", ATTACKER, 1)
        self.assertEqual((out, reason[:11]), (b"", "Non-IEC104 "))
        truncated_i = apci(0x00, 0x00, 0x00, 0x00, bytes([45, 1]))   # I-frame without a full ASDU header
        self.assertIsNone(IEC104Parser.dissect(truncated_i))

    def test_monitor_mode_forwards_and_logs_detected(self):
        proxy = IEC104DPIProxy(authorized_ews_ips=[EWS], log_file=os.path.join(self.tmp.name, "m.jsonl"), enforce=False)
        cmd = i_frame(45, objects=b"\x05\x00\x00\x01")
        out, rest, reason = proxy._frame_client_stream(cmd, ATTACKER, 1)
        self.assertEqual((out, rest, reason), (cmd, b"", None))
        with open(os.path.join(self.tmp.name, "m.jsonl"), encoding="utf-8") as f:
            self.assertEqual(json.loads(f.readline())["event"]["action"], "detected")

    def test_shipped_policy_file_matches_defaults(self):
        pol = iec104_dpi_proxy.load_policy("config/iec104_policy.json")
        self.assertEqual(pol["authorized_ews_identities"], ["ews-01"])
        self.assertEqual(pol["protected_setpoints"], [{"ca": 1, "ioa": 100, "min": 0.0, "max": 900.0}])
        with self.assertRaises(SystemExit):
            iec104_dpi_proxy.load_policy(self.tmp.name)            # a directory, not a file


if __name__ == "__main__":
    unittest.main()
