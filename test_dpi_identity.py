#!/usr/bin/env python3
"""
PlcSentinel - Tests for the mutual-TLS identity path of the DPI gateways.

Needs the cryptography package (to mint a throwaway lab PKI per test run):
    python3 -m unittest -v test_dpi_identity
"""

import os
import ssl
import json
import socket
import asyncio
import tempfile
import threading
import unittest

import dpi_tls
from generate_gateway_certs import make_gateway_pki
from modbus_dpi_proxy import ModbusDPIProxy, EXC_ILLEGAL_FUNCTION
from s7_dpi_proxy import S7DPIProxy
from ews_tls_tunnel import Tunnel

ATTACKER_IP = "127.0.0.1"   # the test client's address is deliberately NOT an authorized IP


class FakeController:
    """One-shot TCP backend: records the first ADU it receives and echoes it back."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.received = b""
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return          # listener closed before any client arrived
        with conn:
            conn.settimeout(3)
            try:
                self.received = conn.recv(4096)
                if self.received:
                    conn.sendall(self.received)
            except OSError:
                pass

    def close(self):
        self.sock.close()


class TlsHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pki = make_gateway_pki(cls.tmp.name, ews_cn="ews-01", sans=("127.0.0.1",))
        cls.server_ctx = dpi_tls.server_context(cls.pki["gateway"], cls.pki["gateway_key"], cls.pki["gateway_ca"])
        cls.rogue = tempfile.TemporaryDirectory()
        cls.rogue_pki = make_gateway_pki(cls.rogue.name, ews_cn="ews-01", sans=("127.0.0.1",))  # different CA

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        cls.rogue.cleanup()

    def handshake(self, client_ctx):
        """Run one mutual-TLS handshake; return (server-side principal, client error)."""
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        result = {}

        def serve():
            conn, _ = listener.accept()
            try:
                tls = self.server_ctx.wrap_socket(conn, server_side=True)
                result["principal"] = dpi_tls.peer_principal(tls.getpeercert())
                tls.close()
            except ssl.SSLError as e:
                result["server_error"] = e
            finally:
                conn.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        client_error = None
        try:
            with socket.create_connection(listener.getsockname(), timeout=3) as raw:
                with client_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                    tls.recv(1)
        except (ssl.SSLError, OSError) as e:
            client_error = e
        t.join(3)
        listener.close()
        return result.get("principal"), client_error

    def test_trusted_client_yields_cn_principal(self):
        ctx = dpi_tls.client_context(self.pki["ews"], self.pki["ews_key"], self.pki["gateway_ca"])
        principal, _ = self.handshake(ctx)
        self.assertEqual(principal, "cn:ews-01")

    def test_client_from_another_ca_is_rejected(self):
        ctx = dpi_tls.client_context(self.rogue_pki["ews"], self.rogue_pki["ews_key"], self.pki["gateway_ca"])
        principal, err = self.handshake(ctx)
        self.assertIsNone(principal)
        self.assertIsNotNone(err)

    def test_client_without_certificate_is_rejected(self):
        ctx = ssl.create_default_context(cafile=self.pki["gateway_ca"])
        principal, err = self.handshake(ctx)
        self.assertIsNone(principal)
        self.assertIsNotNone(err)

    def test_peer_principal_requires_common_name(self):
        self.assertIsNone(dpi_tls.peer_principal(None))
        self.assertIsNone(dpi_tls.peer_principal({"subject": ((("organizationName", "x"),),)}))
        self.assertEqual(dpi_tls.peer_principal({"subject": ((("commonName", "hmi-7"),),)}), "cn:hmi-7")


class ModbusTlsIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pki = make_gateway_pki(cls.tmp.name, ews_cn="ews-01", sans=("127.0.0.1",))
        cls.client_ctx = dpi_tls.client_context(cls.pki["ews"], cls.pki["ews_key"], cls.pki["gateway_ca"])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def gateway(self, identities, backend_port):
        proxy = ModbusDPIProxy(authorized_ews_ips=[], authorized_ews_identities=identities,
                               backend_host="127.0.0.1", backend_port=backend_port,
                               log_file=os.path.join(self.tmp.name, "tls.jsonl"), listen_host="127.0.0.1",
                               tls_port=0, tls_cert=self.pki["gateway"], tls_key=self.pki["gateway_key"], tls_ca=self.pki["gateway_ca"])
        listener = proxy._tls_listener(0)
        threading.Thread(target=proxy._tls_accept_loop, args=(listener,), daemon=True).start()
        return proxy, listener.getsockname()[1]

    def write_via_tls(self, port, adu):
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
            with self.client_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                tls.sendall(adu)
                return tls.recv(1024)

    def test_certificate_identity_authorizes_write_from_untrusted_ip(self):
        plc = FakeController()
        try:
            proxy, port = self.gateway(["ews-01"], plc.port)
            write = bytes.fromhex("0001 0000 0006 01 06 0000 0348".replace(" ", ""))   # reg0 = 840, in range
            self.assertEqual(self.write_via_tls(port, write), write)                     # controller's echo came back
            plc.thread.join(3)
            self.assertEqual(plc.received, write)                                      # forwarded in the clear to the PLC
        finally:
            plc.close()
        with open(os.path.join(self.tmp.name, "tls.jsonl"), encoding="utf-8") as f:
            event = json.loads(f.readlines()[-1])
        self.assertEqual((event["event"]["action"], event["user"]["name"], event["source"]["ip"]), ("allowed", "ews-01", ATTACKER_IP))

    def test_trusted_certificate_with_unlisted_cn_is_authenticated_but_not_authorized(self):
        plc = FakeController()
        try:
            proxy, port = self.gateway(["someone-else"], plc.port)
            write = bytes.fromhex("0002 0000 0006 01 06 0000 0348".replace(" ", ""))
            resp = self.write_via_tls(port, write)
            self.assertEqual(resp[7:9], bytes([0x86, EXC_ILLEGAL_FUNCTION]))          # synthetic exception from the gateway
            self.assertEqual(plc.received, b"")                                        # nothing reached the PLC
        finally:
            plc.close()


class S7TlsIdentityTests(unittest.TestCase):
    """S7comm has no native TLS: the gateway's TLS listener authorizes the certificate CN."""

    # Job: Write Var, one S7ANY item addressing DB1.DBW0 with a 2-byte data section (value 840).
    _PARAM = b"\x05\x01" + b"\x12\x0a\x10\x02\x00\x02\x00\x01\x84\x00\x00\x00"
    _DATA = b"\x00\x04\x00\x10\x03\x48"
    _BODY = (b"\x02\xf0\x80" + b"\x32\x01\x00\x00\x00\x01" + len(_PARAM).to_bytes(2, "big")
             + len(_DATA).to_bytes(2, "big") + _PARAM + _DATA)
    WRITE_DB1 = b"\x03\x00" + (len(_BODY) + 4).to_bytes(2, "big") + _BODY

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pki = make_gateway_pki(cls.tmp.name, ews_cn="ews-01", sans=("127.0.0.1",))
        cls.client_ctx = dpi_tls.client_context(cls.pki["ews"], cls.pki["ews_key"], cls.pki["gateway_ca"])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_session(self, identities, backend_port):
        proxy = S7DPIProxy(authorized_ews_ips=[], authorized_ews_identities=identities, listen_host="127.0.0.1",
                           backend_host="127.0.0.1", backend_port=backend_port, log_file=os.path.join(self.tmp.name, "s7tls.jsonl"),
                           tls_port=0, tls_cert=self.pki["gateway"], tls_key=self.pki["gateway_key"], tls_ca=self.pki["gateway_ca"])

        async def go():
            server = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0, ssl=proxy._tls_ctx)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=self.client_ctx, server_hostname="127.0.0.1")
            writer.write(self.WRITE_DB1)
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.read(1024), 3)
            except asyncio.TimeoutError:
                resp = None
            writer.close()
            server.close()
            await server.wait_closed()
            return resp
        return asyncio.run(go())

    def test_certificate_identity_authorizes_s7_write(self):
        plc = FakeController()
        try:
            resp = self.run_session(["ews-01"], plc.port)
            plc.thread.join(3)
            self.assertEqual((resp, plc.received), (self.WRITE_DB1, self.WRITE_DB1))
        finally:
            plc.close()

    def test_unlisted_cn_write_is_refused_and_session_closed(self):
        plc = FakeController()
        try:
            resp = self.run_session(["someone-else"], plc.port)
            self.assertEqual((resp, plc.received), (b"", b""))        # EOF from the gateway, nothing reached the PLC
        finally:
            plc.close()
        with open(os.path.join(self.tmp.name, "s7tls.jsonl"), encoding="utf-8") as f:
            event = json.loads(f.readlines()[-1])
        self.assertEqual((event["event"]["action"], event["user"]["name"]), ("blocked", "ews-01"))


class TunnelTests(unittest.TestCase):
    def test_plain_client_reaches_modbus_gateway_through_tunnel(self):
        tmp = tempfile.TemporaryDirectory()
        plc = FakeController()
        try:
            pki = make_gateway_pki(tmp.name, ews_cn="ews-01", sans=("127.0.0.1",))
            proxy = ModbusDPIProxy(authorized_ews_ips=[], authorized_ews_identities=["ews-01"], listen_host="127.0.0.1",
                                   backend_host="127.0.0.1", backend_port=plc.port, log_file=os.path.join(tmp.name, "t.jsonl"),
                                   tls_port=0, tls_cert=pki["gateway"], tls_key=pki["gateway_key"], tls_ca=pki["gateway_ca"])
            listener = proxy._tls_listener(0)
            threading.Thread(target=proxy._tls_accept_loop, args=(listener,), daemon=True).start()
            tunnel = Tunnel(("127.0.0.1", 0), ("127.0.0.1", listener.getsockname()[1]),
                            dpi_tls.client_context(pki["ews"], pki["ews_key"], pki["gateway_ca"]))
            tunnel.start()
            write = bytes.fromhex("0003 0000 0006 01 06 0001 00C8".replace(" ", ""))   # reg1 = 200, plain Modbus into the tunnel
            with socket.create_connection(("127.0.0.1", tunnel.port), timeout=3) as plain:
                plain.sendall(write)
                self.assertEqual(plain.recv(1024), write)
            plc.thread.join(3)
            self.assertEqual(plc.received, write)
        finally:
            plc.close()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
