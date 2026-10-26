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
import tempfile
import threading
import unittest

import dpi_tls
from generate_gateway_certs import make_gateway_pki


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


if __name__ == "__main__":
    unittest.main()
