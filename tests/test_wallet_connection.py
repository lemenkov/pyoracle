# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Wallet-based mutual TLS wired into the connection (#127, phase 3).

Two layers, all offline:
  * pure wiring — a wallet resolves into host/port/service + a client SSLContext,
    and the server-DN matcher behaves per SSL_SERVER_DN_MATCH;
  * live TLS — the connection's *real* TLS path (`_open_transport` /
    `_wrap_socket_tls`) is driven against the phase-2 mutual-TLS proxy fronting a
    plaintext echo backend, proving the wallet identity is presented and the
    server DN is enforced without needing a TNS-speaking Oracle server.
"""

import asyncio
import os
import socket
import ssl
import threading
import time
import unittest

from _tls_proxy import TLSProxy

from seerdb.client.aconnection import AsyncOracleConnect
from seerdb.client.connection import OracleConnect
from seerdb.client.wallet import build_client_context, open_wallet, server_dn_matches

WALLET_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'wallet')
CA_CERT = os.path.join(WALLET_DIR, 'ca_cert.pem')
SERVER_CERT = os.path.join(WALLET_DIR, 'server_cert.pem')
SERVER_KEY = os.path.join(WALLET_DIR, 'server_key.pem')
SERVER_DN = 'CN=seerdb-test-server'
CLIENT_DN = 'CN=seerdb-test-client'


class _EchoServer:
    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('127.0.0.1', 0))
        self._sock.listen(8)
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._drain, args=(conn,), daemon=True).start()

    @staticmethod
    def _drain(conn):
        with conn:
            while conn.recv(4096):
                pass

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            # Best-effort: the listening socket may already be closed.
            pass
        self._thread.join(timeout=2)


class TestServerDnMatch(unittest.TestCase):
    def _cert(self, *rdns):
        return {'subject': tuple(((name, value),) for (name, value) in rdns)}

    def test_cn_only_match(self):
        Cert = self._cert(('commonName', 'seerdb-test-server'))
        self.assertTrue(server_dn_matches('CN=seerdb-test-server', Cert))

    def test_order_insensitive_subset(self):
        Cert = self._cert(
            ('commonName', 'db'),
            ('organizationName', 'Oracle'),
            ('countryName', 'US'),
        )
        # Attribute order in the expected DN differs; all its RDNs are present.
        self.assertTrue(server_dn_matches('O=Oracle, CN=db', Cert))

    def test_mismatch_rejected(self):
        Cert = self._cert(('commonName', 'seerdb-test-server'))
        self.assertFalse(server_dn_matches('CN=someone-else', Cert))

    def test_extra_expected_component_rejected(self):
        Cert = self._cert(('commonName', 'db'))
        self.assertFalse(server_dn_matches('CN=db, O=Oracle', Cert))

    def test_empty_inputs(self):
        self.assertFalse(server_dn_matches('', self._cert(('commonName', 'x'))))
        self.assertFalse(server_dn_matches('CN=x', None))


class TestWalletWiring(unittest.TestCase):
    def test_dsn_populates_connection(self):
        Conn = OracleConnect(wallet_location=WALLET_DIR, dsn='seerdb_test')
        self.assertEqual(Conn.host, 'localhost')
        self.assertEqual(Conn.port, 1522)
        self.assertEqual(Conn.service_name, 'seerdb_test_svc')
        self.assertEqual(Conn._wallet_server_dn, SERVER_DN)
        self.assertIsInstance(Conn.ssl, ssl.SSLContext)

    def test_explicit_host_port_override_dsn(self):
        Conn = OracleConnect(
            host='10.0.0.9', port=9999, wallet_location=WALLET_DIR, dsn='seerdb_test'
        )
        # Explicit host/port win; the wallet still supplies the server DN.
        self.assertEqual(Conn.host, '10.0.0.9')
        self.assertEqual(Conn.port, 9999)
        self.assertEqual(Conn._wallet_server_dn, SERVER_DN)

    def test_wallet_without_dsn_sets_context_only(self):
        Conn = OracleConnect(wallet_location=WALLET_DIR)
        self.assertIsNone(Conn._wallet_server_dn)
        self.assertIsInstance(Conn.ssl, ssl.SSLContext)

    def test_build_client_context_shape(self):
        Ctx = build_client_context(open_wallet(WALLET_DIR))
        self.assertFalse(Ctx.check_hostname)
        self.assertEqual(Ctx.verify_mode, ssl.CERT_REQUIRED)


class TestLiveTlsPath(unittest.TestCase):
    def setUp(self):
        self.echo = _EchoServer()
        self.echo.start()
        self.proxy = TLSProxy(
            '127.0.0.1',
            self.echo.port,
            cert_path=SERVER_CERT,
            key_path=SERVER_KEY,
            client_ca_path=CA_CERT,
        )
        self.proxy.start()
        self.addCleanup(self.echo.stop)
        self.addCleanup(self.proxy.stop)

    def _wait_client_dn(self, dn: str, timeout: float = 2.0) -> bool:
        # The proxy records the verified client DN from its own worker thread,
        # just after its side of the handshake completes; poll rather than
        # assume it has landed the instant the client returns.
        Deadline = time.monotonic() + timeout
        while time.monotonic() < Deadline:
            if dn in self.proxy.client_dns:
                return True
            time.sleep(0.02)
        return False

    def test_sync_wallet_handshake_and_dn(self):
        Conn = OracleConnect(
            host='127.0.0.1',
            port=self.proxy.listen_port,
            wallet_location=WALLET_DIR,
            dsn='seerdb_test',
        )
        # Runs the real _wrap_socket_tls (mTLS + DN check), then sends CONNECT.
        Conn._open_transport()
        self.addCleanup(lambda: Conn.sock and Conn.sock.close())
        self.assertTrue(self._wait_client_dn(CLIENT_DN))

    def test_sync_wrong_server_dn_rejected(self):
        Conn = OracleConnect(
            host='127.0.0.1',
            port=self.proxy.listen_port,
            wallet_location=WALLET_DIR,
            dsn='seerdb_test',
        )
        Conn._wallet_server_dn = 'CN=not-the-server'
        with self.assertRaises(ssl.SSLError):
            Conn._open_transport()

    def test_async_wallet_handshake_and_dn(self):
        async def run():
            Conn = AsyncOracleConnect(
                host='127.0.0.1',
                port=self.proxy.listen_port,
                wallet_location=WALLET_DIR,
                dsn='seerdb_test',
            )
            await Conn._open_transport()
            if Conn._writer is not None:
                Conn._writer.close()

        asyncio.run(run())
        self.assertTrue(self._wait_client_dn(CLIENT_DN))

    def test_async_wrong_server_dn_rejected(self):
        async def run():
            Conn = AsyncOracleConnect(
                host='127.0.0.1',
                port=self.proxy.listen_port,
                wallet_location=WALLET_DIR,
                dsn='seerdb_test',
            )
            Conn._wallet_server_dn = 'CN=not-the-server'
            await Conn._open_transport()

        with self.assertRaises(ssl.SSLError):
            asyncio.run(run())


if __name__ == '__main__':
    unittest.main()
