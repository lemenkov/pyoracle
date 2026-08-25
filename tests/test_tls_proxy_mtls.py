# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Mutual-TLS proxy + committed wallet fixture (#127, phase 2).

Offline end-to-end proof that the pieces fit before the client is wired up
(phase 3): a plaintext echo backend behind the mTLS-enabled `TLSProxy`, driven
by a raw ssl client whose identity comes from the committed wallet fixture via
`open_wallet()`. This is exactly the trust setup the seerdb client will assemble
in phase 3, exercised here without touching the connection code.
"""

import os
import socket
import ssl
import tempfile
import threading
import unittest

import _tls_proxy
from _tls_proxy import TLSProxy

from seerdb.client.wallet import open_wallet

WALLET_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'wallet')
CA_CERT = os.path.join(WALLET_DIR, 'ca_cert.pem')
SERVER_CERT = os.path.join(WALLET_DIR, 'server_cert.pem')
SERVER_KEY = os.path.join(WALLET_DIR, 'server_key.pem')


class _EchoServer:
    """A trivial plaintext TCP server that echoes whatever it receives."""

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
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        with conn:
            while True:
                buf = conn.recv(4096)
                if not buf:
                    break
                conn.sendall(buf)

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            # Best-effort: the listening socket may already be closed.
            pass
        self._thread.join(timeout=2)


def _client_context(WithCert: bool) -> ssl.SSLContext:
    """Build the client SSLContext the way phase 3 will — trust the wallet CA,
    and (optionally) present the wallet's client identity."""
    Wallet = open_wallet(WALLET_DIR)
    Ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    Ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # The server cert's CN is seerdb-test-server, not the connect host, so DN
    # matching (phase 3) replaces stdlib hostname verification.
    Ctx.check_hostname = False
    Ctx.verify_mode = ssl.CERT_REQUIRED
    Ctx.load_verify_locations(cadata=Wallet.identity.ca_pem.decode())
    if WithCert:
        # load_cert_chain needs a file; the wallet identity is in-memory.
        Fd, Path = tempfile.mkstemp(suffix='.pem')
        try:
            os.write(Fd, Wallet.identity.cert_key_pem)
            os.close(Fd)
            Ctx.load_cert_chain(Path)
        finally:
            os.unlink(Path)
    return Ctx


class TestMutualTLSProxy(unittest.TestCase):
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

    def _roundtrip(self, Ctx: ssl.SSLContext, Payload: bytes) -> bytes:
        Raw = socket.create_connection(('127.0.0.1', self.proxy.listen_port))
        with Ctx.wrap_socket(Raw, server_hostname='localhost') as Tls:
            Tls.sendall(Payload)
            return Tls.recv(len(Payload))

    def test_client_cert_accepted_and_echoes(self):
        Reply = self._roundtrip(_client_context(WithCert=True), b'ping-mtls')
        self.assertEqual(Reply, b'ping-mtls')
        # The proxy must have verified and recorded our wallet identity.
        self.assertIn('CN=seerdb-test-client', self.proxy.client_dns)

    def test_server_cert_trusted_via_wallet_ca(self):
        # A clean handshake at all proves the wallet CA anchored the proxy's
        # server certificate (self-signed would raise here).
        Reply = self._roundtrip(_client_context(WithCert=True), b'x')
        self.assertEqual(Reply, b'x')

    def test_missing_client_cert_rejected(self):
        # No client identity presented: the proxy demands one, so the handshake
        # must fail rather than reach the echo backend.
        with self.assertRaises((ssl.SSLError, OSError)):
            self._roundtrip(_client_context(WithCert=False), b'nope')
        self.assertNotIn('CN=seerdb-test-client', self.proxy.client_dns)


class TestFormatSubject(unittest.TestCase):
    def test_none_cert(self):
        self.assertIsNone(_tls_proxy._format_subject(None))
        self.assertIsNone(_tls_proxy._format_subject({}))

    def test_multi_rdn(self):
        Cert = {
            'subject': (
                (('commonName', 'host'),),
                (('organizationName', 'Acme'),),
                (('countryName', 'US'),),
            )
        }
        self.assertEqual(_tls_proxy._format_subject(Cert), 'CN=host, O=Acme, C=US')


if __name__ == '__main__':
    unittest.main()
