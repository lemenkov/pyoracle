# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""End-to-end wallet mutual TLS over a real TNS round-trip (#127, phase 4).

The full stack, entirely offline and with no live Oracle:

    seerdb client ── wallet mTLS ──▶ TLSProxy ── plaintext TNS ──▶ Mirror server

The in-process Mirror (`seerdb.Server`) speaks plaintext TTC to a trivial
`dual` backend; the phase-2 mutual-TLS proxy terminates TLS in front of it. The
client authenticates with the committed wallet identity, matches the server DN,
and runs `SELECT * FROM dual` — proving wallet mTLS carries a genuine query, not
just a bare handshake. Sync and async both covered.
"""

import asyncio
import os
import threading
import unittest

from _tls_proxy import TLSProxy

import seerdb
from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
from seerdb.server import ColumnMeta, Result, UnsupportedFeature, credential_lookup

WALLET_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'wallet')
CA_CERT = os.path.join(WALLET_DIR, 'ca_cert.pem')
SERVER_CERT = os.path.join(WALLET_DIR, 'server_cert.pem')
SERVER_KEY = os.path.join(WALLET_DIR, 'server_key.pem')
CLIENT_DN = 'CN=seerdb-test-client'


class _DualBackend:
    """One-row `dual` backend, per the seerdb.Server test convention."""

    capabilities = frozenset()

    def authenticate(self, username: str) -> str | None:
        return credential_lookup({'PYO': 'pyo123'}, username)

    def execute(self, sql: str, binds=()) -> Result:
        if 'dual' in sql.lower():
            Col = ColumnMeta(
                name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
            )
            return Result(columns=[Col], rows=[('X',)])
        raise UnsupportedFeature(sql)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass


class TestWalletEndToEnd(unittest.TestCase):
    def setUp(self):
        # Plaintext Mirror on an ephemeral port.
        self.server = seerdb.Server(
            host='127.0.0.1', port=0, backend_factory=_DualBackend
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        # mTLS proxy terminating TLS in front of the Mirror.
        self.proxy = TLSProxy(
            '127.0.0.1',
            self.server.port,
            cert_path=SERVER_CERT,
            key_path=SERVER_KEY,
            client_ca_path=CA_CERT,
        )
        self.proxy.start()
        self.addCleanup(self._teardown)

    def _teardown(self):
        self.proxy.stop()
        self.server.close()
        self.thread.join(timeout=5)

    def _kwargs(self):
        return {
            'host': '127.0.0.1',
            'port': self.proxy.listen_port,
            'user': 'PYO',
            'password': 'pyo123',
            'service_name': 'XE',
            'wallet_location': WALLET_DIR,
            'dsn': 'seerdb_test',
            'timeout': 5000,
        }

    def test_sync_select_over_wallet_mtls(self):
        Conn = seerdb.connect(**self._kwargs())
        try:
            Cur = Conn.cursor()
            Cur.execute('select * from dual')
            Row = Cur.fetchone()
        finally:
            Conn.close()
        self.assertEqual(Row, ('X',))
        # The query really traversed the mutual-TLS channel.
        self.assertIn(CLIENT_DN, self.proxy.client_dns)

    def test_async_select_over_wallet_mtls(self):
        async def run():
            Conn = await seerdb.connect_async(**self._kwargs())
            async with Conn:
                Cur = Conn.cursor()
                await Cur.execute('select * from dual')
                return await Cur.fetchone()

        Row = asyncio.run(run())
        self.assertEqual(Row, ('X',))
        self.assertIn(CLIENT_DN, self.proxy.client_dns)


if __name__ == '__main__':
    unittest.main()
