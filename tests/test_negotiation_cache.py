# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The opt-in negotiation cache (#438).

A reconnect to a fast-auth (fv >= 18) server it has seen before can skip the bare
PRO probe and go straight to the fast-auth bundle, saving one round trip. A stale
entry (the server changed) makes the cached-path handshake fail; connect() then
invalidates the entry and retries a full negotiation.

The retry is exercised against the 11g Mirror: a poisoned cache entry makes the
client send a fast-auth bundle the Mirror rejects, forcing the invalidate-and-
retry — all in-process, no live server.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import threading
import unittest
from pathlib import Path

import seerdb
from seerdb.client.connection import (
    _NEGOTIATION_CACHE,
    OracleConnect,
    _nego_cache_del,
    _nego_cache_get,
    _nego_cache_put,
)
from seerdb.server import PacketStream, serve_session

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'examples'))
from sqlite_backend import SqliteBackend  # noqa: E402

_CREDS = {'PYO': 'pyo123'}
# A field version that puts the client on the fast-auth (cached) path.
_FAST_AUTH_FV = 24


class TestCacheHelpers(unittest.TestCase):
    def setUp(self) -> None:
        _NEGOTIATION_CACHE.clear()

    def test_get_put_del_roundtrip(self) -> None:
        key = ('h', 1521, 'svc')
        self.assertIsNone(_nego_cache_get(key))
        _nego_cache_put(key, 24)
        self.assertEqual(_nego_cache_get(key), 24)
        _nego_cache_del(key)
        self.assertIsNone(_nego_cache_get(key))

    def test_del_missing_key_is_a_noop(self) -> None:
        _nego_cache_del(('nope', 0, ''))  # must not raise

    def test_key_uses_service_then_sid(self) -> None:
        c = OracleConnect(host='db', port=1522, service_name='PDB1')
        self.assertEqual(c._nego_cache_key(), ('db', 1522, 'PDB1'))
        c2 = OracleConnect(host='db', port=1522, sid='ORCL')
        self.assertEqual(c2._nego_cache_key(), ('db', 1522, 'ORCL'))


def _start_mirror() -> tuple[socket.socket, threading.Thread, dict]:
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(2)
    result: dict = {}

    def run() -> None:
        # Serve up to two sessions: the aborted cached attempt + the retry.
        for _ in range(2):
            try:
                conn, _ = listen.accept()
                serve_session(
                    PacketStream(conn), SqliteBackend(':memory:', credentials=_CREDS)
                )
            except Exception:  # noqa: BLE001 - a rejected cached attempt is expected
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    server = threading.Thread(target=run, daemon=True)
    server.start()
    return listen, server, result


class TestStaleCacheRetry(unittest.TestCase):
    def setUp(self) -> None:
        _NEGOTIATION_CACHE.clear()

    def _poison(self, port: int) -> tuple[str, int, str]:
        key = ('127.0.0.1', port, 'XE')
        _nego_cache_put(key, _FAST_AUTH_FV)
        return key

    def test_stale_cache_invalidates_and_retries(self) -> None:
        # The cached path sends a fast-auth bundle the 11g Mirror rejects; connect
        # must invalidate the entry and recover via a full legacy handshake.
        listen, server, _ = _start_mirror()
        port = listen.getsockname()[1]
        key = self._poison(port)
        conn = seerdb.connect(
            host='127.0.0.1',
            port=port,
            user='PYO',
            password='pyo123',
            service_name='XE',
            negotiation_cache=True,
            timeout=5000,
        )
        try:
            cur = conn.cursor()
            cur.execute('create table t (x number)')
            cur.execute('insert into t values (7)')
            cur.execute('select x from t')
            rows = cur.fetchall()
        finally:
            conn.close()
            server.join(timeout=5)
            listen.close()
        self.assertEqual(rows, [(7,)])
        self.assertFalse(conn._used_nego_cache)  # the retry cleared the flag
        self.assertIsNone(_nego_cache_get(key))  # stale entry invalidated
        # An 11g server (fv < 18) is not re-cached.

    def test_disabled_cache_ignores_a_poisoned_entry(self) -> None:
        # With the opt-in off, a stale entry must not be consulted at all: the
        # first connection goes straight down the full-negotiation path.
        listen, server, _ = _start_mirror()
        port = listen.getsockname()[1]
        self._poison(port)
        conn = seerdb.connect(
            host='127.0.0.1',
            port=port,
            user='PYO',
            password='pyo123',
            service_name='XE',
            negotiation_cache=False,
            timeout=5000,
        )
        try:
            cur = conn.cursor()
            cur.execute('create table t (x number)')
            cur.execute('insert into t values (2)')
            cur.execute('select x from t')
            row = cur.fetchone()
        finally:
            conn.close()
            server.join(timeout=5)
            listen.close()
        self.assertEqual(row, (2,))
        self.assertFalse(conn._used_nego_cache)

    def test_stale_cache_retry_async(self) -> None:
        listen, server, _ = _start_mirror()
        port = listen.getsockname()[1]
        key = self._poison(port)

        async def run() -> list:
            conn = await seerdb.connect_async(
                host='127.0.0.1',
                port=port,
                user='PYO',
                password='pyo123',
                service_name='XE',
                negotiation_cache=True,
                timeout=5000,
            )
            cur = conn.cursor()
            await cur.execute('create table t (x number)')
            await cur.execute('insert into t values (9)')
            await cur.execute('select x from t')
            rows = await cur.fetchall()
            await conn.close()
            return rows

        try:
            rows = asyncio.run(run())
        finally:
            server.join(timeout=5)
            listen.close()
        self.assertEqual(rows, [(9,)])
        self.assertIsNone(_nego_cache_get(key))


if __name__ == '__main__':
    unittest.main()
