# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import socket
import threading
import time
import unittest
from unittest import mock

from seerdb.client.connection import (
    _FV2_MAX_RAW_BIND,
    _FV2_MAX_VARCHAR_BIND,
    _REDIRECT_CONNECT_ATTEMPTS,
    OracleConnect,
    _check_fv2_bind_sizes,
    _reject_cqn,
    _reject_sharding,
    _split_proxy_user,
)
from seerdb.common.exceptions import DatabaseError, NotSupportedError, OperationalError


class TestCqnRejected(unittest.TestCase):
    # Continuous Query Notification (#129) registers a server-initiated
    # subscription — the DB opens a callback channel back to the client, an
    # OCI-only capability outside the thin request/response protocol. seerdb
    # exposes subscribe / unsubscribe for API parity but raises
    # NotSupportedError, so ported thin code gets that rather than an
    # AttributeError on a missing method.
    def test_helper_raises(self):
        with self.assertRaises(NotSupportedError):
            _reject_cqn()

    def test_subscribe_unsubscribe_reject_any_args(self):
        c = OracleConnect(host='x', port=1, user='pyo', password='p')
        with self.assertRaises(NotSupportedError):
            c.subscribe(callback=lambda m: None)
        with self.assertRaises(NotSupportedError):
            c.unsubscribe()

    def test_async_subscribe_unsubscribe_reject(self):
        # Sync/async parity: regular (non-coroutine) methods that raise before
        # any await point.
        from seerdb.client.aconnection import AsyncOracleConnect

        a = AsyncOracleConnect(host='x', port=1, user='pyo', password='p')
        with self.assertRaises(NotSupportedError):
            a.subscribe(callback=lambda m: None)
        with self.assertRaises(NotSupportedError):
            a.unsubscribe()


class TestProxyUser(unittest.TestCase):
    # Proxy authentication (#126): user "proxy[schema]" -> authenticate as
    # proxy, operate in schema. The wire side (PROXY_CLIENT_NAME auth pair) is
    # covered by the live tests on 10g/11g/21c/23ai.
    def test_split(self):
        self.assertEqual(_split_proxy_user('pyo[hr]'), ('pyo', 'hr'))
        self.assertEqual(_split_proxy_user('PROXY[TARGET]'), ('PROXY', 'TARGET'))

    def test_plain_user_unchanged(self):
        self.assertEqual(_split_proxy_user('pyo'), ('pyo', None))
        self.assertEqual(_split_proxy_user(''), ('', None))
        self.assertEqual(_split_proxy_user(None), (None, None))

    def test_only_trailing_brackets_after_name(self):
        # a leading bracket or a missing closing bracket is not a proxy form
        self.assertEqual(_split_proxy_user('[hr]'), ('[hr]', None))
        self.assertEqual(_split_proxy_user('pyo[hr'), ('pyo[hr', None))

    def test_connection_init_parses_user(self):
        c = OracleConnect(host='x', port=1, user='pyo[hr]', password='p')
        self.assertEqual(c.user, 'pyo')
        self.assertEqual(c.proxy_user, 'hr')
        env = c._make_dict(None)['env']
        self.assertEqual(env['user'], 'pyo')
        self.assertEqual(env['proxy_user'], 'hr')


class TestShardingRejected(unittest.TestCase):
    # Sharding keys (#164) route to a shard of a sharded database — an OCI-only
    # capability below the thin wire protocol. seerdb accepts the
    # oracledb-compatible parameters but rejects them with NotSupportedError
    # (before any socket work), so ported thin code gets the recognizable error
    # rather than a TypeError on an unexpected keyword.
    def test_helper_passes_through_when_absent(self):
        # None / absent must not raise (the default construction path).
        self.assertIsNone(_reject_sharding(None, None))

    def test_helper_rejects_each_key(self):
        with self.assertRaises(NotSupportedError):
            _reject_sharding(['CUST42'], None)
        with self.assertRaises(NotSupportedError):
            _reject_sharding(None, ['REGION1'])
        with self.assertRaises(NotSupportedError):
            _reject_sharding([42], ['REGION1'])

    def test_helper_rejects_falsey_but_present_key(self):
        # An empty list is still a request to shard — present, so rejected.
        with self.assertRaises(NotSupportedError):
            _reject_sharding([], None)

    def test_connection_init_rejects_sharding(self):
        # Raised at construction, before any host/port is touched.
        with self.assertRaises(NotSupportedError):
            OracleConnect(host='x', port=1, user='pyo', shardingkey=['CUST42'])
        with self.assertRaises(NotSupportedError):
            OracleConnect(host='x', port=1, user='pyo', supershardingkey=['R1'])

    def test_connection_init_without_sharding_ok(self):
        # The default (no sharding) construction path is unaffected.
        c = OracleConnect(host='x', port=1, user='pyo', password='p')
        self.assertEqual(c.host, 'x')

    def test_async_connection_init_rejects_sharding(self):
        # Sync/async parity: the async constructor rejects it the same way
        # (its __init__ is not a coroutine, so no loop is needed here).
        from seerdb.client.aconnection import AsyncOracleConnect

        with self.assertRaises(NotSupportedError):
            AsyncOracleConnect(host='x', port=1, user='pyo', shardingkey=['C'])
        # And the default path still constructs.
        a = AsyncOracleConnect(host='x', port=1, user='pyo', password='p')
        self.assertEqual(a.host, 'x')


class TestFv2BindSizeGate(unittest.TestCase):
    # 9i (fv2) has no streamed LOB/LONG bind path, so a bind is capped at the
    # SQL inline limits: 2000 bytes (RAW) / 4000 bytes (VARCHAR2). Past those the
    # 9i server kills the connection (BLOB) or errors; reject up front so the
    # connection survives (#168/#169). Verified live on 9i in the integration
    # suite; this guards the limits + boundary offline.
    def test_bytes_within_cap_ok(self):
        _check_fv2_bind_sizes([b'x' * _FV2_MAX_RAW_BIND])  # exactly 2000

    def test_bytes_over_cap_raises(self):
        with self.assertRaises(NotSupportedError):
            _check_fv2_bind_sizes([b'x' * (_FV2_MAX_RAW_BIND + 1)])

    def test_str_within_cap_ok(self):
        _check_fv2_bind_sizes(['x' * _FV2_MAX_VARCHAR_BIND])  # exactly 4000

    def test_str_over_cap_raises(self):
        with self.assertRaises(NotSupportedError):
            _check_fv2_bind_sizes(['x' * (_FV2_MAX_VARCHAR_BIND + 1)])

    def test_str_counts_utf8_bytes_not_chars(self):
        # A multibyte char string under 4000 chars can exceed 4000 utf-8 bytes.
        Value = 'é' * 2001  # 4002 utf-8 bytes
        with self.assertRaises(NotSupportedError):
            _check_fv2_bind_sizes([Value])

    def test_dict_and_batch_values_checked(self):
        with self.assertRaises(NotSupportedError):
            _check_fv2_bind_sizes({'b': b'x' * 2001})
        with self.assertRaises(NotSupportedError):
            _check_fv2_bind_sizes([1], Batch=[[b'x' * 2001]])

    def test_small_and_nonblob_binds_pass(self):
        _check_fv2_bind_sizes([1, 'small', b'raw', None, 3.14])
        _check_fv2_bind_sizes([])


class TestConnection(unittest.TestCase):
    def test_empty_credentials_rejected(self):
        # Connecting with the default empty username/password must not silently
        # "succeed". The server rejects the logon with an auth-error OER, which
        # now surfaces as a DatabaseError (ORA-01017) instead of being swallowed
        # — and crucially no longer hangs the handshake. Needs a reachable
        # listener on localhost:1521; an unreachable one raises OSError instead.
        con = OracleConnect()
        with self.assertRaises((DatabaseError, OSError)):
            con.connect()

    def test_recv_times_out_on_silent_server(self):
        # The connection `timeout` (ms) must bound blocking socket reads: a
        # server that accepts the TCP connection but never replies (e.g. an XE
        # session held by the logon-storm throttle) used to wedge recv forever
        # because the timeout was never applied to the socket. It now raises an
        # OperationalError after roughly `timeout` ms instead of hanging.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        self.addCleanup(srv.close)
        accepted = []

        def accept_and_hang():
            try:
                conn, _ = srv.accept()
                accepted.append(conn)  # hold it open; never reply
            except OSError:
                # Expected during teardown/races when the listening socket is
                # closed while this daemon thread is blocked in accept().
                pass

        threading.Thread(target=accept_and_hang, daemon=True).start()

        con = OracleConnect(
            host='127.0.0.1',
            port=srv.getsockname()[1],
            user='x',
            password='y',
            service_name='XE',
            timeout=1000,
        )
        start = time.monotonic()
        with self.assertRaises(OperationalError):
            con.connect()
        elapsed = time.monotonic() - start
        # Fired on the timeout, not after some unbounded wait.
        self.assertLess(elapsed, 10)
        self.assertGreaterEqual(elapsed, 0.5)
        for conn in accepted:
            conn.close()


class TestRedirectConnectRetry(unittest.TestCase):
    # #399: following a TNS_REDIRECT, the target dispatcher / dedicated-server
    # process may still be binding its port — a refused connect should be retried
    # briefly. An INITIAL refused connect must still fail fast.

    @staticmethod
    def _conn():
        return OracleConnect(
            host='127.0.0.1', port=1, user='x', password='y', service_name='XE'
        )

    def _fake_socket(self, refusals):
        # A socket whose connect() raises ConnectionRefusedError `refusals` times,
        # then succeeds. Tracks the attempt count.
        state = {'n': 0}

        class Fake:
            def settimeout(self, _t):
                pass

            def connect(self, _addr):
                state['n'] += 1
                if state['n'] <= refusals:
                    raise ConnectionRefusedError(111, 'Connection refused')

            def close(self):
                pass

        return Fake(), state

    def test_retries_on_refused_while_following_redirect(self):
        con = self._conn()
        con._redirects = 1  # we are following a redirect
        fake, state = self._fake_socket(refusals=3)
        with (
            mock.patch('seerdb.client.connection.socket.socket', return_value=fake),
            mock.patch('seerdb.client.connection.time.sleep'),
            mock.patch.object(con, 'send'),
        ):
            con._open_transport()  # must not raise
        self.assertEqual(state['n'], 4)  # 3 refusals + 1 success

    def test_initial_connect_does_not_retry(self):
        con = self._conn()
        con._redirects = 0  # initial connect
        fake, state = self._fake_socket(refusals=99)
        with (
            mock.patch('seerdb.client.connection.socket.socket', return_value=fake),
            mock.patch('seerdb.client.connection.time.sleep'),
            mock.patch.object(con, 'send'),
        ):
            with self.assertRaises(ConnectionRefusedError):
                con._open_transport()
        self.assertEqual(state['n'], 1)  # failed fast, no retry

    def test_gives_up_after_the_attempt_cap(self):
        con = self._conn()
        con._redirects = 1
        fake, state = self._fake_socket(refusals=999)  # never comes up
        with (
            mock.patch('seerdb.client.connection.socket.socket', return_value=fake),
            mock.patch('seerdb.client.connection.time.sleep'),
            mock.patch.object(con, 'send'),
        ):
            with self.assertRaises(ConnectionRefusedError):
                con._open_transport()
        self.assertEqual(state['n'], _REDIRECT_CONNECT_ATTEMPTS)
