# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A live client runs real SQL against a SQLite-backed Mirror.

Exercises the whole stack — Oracle wire protocol → the Backend seam → a real
database — with DDL, DML and a typed SELECT, no Oracle and no Postgres in sight.
"""

from __future__ import annotations

import datetime
import socket
import sys
import threading
from decimal import Decimal
from pathlib import Path

import pytest

import seerdb
from seerdb.server import PacketStream, serve_session

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'examples'))
from sqlite_backend import SqliteBackend  # noqa: E402

_CREDS = {'PYO': 'pyo123'}


def _serve_sqlite(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    # The backend is created in THIS thread: sqlite3 objects are thread-affine,
    # which is exactly the per-session backend model (one DB session per client).
    try:
        result['user'] = serve_session(
            PacketStream(conn), SqliteBackend(':memory:', credentials=_CREDS)
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def _start_mirror() -> tuple[socket.socket, threading.Thread, dict]:
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    result: dict = {}
    server = threading.Thread(target=_serve_sqlite, args=(listen, result), daemon=True)
    server.start()
    return listen, server, result


def _connect(port: int):
    return seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )


def test_unknown_user_is_rejected() -> None:
    # Auth lives with the backend: a user absent from its credentials is refused
    # by authenticate(), and the Mirror rejects the login with ORA-01017 — so
    # connect() itself raises, the way real Oracle denies a bad login.
    listen, server, result = _start_mirror()
    port = listen.getsockname()[1]
    try:
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            seerdb.connect(
                host='127.0.0.1',
                port=port,
                user='NOBODY',
                password='whatever',
                service_name='XE',
                timeout=3000,
            )
        assert 'ORA-01017' in str(excinfo.value)
    finally:
        server.join(timeout=5)
        listen.close()

    # The backend's authenticate() gated the login server-side.
    assert isinstance(result.get('error'), Exception)
    assert 'NOBODY' in str(result['error'])


def test_wrong_password_is_rejected() -> None:
    # The Mirror verifies the client's AUTH_PASSWORD proof server-side, so a
    # valid user with the wrong password is denied ORA-01017 at connect — it
    # cannot get a session by ignoring the server proof it can't validate.
    listen, server, result = _start_mirror()
    port = listen.getsockname()[1]
    try:
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            seerdb.connect(
                host='127.0.0.1',
                port=port,
                user='PYO',
                password='WRONGPASS',
                service_name='XE',
                timeout=3000,
            )
        assert 'ORA-01017' in str(excinfo.value)
    finally:
        server.join(timeout=5)
        listen.close()

    assert isinstance(result.get('error'), Exception)
    assert 'wrong password' in str(result['error'])


def test_real_sql_round_trip() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('create table t (id number, name varchar2(20), score number)')
        cur.execute("insert into t values (1, 'alice', 9.5)")
        cur.execute("insert into t values (2, 'bob', -3)")
        cur.execute('select id, name, score from t order by id')
        rows = cur.fetchall()
        # A second statement after a fetch exercises the CLOSE_CURSORS piggyback
        # the client prepends — the Mirror must skip it and still answer.
        cur.execute('select name from t where id = 2')
        second = cur.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    # NUMBER: integers stay int, non-integers become Decimal (Oracle semantics).
    assert rows == [(1, 'alice', Decimal('9.5')), (2, 'bob', -3)]
    assert second == ('bob',)  # the post-fetch statement was answered


def test_bad_sql_is_an_ora_error_not_a_desync() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            cur.execute('select * from a_table_that_does_not_exist')
        assert 'ORA-00900' in str(excinfo.value)
        # The connection survived — a valid query still works.
        cur.execute('create table t (n number)')
        cur.execute('insert into t values (42)')
        cur.execute('select n from t')
        rows = cur.fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rows == [(42,)]


def test_bind_variables() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('create table t (id number, name varchar2(20))')
        cur.execute('insert into t values (:1, :2)', [1, 'alice'])
        cur.execute('insert into t values (:1, :2)', [2, 'bob'])
        cur.execute('select name from t where id = :1', [2])
        row = cur.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('bob',)


def test_batched_fetch_large_row_count() -> None:
    # A result set far larger than the fetch batch is delivered across follow-up
    # TTI_FETCH calls: every row arrives (fetchmany then fetchall), and a second
    # query on the same connection proves the server cursor was cleaned up.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('create table t (n number)')
        cur.executemany('insert into t values (:1)', [(i,) for i in range(500)])
        cur.execute('select n from t order by n')
        first = cur.fetchmany(10)
        rest = cur.fetchall()
        cur.execute('select count(*) from t')
        count = cur.fetchone()[0]
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert [r[0] for r in first] == list(range(10))
    assert [r[0] for r in first] + [r[0] for r in rest] == list(range(500))
    assert count == 500


def test_large_response_spans_many_packets() -> None:
    # A result set far larger than the TNS packet limit (here ~175 KB) must
    # fragment across many DATA packets and reassemble in the client — the
    # server-side fragmentation matching Oracle's SDU-37/-81 continuation sizes.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('create table t (id number, v varchar2(4000))')
        for i in range(50):
            cur.execute('insert into t values (:1, :2)', [i, chr(65 + i % 26) * 3500])
        cur.execute('select id, v from t order by id')
        rows = cur.fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert len(rows) == 50
    assert rows[0] == (0, 'A' * 3500)
    assert rows[49] == (49, 'X' * 3500)


def test_large_values_round_trip() -> None:
    # A string and a RAW value well over the 253-byte single-byte DALC limit
    # must chunk correctly all the way through the wire and back.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    big_str = 'seerdb-' * 500  # 3500 chars
    big_raw = bytes(range(256)) * 8  # 2048 bytes
    try:
        cur = conn.cursor()
        cur.execute('create table t (id number, s varchar2(4000), b raw(4000))')
        cur.execute('insert into t values (:1, :2, :3)', [1, big_str, big_raw])
        cur.execute('select s, b from t where id = :1', [1])
        row = cur.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == (big_str, big_raw)


def test_thin_lob_read_round_trip() -> None:
    # A thin (seerdb) client reads CLOB / BLOB columns from the Mirror: the row
    # carries a locator and the driver auto-resolves it over TTI_LOBOPS (#413).
    # Covers small, large (multi-chunk), NULL, and multiple LOB columns per row.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    big_clob = 'seerdb-clob-' * 500  # 6000 chars
    big_blob = bytes(range(256)) * 20  # 5120 bytes
    try:
        cur = conn.cursor()
        cur.execute('create table t (id number, c clob, b blob)')
        cur.execute(
            'insert into t values (:1, :2, :3)', [1, 'hi-clob', b'\xca\xfe\xba\xbe']
        )
        cur.execute('insert into t values (:1, :2, :3)', [2, big_clob, big_blob])
        cur.execute('insert into t values (:1, :2, :3)', [3, None, None])
        cur.execute('select id, c, b from t order by id')
        rows = cur.fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rows[0] == (1, 'hi-clob', b'\xca\xfe\xba\xbe')
    assert rows[1] == (2, big_clob, big_blob)  # large CLOB + BLOB, multiple per row
    assert rows[2] == (3, None, None)  # NULL LOBs


def test_executemany_array_dml() -> None:
    # executemany sends one execute carrying every row; the Mirror applies them
    # all and reports the total affected count.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('create table t (id number, name varchar2(20))')
        cur.executemany(
            'insert into t values (:1, :2)',
            [(1, 'a'), (2, 'b'), (3, 'c'), (4, 'd')],
        )
        rowcount = cur.rowcount
        cur.execute('select id, name from t order by id')
        rows = cur.fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rowcount == 4
    assert rows == [(1, 'a'), (2, 'b'), (3, 'c'), (4, 'd')]


def test_large_integer_bind() -> None:
    # An integer beyond SQLite's 64-bit INTEGER range is accepted (spilled to
    # REAL) instead of crashing with ORA-00600; an in-range integer stays exact.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    in_range = 9_000_000_000_000_000_000  # < 2**63, exact
    huge = 10**30  # > 2**63, lossy REAL
    try:
        cur = conn.cursor()
        cur.execute('create table t (id number, v number)')
        cur.execute('insert into t values (1, :1)', [in_range])
        cur.execute('insert into t values (2, :1)', [huge])
        cur.execute('select v from t where id = 1')
        exact = cur.fetchone()[0]
        cur.execute('select v from t where id = 2')
        big = cur.fetchone()[0]
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert exact == in_range  # in-range integer is exact
    assert abs(float(big) - float(huge)) / float(huge) < 1e-9  # accepted, ~equal


def test_fractional_number_bind() -> None:
    # A non-integer NUMBER bind decodes server-side to a Decimal; the SQLite
    # backend must accept it (as REAL) rather than reject it. float binds take
    # the same path (the client encodes both as NUMBER).
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('create table t (id number, v number)')
        cur.execute('insert into t values (:1, :2)', [1, Decimal('3.14159')])
        cur.execute('insert into t values (:1, :2)', [2, 2.5])
        cur.execute('select v from t order by id')
        rows = cur.fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    # Stored as REAL and read back through NUMBER — both round-trip as Decimal.
    assert rows == [(Decimal('3.14159'),), (Decimal('2.5'),)]


def test_commit_and_rollback() -> None:
    # With autocommit off, rollback() must discard uncommitted work and commit()
    # must keep it — real transaction control, not a no-op reply.
    listen, server, result = _start_mirror()
    conn = seerdb.connect(
        host='127.0.0.1',
        port=listen.getsockname()[1],
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
        autocommit=False,
    )
    try:
        cur = conn.cursor()
        cur.execute('create table t (n number)')  # DDL self-commits
        cur.execute('insert into t values (1)')
        cur.execute('insert into t values (2)')
        conn.rollback()
        cur.execute('select n from t')
        after_rollback = cur.fetchall()
        cur.execute('insert into t values (3)')
        conn.commit()
        cur.execute('select n from t order by n')
        after_commit = cur.fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert after_rollback == []  # the two inserts were rolled back
    assert after_commit == [(3,)]  # the committed insert survived


def test_date_and_timestamp_round_trip() -> None:
    # A DATE column keeps day+second precision; a TIMESTAMP column additionally
    # keeps the sub-second part, all the way through the wire and back.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    ts = datetime.datetime(2024, 1, 15, 13, 30, 45, 123456)
    day = datetime.date(2020, 12, 31)
    try:
        cur = conn.cursor()
        cur.execute('create table t (d date, ts timestamp)')
        cur.execute('insert into t values (:1, :2)', [day, ts])
        cur.execute('select d, ts from t')
        row = cur.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    # DATE decodes to a datetime at midnight; TIMESTAMP preserves microseconds.
    assert row == (datetime.datetime(2020, 12, 31, 0, 0), ts)
