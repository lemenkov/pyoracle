# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A live client runs real SQL against a SQLite-backed Mirror.

Exercises the whole stack — Oracle wire protocol → the Backend seam → a real
database — with DDL, DML and a typed SELECT, no Oracle and no Postgres in sight.
"""

from __future__ import annotations

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
            PacketStream(conn), _CREDS, SqliteBackend(':memory:')
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
