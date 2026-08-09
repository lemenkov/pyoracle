# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A live client runs real SQL against a PostgreSQL-backed Mirror.

Skips cleanly when psycopg is not installed or no PostgreSQL is reachable
(``MIRROR_PG`` overrides the connection string), so CI without a database just
skips — the same pattern as the live-Oracle integration tests.
"""

from __future__ import annotations

import datetime
import os
import socket
import sys
import threading
from decimal import Decimal
from pathlib import Path

import pytest

import seerdb
from seerdb.server import PacketStream, serve_session

psycopg = pytest.importorskip('psycopg')
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'examples'))
from postgres_backend import PostgresBackend  # noqa: E402

_CONNINFO = os.environ.get(
    'MIRROR_PG', 'host=127.0.0.1 port=5433 user=pyo password=pyo123 dbname=mirror'
)
_CREDS = {'PYO': 'pyo123'}


def _pg_reachable() -> bool:
    try:
        psycopg.connect(_CONNINFO, connect_timeout=2).close()
    except Exception:
        return False
    return True


pytestmark = pytest.mark.skipif(not _pg_reachable(), reason='no PostgreSQL reachable')


def _serve(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(
            PacketStream(conn), _CREDS, PostgresBackend(_CONNINFO)
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
    server = threading.Thread(target=_serve, args=(listen, result), daemon=True)
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


def test_real_sql_round_trip_postgres() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_mirror')
        cur.execute(
            'create table t_mirror (id integer, name varchar(20), score numeric)'
        )
        cur.execute("insert into t_mirror values (1, 'alice', 9.5)")
        cur.execute("insert into t_mirror values (2, 'bob', -3)")
        cur.execute('select id, name, score from t_mirror order by id')
        rows = cur.fetchall()
        cur.execute('drop table t_mirror')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rows == [(1, 'alice', Decimal('9.5')), (2, 'bob', -3)]


def test_unsupported_pg_type_is_an_ora_error() -> None:
    # A column type the Mirror can't yet represent (timestamp) is refused with a
    # clean ORA-03001 — the connection stays usable, per the capabilities design.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            cur.execute("select '[]'::json")  # json isn't mapped yet
        assert 'ORA-03001' in str(excinfo.value)
        cur.execute('select 7 as n')
        rows = cur.fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rows == [(7,)]


def test_date_and_timestamp_columns() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute(
            "select timestamp '2024-01-15 13:30:45' as ts, date '2020-12-31' as d"
        )
        row = cur.fetchone()
        cur.execute('select now() as n')  # was ORA-03001; now a DATE
        now_value = cur.fetchone()[0]
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == (
        datetime.datetime(2024, 1, 15, 13, 30, 45),
        datetime.datetime(2020, 12, 31, 0, 0),
    )
    assert isinstance(now_value, datetime.datetime)


def test_bind_variables_postgres() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_bind')
        cur.execute('create table t_bind (id integer, name varchar(20))')
        cur.execute('insert into t_bind values (:1, :2)', [1, 'alice'])
        cur.execute('insert into t_bind values (:1, :2)', [2, 'bob'])
        cur.execute('select name from t_bind where id = :1', [2])
        row = cur.fetchone()
        cur.execute('drop table t_bind')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('bob',)
