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
from postgres_backend import (  # noqa: E402
    _HELPER_FUNCTIONS_DDL,
    _IS_DDL,
    _REF_SELECT,
    OraInterval,
    PostgresBackend,
    _backend_error,
    _distinct_bind_refs,
    _parse_out_assignments,
    _reject_unsupported_ddl_types,
    _to_interval_ym,
    _translate_binds,
    _translate_ddl,
    _translate_idioms,
    _translate_plsql_block,
    _translate_routine_ddl,
)


class _FakePgError(Exception):
    def __init__(self, sqlstate: str, message: str) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


def test_backend_error_uses_oracle_canonical_text_for_mapped_code() -> None:
    # A mapped code with a canonical Oracle phrasing gets it, so a client matching
    # on the Oracle text behaves — ORA-00942 is "table or view does not exist", not
    # PostgreSQL's "relation … does not exist" (#529).
    err = _backend_error(_FakePgError('42P01', 'relation "nope" does not exist'))
    assert err.ora_code == 942
    assert 'table or view' in str(err) and 'does not exist' in str(err)
    # A mapped code with no canonical text keeps PostgreSQL's message (its English
    # varies by Oracle version), still under the right code.
    num = _backend_error(_FakePgError('22P02', 'invalid input syntax for type numeric'))
    assert num.ora_code == 1722
    assert 'invalid input syntax' in str(num)
    # An unmapped SQLSTATE falls back to ORA-00900 with PostgreSQL's message.
    other = _backend_error(_FakePgError('XX000', 'internal error'))
    assert other.ora_code == 900


# --- DDL type translation (#500) — a pure function, no live PostgreSQL needed ---


def test_translate_ddl_maps_create_table_column_types() -> None:
    sent = _translate_ddl(
        'CREATE TABLE t (id NUMBER(10,2), v VARCHAR2(20), d DATE, '
        'r RAW(16), c CLOB, b BLOB, ts TIMESTAMP WITH TIME ZONE, '
        'f BINARY_FLOAT, g BINARY_DOUBLE)'
    )
    assert 'numeric(10,2)' in sent
    assert 'varchar(20)' in sent
    assert 'timestamp(0)' in sent  # DATE keeps its time-of-day
    assert 'r bytea' in sent  # RAW(16) → bytea (size dropped)
    assert 'c ora_clob' in sent  # CLOB → domain over text, so empty ≠ NULL (#534)
    assert 'b ora_blob' in sent  # BLOB → domain over bytea (#534)
    assert 'ts ora_tstz' in sent  # WITH TIME ZONE preserves the offset (#519)
    assert 'f real' in sent and 'g double precision' in sent
    assert 'NUMBER' not in sent and 'VARCHAR2' not in sent


def test_translate_ddl_maps_object_type_to_composite() -> None:
    # CREATE TYPE ... AS OBJECT (attrs) → a PostgreSQL composite type, the OBJECT
    # keyword dropped and the attribute types mapped like a table's columns (#139).
    sent = _translate_ddl(
        'CREATE TYPE PYORACLE_REF_PERSON AS OBJECT (id NUMBER, name VARCHAR2(40))'
    )
    assert 'AS OBJECT' not in sent and 'OBJECT' not in sent
    assert 'AS (id numeric, name varchar(40))' in sent
    assert 'PYORACLE_REF_PERSON' in sent  # the type name is untouched


def test_translate_ddl_maps_ref_column_to_bytea() -> None:
    # A `REF <object type>` column has no PostgreSQL equal; since the REF bind that
    # uses it is 12c+ and skips on the 11g Mirror, the column becomes a bytea
    # placeholder so the CREATE succeeds (#139). A REF() call is left alone.
    sent = _translate_ddl('CREATE TABLE t (id NUMBER, r REF PYORACLE_REF_PERSON)')
    assert 'r bytea' in sent
    assert 'REF' not in sent
    # CREATE TABLE ... OF type (a typed table) passes through unchanged.
    assert _translate_ddl('CREATE TABLE people OF PYORACLE_REF_PERSON') == (
        'CREATE TABLE people OF PYORACLE_REF_PERSON'
    )


def test_ref_select_matches_the_object_ref_fetch() -> None:
    # `SELECT REF(alias) FROM table alias [rest]` is recognised so the backend can
    # stand in the ctid + report the object type; the alias inside REF() must match
    # the table alias (#139).
    m = _REF_SELECT.match('SELECT REF(p) FROM PYORACLE_REF_PEOPLE p WHERE p.id = 1')
    assert m is not None
    assert m.group(1) == 'p' and m.group(2) == 'PYORACLE_REF_PEOPLE'
    assert m.group(3) == 'p' and m.group(4).strip() == 'WHERE p.id = 1'
    # A DEREF select (the 12c+ path) is not a REF fetch.
    assert _REF_SELECT.match('SELECT DEREF(r).name FROM t') is None


def test_translate_ddl_maps_interval_year_to_month_to_domain() -> None:
    # INTERVAL YEAR TO MONTH → the ora_intervalym domain (so the read path can tell
    # it from a DAY TO SECOND interval), while DAY TO SECOND stays a plain interval
    # (#504).
    sent = _translate_ddl(
        'CREATE TABLE t (ym INTERVAL YEAR(4) TO MONTH, ds INTERVAL DAY TO SECOND)'
    )
    assert 'ym ora_intervalym' in sent
    assert 'ds interval' in sent and 'ds ora_intervalym' not in sent


def test_translate_binds_wraps_interval_ym_as_make_interval() -> None:
    # An IntervalYM bind can't be sent as-is (psycopg has no dumper), so it becomes
    # make_interval(months => N) with N the whole-month count — 3y7m → 43, and a
    # negative -1y2m → -14 (IntervalYM normalises the sign) (#504).
    sql, params = _translate_binds(
        'INSERT INTO t VALUES (:1)', [seerdb.IntervalYM(3, 7)]
    )
    assert sql == 'INSERT INTO t VALUES (make_interval(months => %(b1)s))'
    assert params == {'b1': 43}
    _sql, neg = _translate_binds(
        'INSERT INTO t VALUES (:1)', [seerdb.IntervalYM(-1, -2)]
    )
    assert neg == {'b1': -14}


def test_to_interval_ym_from_ora_interval() -> None:
    # An OraInterval (a timedelta carrying the whole-month count) → an IntervalYM;
    # IntervalYM normalises the split and shares the sign (#504). A None passes.
    empty = datetime.timedelta()
    assert _to_interval_ym(OraInterval(months=43, td=empty)) == seerdb.IntervalYM(3, 7)
    assert _to_interval_ym(OraInterval(months=-14, td=empty)) == seerdb.IntervalYM(
        -1, -2
    )
    assert _to_interval_ym(None) is None
    # A DAY TO SECOND interval carries months == 0 and keeps its exact duration, so
    # it is still a real timedelta the INTERVALDS encode path handles unchanged.
    ds = OraInterval(months=0, td=datetime.timedelta(days=2, seconds=11045))
    assert isinstance(ds, datetime.timedelta)
    assert ds == datetime.timedelta(days=2, seconds=11045)
    assert _to_interval_ym(ds) == seerdb.IntervalYM(0, 0)


def test_translate_ddl_time_zone_variants() -> None:
    # WITH LOCAL TIME ZONE normalises like PostgreSQL timestamptz; plain WITH TIME
    # ZONE preserves the entered offset, so it maps to the ora_tstz composite (#519).
    sent = _translate_ddl(
        'CREATE TABLE t (a TIMESTAMP WITH LOCAL TIME ZONE, '
        'b TIMESTAMP WITH TIME ZONE, c TIMESTAMP)'
    )
    assert 'a timestamptz' in sent
    assert 'b ora_tstz' in sent
    assert 'c timestamp' in sent and 'c ora_tstz' not in sent


def test_translate_idioms_rewrites_connect_by_level_row_generator() -> None:
    # FROM dual CONNECT BY LEVEL <= N maps to generate_series aliased `level`, so a
    # bare LEVEL in the select list resolves to its column (#531).
    simple = _translate_idioms('SELECT LEVEL FROM dual CONNECT BY LEVEL <= 5')
    assert simple == 'SELECT LEVEL FROM generate_series(1, 5) AS level'
    multi = _translate_idioms(
        'SELECT 42 AS k, LEVEL AS n FROM dual CONNECT BY LEVEL <= 200'
    )
    assert multi == 'SELECT 42 AS k, LEVEL AS n FROM generate_series(1, 200) AS level'


def test_translate_idioms_rewrites_offset_bearing_timestamp_literal() -> None:
    # TIMESTAMP '<ts> ±HH:MM' is a WITH TIME ZONE value — build the composite so
    # the offset survives, rather than PostgreSQL's WITHOUT-time-zone parse dropping
    # it. A literal with no offset is an ordinary timestamp, left untouched (#519).
    with_offset = _translate_idioms("v := TIMESTAMP '2026-06-07 13:14:15.5 +02:00'")
    assert (
        "ROW(TIMESTAMPTZ '2026-06-07 13:14:15.5 +02:00', 7200)::ora_tstz" in with_offset
    )
    negative = _translate_idioms("TIMESTAMP '2026-05-23 10:11:12.345678 -05:30'")
    assert '-19800)::ora_tstz' in negative  # -(5*3600 + 30*60)
    plain = _translate_idioms("TIMESTAMP '2026-06-07 13:14:15.5'")
    assert plain == "TIMESTAMP '2026-06-07 13:14:15.5'"


def test_translate_idioms_negates_whole_day_to_second_interval() -> None:
    # Oracle's leading `-` negates the whole DAY TO SECOND interval; PostgreSQL
    # applies it only to the days, so lift it to a unary minus on the literal (#520).
    neg = _translate_idioms(
        "INSERT INTO t VALUES (INTERVAL '-0 00:00:01.5' DAY TO SECOND)"
    )
    assert "(- INTERVAL '0 00:00:01.5' DAY TO SECOND)" in neg
    # Precision qualifiers ride along; a positive literal is left untouched.
    prec = _translate_idioms("p := INTERVAL '-1 02:03:04.5' DAY(4) TO SECOND(6)")
    assert "- INTERVAL '1 02:03:04.5' DAY(4) TO SECOND(6)" in prec
    pos = _translate_idioms("INTERVAL '5 04:03:02.123456' DAY TO SECOND")
    assert pos == "INTERVAL '5 04:03:02.123456' DAY TO SECOND"


def test_translate_binds_wraps_aware_datetime_as_composite() -> None:
    # An aware datetime bind carries a WITH TIME ZONE value: it becomes a ROW cast
    # with the offset in seconds alongside the instant, so the offset round-trips
    # rather than being normalised to UTC by a bare timestamptz bind (#519).
    tz = datetime.timezone(datetime.timedelta(hours=-5, minutes=-30))
    value = datetime.datetime(2026, 5, 23, 10, 11, 12, 345678, tzinfo=tz)
    sql, params = _translate_binds('INSERT INTO t VALUES (:1)', [value])
    assert sql == 'INSERT INTO t VALUES (ROW(%(b1)s, %(b1__off)s)::ora_tstz)'
    assert params['b1'] is value
    assert params['b1__off'] == -19800
    # A naive datetime (or any non-aware value) binds plainly, no composite wrap.
    naive = datetime.datetime(2026, 5, 23, 10, 11, 12)
    sql2, params2 = _translate_binds('INSERT INTO t VALUES (:1)', [naive])
    assert sql2 == 'INSERT INTO t VALUES (%(b1)s)'
    assert '__off' not in ''.join(params2)


def test_translate_ddl_maps_lob_types_to_domains() -> None:
    # CLOB / NCLOB / BLOB become ora_clob / ora_blob domains so the read path can
    # tell a LOB from a plain VARCHAR2 / RAW and keep empty distinct from NULL
    # (#534). LONG / LONG RAW / RAW are not LOBs and stay text / bytea.
    sent = _translate_ddl(
        'CREATE TABLE t (a CLOB, b NCLOB, c BLOB, d LONG, e LONG RAW, f RAW(8))'
    )
    assert 'a ora_clob' in sent
    assert 'b ora_clob' in sent
    assert 'c ora_blob' in sent
    assert 'd text' in sent
    assert 'e bytea' in sent and 'f bytea' in sent
    assert 'ora_clob' not in sent.split('d text')[1]  # LONG isn't a LOB domain


def test_translate_ddl_drops_organization_index_and_global_temporary() -> None:
    iot = _translate_ddl('CREATE TABLE t (id NUMBER PRIMARY KEY) ORGANIZATION INDEX')
    assert 'ORGANIZATION INDEX' not in iot
    gtt = _translate_ddl(
        'CREATE GLOBAL TEMPORARY TABLE g (id NUMBER) ON COMMIT PRESERVE ROWS'
    )
    assert 'GLOBAL TEMPORARY' not in gtt and 'TEMPORARY TABLE' in gtt


def test_is_ddl_classifies_auto_committing_statements() -> None:
    # Oracle auto-commits DDL, so these are committed after they run (#532)…
    for sql in (
        'CREATE TABLE t (id NUMBER)',
        'CREATE OR REPLACE PROCEDURE p AS BEGIN NULL; END;',
        'DROP TABLE t',
        'ALTER TABLE t ADD (v VARCHAR2(10))',
        'TRUNCATE TABLE t',
        '  create index i on t (id)',
    ):
        assert _IS_DDL.match(sql) is not None
    # …while DML / queries stay under the client's own transaction control.
    for sql in (
        'INSERT INTO t VALUES (1)',
        'UPDATE t SET id = 2',
        'DELETE FROM t',
        'SELECT * FROM t',
        'BEGIN p(:1); END;',
    ):
        assert _IS_DDL.match(sql) is None


def test_translate_plsql_block_wraps_anonymous_declare_block() -> None:
    # A bind-less DECLARE … BEGIN … END block becomes DO $$ … $$ with the declared
    # local types mapped (VARCHAR2 → varchar); the body rides along (#533).
    out = _translate_plsql_block(
        "DECLARE v VARCHAR2(32767); BEGIN v := RPAD('X', 10, 'X'); "
        'INSERT INTO t VALUES (1, v); END;'
    )
    assert out.startswith('DO $$ DECLARE v varchar(32767); BEGIN ')
    assert out.endswith('END $$')
    assert 'INSERT INTO t VALUES (1, v);' in out
    # A bare BEGIN … END (no DECLARE) is wrapped too; a NUMBER local maps to numeric.
    numeric = _translate_plsql_block('DECLARE n NUMBER; BEGIN n := 1; END;')
    assert numeric.startswith('DO $$ DECLARE n numeric; BEGIN ')
    # A bare BEGIN with no END (transaction control) is left alone.
    assert _translate_plsql_block('BEGIN') == 'BEGIN'
    # Non-block SQL passes through untouched.
    assert _translate_plsql_block('SELECT 1') == 'SELECT 1'


def test_translate_ddl_leaves_non_create_table_unchanged() -> None:
    # Only CREATE TABLE is rewritten — a DATE literal / type keyword elsewhere
    # (DML, a query) must pass through verbatim.
    for sql in (
        "INSERT INTO t (d) VALUES (DATE '2020-01-01')",
        'SELECT id, v FROM t',
        'UPDATE t SET v = :1 WHERE id = :2',
    ):
        assert _translate_ddl(sql) == sql


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
            PacketStream(conn), PostgresBackend(_CONNINFO, credentials=_CREDS)
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
    # Each temporal PostgreSQL type maps to the Oracle type of matching
    # precision: date → DATE (day), timestamp → TIMESTAMP (sub-second),
    # timestamptz → TIMESTAMPTZ (offset-aware).
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute("select date '2020-12-31' as d")
        date_value = cur.fetchone()[0]
        cur.execute("select timestamp '2024-01-15 13:30:45.123456' as ts")
        ts_value = cur.fetchone()[0]
        cur.execute("select timestamptz '2024-06-01 09:00:00+02' as tz")
        tz_value = cur.fetchone()[0]
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    # DATE keeps day precision (midnight of that day).
    assert date_value == datetime.datetime(2020, 12, 31, 0, 0)
    # TIMESTAMP keeps the microseconds.
    assert ts_value == datetime.datetime(2024, 1, 15, 13, 30, 45, 123456)
    # TIMESTAMPTZ is offset-aware and equals the same instant as 07:00Z.
    assert tz_value.tzinfo is not None
    assert tz_value == datetime.datetime(
        2024, 6, 1, 7, 0, 0, tzinfo=datetime.timezone.utc
    )


def test_interval_day_to_second_column() -> None:
    # A PostgreSQL `interval` (oid 1186) maps to Oracle INTERVAL DAY TO SECOND
    # (#501): psycopg returns a timedelta, which the Mirror encodes as INTERVALDS
    # and the client decodes back to the same timedelta.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute("select interval '5 3:2:1.5' as v")
        value = cur.fetchone()[0]
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert value == datetime.timedelta(
        days=5, hours=3, minutes=2, seconds=1, microseconds=500000
    )


def test_high_precision_numeric() -> None:
    # PostgreSQL numeric returns a Decimal; the Mirror's exact base-100 encoder
    # carries all of it, well past float's ~15 significant digits.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute(
            'select 1.234567890123456789::numeric as a,'
            ' 123456789012345678901234567890::numeric as b,'
            ' (-9999999999.9999999999)::numeric as c'
        )
        row = cur.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == (
        Decimal('1.234567890123456789'),
        Decimal('123456789012345678901234567890'),
        Decimal('-9999999999.9999999999'),
    )


def test_binary_float_and_double_columns() -> None:
    # PostgreSQL float4 / float8 map to Oracle BINARY_FLOAT / BINARY_DOUBLE
    # (Python float, IEEE-exact), while numeric stays NUMBER (Decimal).

    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute(
            'select 3.5::float8 as d, 1.5::float4 as f,'
            ' (-2.25)::float8 as neg, 9.9::numeric(3,1) as amt'
        )
        row = cur.fetchone()
        types = [d[1] for d in cur.description]
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == (3.5, 1.5, -2.25, Decimal('9.9'))
    assert isinstance(row[0], float) and isinstance(row[1], float)
    # description type_code is the seerdb.DB_TYPE_* object (oracledb parity).
    assert types[0] == seerdb.DB_TYPE_BINARY_DOUBLE
    assert types[1] == seerdb.DB_TYPE_BINARY_FLOAT


def test_batched_fetch_large_row_count_postgres() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_batch')
        cur.execute('create table t_batch (n integer)')
        cur.executemany('insert into t_batch values (:1)', [(i,) for i in range(500)])
        cur.execute('select n from t_batch order by n')
        first = cur.fetchmany(10)
        rest = cur.fetchall()
        cur.execute('select count(*) from t_batch')
        count = cur.fetchone()[0]
        cur.execute('drop table t_batch')
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


def test_number_precision_and_scale_in_description() -> None:
    # A PostgreSQL numeric(p, s) column surfaces its precision/scale in
    # cursor.description; an unconstrained integer reports None/None (oracledb
    # parity: precision/scale are None unless one of them is set).
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('select 123.45::numeric(10,2) as amt, 7::int as n')
        cur.fetchall()
        description = cur.description
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    # description tuple: (name, type, display, internal, precision, scale, null_ok)
    amt, n = description[0], description[1]
    assert (amt[4], amt[5]) == (10, 2)
    assert (n[4], n[5]) == (None, None)


def test_executemany_array_dml_postgres() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_many')
        cur.execute('create table t_many (id integer, name varchar(20))')
        cur.executemany(
            'insert into t_many values (:1, :2)',
            [(1, 'a'), (2, 'b'), (3, 'c'), (4, 'd')],
        )
        rowcount = cur.rowcount
        cur.execute('select id, name from t_many order by id')
        rows = cur.fetchall()
        cur.execute('drop table t_many')
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


def test_fractional_number_bind_postgres() -> None:
    # psycopg maps a Decimal bind straight to numeric; the exact value survives
    # (the SQLite backend takes a lossy REAL path — this is the exact one).
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_dec')
        cur.execute('create table t_dec (id integer, v numeric)')
        cur.execute('insert into t_dec values (:1, :2)', [1, Decimal('3.14159')])
        cur.execute('insert into t_dec values (:1, :2)', [2, 2.5])
        cur.execute('select v from t_dec order by id')
        rows = cur.fetchall()
        cur.execute('drop table t_dec')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rows == [(Decimal('3.14159'),), (Decimal('2.5'),)]


def _connect_no_autocommit(port: int):
    return seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
        autocommit=False,
    )


def test_commit_and_rollback_postgres() -> None:
    listen, server, result = _start_mirror()
    conn = _connect_no_autocommit(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_txn')
        conn.commit()
        cur.execute('create table t_txn (n integer)')
        conn.commit()
        cur.execute('insert into t_txn values (1)')
        cur.execute('insert into t_txn values (2)')
        conn.rollback()
        cur.execute('select n from t_txn')
        after_rollback = cur.fetchall()
        cur.execute('insert into t_txn values (3)')
        conn.commit()
        cur.execute('select n from t_txn order by n')
        after_commit = cur.fetchall()
        cur.execute('drop table t_txn')
        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert after_rollback == []
    assert after_commit == [(3,)]


def test_statement_error_keeps_the_transaction() -> None:
    # A failed statement rolls back only itself (via the per-statement SAVEPOINT):
    # the connection stays usable and earlier uncommitted work survives — Oracle's
    # statement-level model, not PostgreSQL's abort-the-whole-transaction default.
    listen, server, result = _start_mirror()
    conn = _connect_no_autocommit(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_iso')
        conn.commit()
        cur.execute('create table t_iso (n integer)')
        conn.commit()
        cur.execute('insert into t_iso values (10)')  # good, uncommitted
        with pytest.raises(seerdb.DatabaseError):
            cur.execute('insert into t_iso values (no_such_column)')  # PG error
        cur.execute('insert into t_iso values (20)')  # connection still usable
        conn.commit()
        cur.execute('select n from t_iso order by n')
        rows = cur.fetchall()
        cur.execute('drop table t_iso')
        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rows == [(10,), (20,)]  # the pre-error row was not rolled back


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


# --- Oracle SQL idiom / function translation (#502) — pure, no live PG needed --


def test_helper_functions_ddl_defines_the_scalar_helpers() -> None:
    # The Oracle scalar functions orafce doesn't cover are installed as real
    # PostgreSQL functions (#513) instead of rewritten per call site, so those
    # call sites resolve directly. Each is defined idempotently (CREATE OR
    # REPLACE) and returns the LOB domains where appropriate.
    for name in (
        'hextoraw',
        'rawtohex',
        'empty_clob',
        'empty_blob',
        'from_tz',
        'rowidtochar',
    ):
        assert f'FUNCTION {name}(' in _HELPER_FUNCTIONS_DDL
    assert _HELPER_FUNCTIONS_DDL.count('CREATE OR REPLACE FUNCTION') == 6
    # rowidtochar is the identity on the text ctid the ROWID pseudo-column rewrites
    # to, so ROWIDTOCHAR(ROWID) equals ROWID.
    assert 'FUNCTION rowidtochar(text) RETURNS text' in _HELPER_FUNCTIONS_DDL
    # empty_clob / empty_blob hand back the domain types, so a value stored
    # through one is recognised as a LOB on read-back rather than a plain string.
    assert 'RETURNS ora_clob' in _HELPER_FUNCTIONS_DDL
    assert 'RETURNS ora_blob' in _HELPER_FUNCTIONS_DDL
    # Oracle's RAWTOHEX yields upper-case hex (PostgreSQL's encode is lower-case).
    assert 'upper(encode(' in _HELPER_FUNCTIONS_DDL
    # from_tz returns the ora_tstz composite (not a plain timestamptz), so a named
    # region's DST-correct offset round-trips into a WITH TIME ZONE column; it is
    # STABLE, since a named region's offset depends on the tz database.
    assert 'FUNCTION from_tz(timestamp, text) RETURNS ora_tstz' in _HELPER_FUNCTIONS_DDL
    assert 'AT TIME ZONE' in _HELPER_FUNCTIONS_DDL
    from_tz_body = _HELPER_FUNCTIONS_DDL.split('from_tz', 1)[1].split(
        'CREATE OR REPLACE', 1
    )[0]
    assert 'IMMUTABLE' not in from_tz_body


def test_translate_idioms_functions_and_literals() -> None:
    assert _translate_idioms('SELECT SYSDATE') == 'SELECT localtimestamp(0)'
    # HEXTORAW / RAWTOHEX, EMPTY_CLOB / EMPTY_BLOB and FROM_TZ are installed as
    # real PostgreSQL functions (_HELPER_FUNCTIONS_DDL), so their call sites
    # resolve directly and pass through the idiom translation unchanged — just
    # like the orafce-provided NVL / DECODE / TO_CHAR do.
    assert _translate_idioms("SELECT NVL(:v, 'x')") == "SELECT NVL(:v, 'x')"
    assert _translate_idioms("SELECT HEXTORAW('DEADBEEF')") == (
        "SELECT HEXTORAW('DEADBEEF')"
    )
    assert _translate_idioms('INSERT INTO t VALUES (EMPTY_CLOB())') == (
        'INSERT INTO t VALUES (EMPTY_CLOB())'
    )
    assert (
        _translate_idioms(
            "SELECT FROM_TZ(TIMESTAMP '2024-01-15 12:00:00', 'US/Eastern')"
        )
        == "SELECT FROM_TZ(TIMESTAMP '2024-01-15 12:00:00', 'US/Eastern')"
    )


def test_translate_idioms_rewrites_rowid_pseudocolumn() -> None:
    # The ROWID pseudo-column becomes ctid::text — one rewrite serving both a
    # SELECT (returns the '(0,1)' text) and a WHERE ROWID = :bind (text compare).
    assert _translate_idioms('SELECT ROWID FROM t') == 'SELECT ctid::text FROM t'
    assert _translate_idioms('SELECT id FROM t WHERE ROWID = :r') == (
        'SELECT id FROM t WHERE ctid::text = :r'
    )
    # The word boundary keeps it off ROWIDTOCHAR (no boundary mid-token) — that call
    # resolves to the installed identity helper — and off UROWID (a word char
    # precedes ROWID), so a UROWID column type name is left intact.
    assert _translate_idioms('SELECT ROWIDTOCHAR(ROWID) FROM t') == (
        'SELECT ROWIDTOCHAR(ctid::text) FROM t'
    )
    assert _translate_idioms('CREATE TABLE t (r UROWID)') == (
        'CREATE TABLE t (r UROWID)'
    )
    # Case-insensitive, like the other pseudo-column rewrites.
    assert _translate_idioms('select rowid from t') == 'select ctid::text from t'


def test_translate_idioms_binary_float_double_literals() -> None:
    # The BINARY_DOUBLE / BINARY_FLOAT literal suffix is dropped; the special
    # values become IEEE-754 float literals.
    assert _translate_idioms('VALUES (1234.5678d)') == 'VALUES (1234.5678)'
    assert _translate_idioms('VALUES (-2.25f)') == 'VALUES (-2.25)'
    assert _translate_idioms('VALUES (binary_double_infinity)') == (
        "VALUES ('Infinity'::float8)"
    )
    assert _translate_idioms('VALUES (binary_double_nan)') == "VALUES ('NaN'::float8)"
    # A decimal point is required, so a plain integer or identifier is untouched.
    assert _translate_idioms('SELECT id2 FROM t') == 'SELECT id2 FROM t'
    assert _translate_idioms('VALUES (100)') == 'VALUES (100)'


# --- Oracle-only type rejection (#504) — a pure check, no live PG needed --------


def test_reject_oracle_only_ddl_types_raises_ora_902() -> None:
    from seerdb.server import BackendError

    # JSON (21c+), VECTOR / BOOLEAN (23ai+) are invalid at the 11.2 version the
    # Mirror advertises, so a CREATE TABLE using one is refused with ORA-00902 —
    # which is exactly what the suite's version guards skip on.
    for coltype in ('doc JSON', 'v VECTOR(3, FLOAT32)', 'flag BOOLEAN'):
        with pytest.raises(BackendError) as exc:
            _reject_unsupported_ddl_types(f'CREATE TABLE t (id NUMBER, {coltype})')
        assert exc.value.ora_code == 902

    # An ordinary CREATE TABLE — and any non-CREATE-TABLE statement — is fine.
    _reject_unsupported_ddl_types('CREATE TABLE t (id NUMBER, v VARCHAR2(10))')
    _reject_unsupported_ddl_types('SELECT json_col FROM t WHERE flag = 1')


def test_reject_create_domain_raises_ora_901() -> None:
    from seerdb.server import BackendError

    # SQL domains are 23ai; the 11.2 Mirror's server doesn't know CREATE DOMAIN, so
    # it is refused with ORA-00901 — one of the codes the suite's SQL-domain guard
    # skips on (#512). A domain-referencing CREATE TABLE is not itself a domain
    # definition and passes this check.
    with pytest.raises(BackendError) as exc:
        _reject_unsupported_ddl_types('CREATE DOMAIN PYO_DOM_T AS NUMBER(3,0)')
    assert exc.value.ora_code == 901
    _reject_unsupported_ddl_types(
        'CREATE TABLE t (id NUMBER, d NUMBER DOMAIN PYO_DOM_T)'
    )


# --- PL/SQL routine translation (#503) — a pure function, no live PG needed -----


def test_translate_routine_ddl_procedure() -> None:
    out = _translate_routine_ddl(
        'CREATE OR REPLACE PROCEDURE p '
        '(p_in IN NUMBER, p_out OUT NUMBER, p_io IN OUT VARCHAR2) '
        'AS BEGIN p_out := p_in * 2; END;'
    )
    # DROP-first so a changed signature can replace a prior definition (#521).
    assert out.startswith('DROP PROCEDURE IF EXISTS p; CREATE OR REPLACE PROCEDURE p(')
    assert 'p_in IN numeric' in out
    assert 'p_out OUT numeric' in out
    assert 'p_io INOUT varchar' in out  # IN OUT -> INOUT
    assert 'LANGUAGE plpgsql AS $$ BEGIN p_out := p_in * 2; END $$' in out


def test_translate_routine_ddl_function() -> None:
    out = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION f(p IN NUMBER) RETURN NUMBER '
        'AS BEGIN RETURN p + 100; END;'
    )
    assert out.startswith(
        'DROP FUNCTION IF EXISTS f; '
        'CREATE OR REPLACE FUNCTION f(p IN numeric) RETURNS numeric'
    )
    assert 'LANGUAGE plpgsql AS $$ BEGIN RETURN p + 100; END $$' in out


def test_translate_routine_ddl_parameterless_function() -> None:
    # Oracle lets a no-parameter routine omit the list entirely; PostgreSQL always
    # needs the parentheses, so an absent list becomes an empty one (#530). A body
    # containing its own parentheses still parses (params don't swallow the body).
    out = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION f RETURN BINARY_DOUBLE AS BEGIN RETURN 2.25; END;'
    )
    assert 'CREATE OR REPLACE FUNCTION f() RETURNS double precision' in out
    assert 'LANGUAGE plpgsql AS $$ BEGIN RETURN 2.25; END $$' in out
    withbody = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION g(x IN NUMBER) RETURN NUMBER '
        'AS BEGIN RETURN x * (x + 1); END;'
    )
    assert 'FUNCTION g(x IN numeric) RETURNS numeric' in withbody
    assert 'BEGIN RETURN x * (x + 1); END' in withbody


def test_translate_routine_ddl_maps_sys_refcursor_out() -> None:
    # A REF CURSOR OUT parameter (SYS_REFCURSOR) maps to PostgreSQL's refcursor; the
    # OPEN … FOR body is already valid PL/pgSQL (#518).
    out = _translate_routine_ddl(
        'CREATE OR REPLACE PROCEDURE seerdb_test_proc (p_rc OUT SYS_REFCURSOR) '
        'AS BEGIN OPEN p_rc FOR SELECT 1 AS a FROM dual; END;'
    )
    assert 'p_rc OUT refcursor' in out
    assert 'SYS_REFCURSOR' not in out
    assert 'OPEN p_rc FOR SELECT 1 AS a FROM dual' in out


def test_translate_routine_ddl_drops_before_create() -> None:
    # PostgreSQL cannot change an existing routine's OUT/return row type via CREATE
    # OR REPLACE; the suite reuses one name with different signatures, so a DROP …
    # IF EXISTS by name precedes every CREATE (#521).
    proc = _translate_routine_ddl(
        'CREATE OR REPLACE PROCEDURE seerdb_test_proc (p OUT TIMESTAMP) '
        'AS BEGIN p := SYSTIMESTAMP; END;'
    )
    assert proc.startswith(
        'DROP PROCEDURE IF EXISTS seerdb_test_proc; CREATE OR REPLACE'
    )
    func = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION seerdb_test_func(p IN NUMBER) RETURN NUMBER '
        'AS BEGIN RETURN p; END;'
    )
    assert func.startswith(
        'DROP FUNCTION IF EXISTS seerdb_test_func; CREATE OR REPLACE'
    )


def test_translate_routine_ddl_leaves_other_sql_unchanged() -> None:
    for sql in ('SELECT 1', 'CREATE TABLE t (id NUMBER)', 'BEGIN p(:1); END;'):
        assert _translate_routine_ddl(sql) == sql


# --- changepassword (#515) — credential-map only, no live PG needed -------------


class _NoConnPostgresBackend(PostgresBackend):
    # Skip the psycopg connect / orafce setup — change_password only touches the
    # credential map, so no live PostgreSQL is needed to test it.
    def __init__(self, credentials: dict) -> None:
        self._credentials = credentials


def test_change_password_updates_the_shared_credential_map() -> None:

    creds = {'PYO': 'pyo123'}
    backend = _NoConnPostgresBackend(creds)
    backend.change_password('PYO', 'pyo123', 'pyo123_new')
    # The shared map now carries the new secret (a fresh session authenticates
    # with it); the backend's own PostgreSQL conninfo is untouched.
    assert creds['PYO'] == 'pyo123_new'
    # Case-insensitive on the username, like Oracle.
    backend.change_password('pyo', 'pyo123_new', 'again')
    assert creds['PYO'] == 'again'


def test_change_password_rejects_a_wrong_old_password() -> None:
    from seerdb.server import BackendError

    backend = _NoConnPostgresBackend({'PYO': 'pyo123'})
    with pytest.raises(BackendError) as exc:
        backend.change_password('PYO', 'not-the-old-one', 'whatever')
    assert exc.value.ora_code == 1017


# --- Bind translation (#516) — a pure function, no live PG needed --------------


def test_translate_binds_repeated_named_bind_is_one_value() -> None:
    # `:x` twice is one Oracle value → one psycopg parameter reused, not two.
    sql, params = _translate_binds('SELECT id FROM t WHERE id = :x OR :x IS NULL', [1])
    assert sql == 'SELECT id FROM t WHERE id = %(x)s OR %(x)s IS NULL'
    assert params == {'x': 1}


def test_translate_binds_skips_colon_inside_string_literal() -> None:
    sql, params = _translate_binds(
        "INSERT INTO t VALUES ('hello :not_a_bind ' || :v)", ['world']
    )
    assert sql == "INSERT INTO t VALUES ('hello :not_a_bind ' || %(v)s)"
    assert params == {'v': 'world'}


def test_translate_binds_positional_and_casts() -> None:
    # Positional :1/:2 map by order; a :: cast is left alone.
    sql, params = _translate_binds('INSERT INTO t VALUES (:1, :2)', [7, 'a'])
    assert sql == 'INSERT INTO t VALUES (%(b1)s, %(b2)s)'
    assert params == {'b1': 7, 'b2': 'a'}
    sql, params = _translate_binds('SELECT :a::text FROM t', ['x'])
    assert sql == 'SELECT %(a)s::text FROM t'
    assert params == {'a': 'x'}


def test_translate_binds_mixed_named_first_appearance_order() -> None:
    sql, params = _translate_binds(
        'SELECT * FROM t WHERE a = :x AND b = :y AND c = :x', [1, 2]
    )
    assert sql == 'SELECT * FROM t WHERE a = %(x)s AND b = %(y)s AND c = %(x)s'
    assert params == {'x': 1, 'y': 2}


# --- Anonymous PL/SQL blocks with binds (#517) — pure helpers, no live PG ------


def test_parse_out_assignments_recognises_assignment_blocks() -> None:
    # A pure OUT-assignment block → the (ref, expr) pairs; anything else → None.
    assert _parse_out_assignments(':y := 7 * 6') == [('y', '7 * 6')]
    assert _parse_out_assignments(":1 := 'x'; :2 := NULL; :3 := 'z'") == [
        ('1', "'x'"),
        ('2', 'NULL'),
        ('3', "'z'"),
    ]
    # A DML block is not an assignment block.
    assert _parse_out_assignments('INSERT INTO t VALUES (:x)') is None
    assert _parse_out_assignments('proc(:a, :b)') is None


def test_distinct_bind_refs_first_appearance_order_skips_literals() -> None:
    assert _distinct_bind_refs(':a := :b; :c := :a') == ['a', 'b', 'c']
    # A colon inside a string literal is not a bind ref.
    assert _distinct_bind_refs("INSERT INTO t VALUES ('x :nope' || :v)") == ['v']
