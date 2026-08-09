# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A PostgreSQL backend for the Mirror (psycopg 3).

Point a Mirror at a PostgreSQL database and thin-dialect Oracle clients run real
SQL against it. Result columns map from PostgreSQL type OIDs to Oracle types; a
column whose type the Mirror cannot yet represent is refused with a clean
``ORA-03001`` (unimplemented feature) rather than mis-encoded — the same
capabilities-and-errors contract SQLite uses, just with a different set of
supported types.

Requires the ``psycopg`` package. This is a demo/adapter outside ``seerdb``
core; the driver dependency lives here, not in the library.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import psycopg

from seerdb.common.tns_consts import (
    TNS_TYPE_DATE,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
)
from seerdb.server import (
    BackendError,
    Capability,
    ColumnMeta,
    Result,
    UnsupportedFeature,
)

# Oracle numbered/named binds (:1, :name) → psycopg positional '%s'. The
# negative lookbehind leaves any '::' cast untouched.
_ORACLE_BIND = re.compile(r'(?<!:):\w+')

# PostgreSQL type OIDs (pg_type.oid) → Oracle wire type.
_NUMBER_OIDS = frozenset(
    {
        16,
        20,
        21,
        23,
        26,
        700,
        701,
        1700,
    }  # bool int8 int2 int4 oid float4 float8 numeric
)
_TEXT_OIDS = frozenset({18, 19, 25, 1042, 1043})  # char name text bpchar varchar
_RAW_OIDS = frozenset({17})  # bytea
# Each PostgreSQL temporal OID maps to the Oracle type of matching precision:
# a bare date → DATE (7 bytes), timestamp → TIMESTAMP (11), timestamptz → 13.
_TEMPORAL_OIDS = {
    1082: (TNS_TYPE_DATE, 7),  # date
    1114: (TNS_TYPE_TIMESTAMP, 11),  # timestamp (without time zone)
    1184: (TNS_TYPE_TIMESTAMPTZ, 13),  # timestamptz
}

_ORA_INVALID_SQL = 900


def _column_meta(name: str, oid: int, values: list) -> ColumnMeta:
    ident = name.upper().encode('utf-8')
    if oid in _NUMBER_OIDS:
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22
        )
    if oid in _TEMPORAL_OIDS:
        data_type, width = _TEMPORAL_OIDS[oid]
        return ColumnMeta(
            name=ident, data_type=data_type, data_length=width, max_size=width
        )
    if oid in _RAW_OIDS:
        width = max(
            (len(v) for v in values if isinstance(v, (bytes, bytearray, memoryview))),
            default=1,
        )
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_RAW, data_length=width, max_size=width
        )
    if oid in _TEXT_OIDS:
        width = max((len(str(v)) for v in values if v is not None), default=1)
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_VARCHAR, data_length=width, max_size=width
        )
    raise UnsupportedFeature(
        f'column {name!r}: PostgreSQL type oid {oid} is not supported yet'
    )


class PostgresBackend:
    """A :class:`~seerdb.server.Backend` over a psycopg connection.

    One instance per Mirror session. ``conninfo`` is a libpq connection string,
    e.g. ``host=127.0.0.1 port=5432 user=pyo password=... dbname=mirror``.
    Autocommit is on so each statement persists (matching the Oracle client's
    default autocommit).
    """

    capabilities = frozenset({Capability.TRANSACTIONS})

    def __init__(self, conninfo: str = '') -> None:
        self._conn = psycopg.connect(conninfo, autocommit=True)

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        if binds:
            sql = _ORACLE_BIND.sub('%s', sql)
        try:
            cursor = self._conn.execute(sql, tuple(binds) or None)
        except psycopg.Error as exc:
            # A PostgreSQL failure surfaces as a clean ORA error — never a desync.
            raise BackendError(str(exc).strip(), ora_code=_ORA_INVALID_SQL) from exc
        if cursor.description is None:
            return Result(rowcount=max(cursor.rowcount, 0))
        rows = cursor.fetchall()
        columns = [
            _column_meta(desc.name, desc.type_code, [row[index] for row in rows])
            for index, desc in enumerate(cursor.description)
        ]
        return Result(columns=columns, rows=rows)

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()
