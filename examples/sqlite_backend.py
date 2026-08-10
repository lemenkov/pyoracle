# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A SQLite backend for the Mirror — stdlib only, the reference Backend.

Point a Mirror at a SQLite database and thin-dialect Oracle clients (seerdb,
SeerODBC) can run real SQL against it. SQLite's permissive typing accepts
Oracle-ish DDL (``NUMBER``, ``VARCHAR2(n)``) via type affinity, so plain tables
"just work". SQLite carries no static column types, so the Mirror infers each
result column's Oracle type from its values.

This lives outside ``seerdb`` core (it is only a demo/adapter), but adds no
dependency — ``sqlite3`` is in the standard library.
"""

from __future__ import annotations

import datetime
import re
import sqlite3
from collections.abc import Sequence
from decimal import Decimal

# Oracle numbered/named binds (:1, :name) → SQLite positional '?'. The negative
# lookbehind leaves any '::' cast untouched.
_ORACLE_BIND = re.compile(r'(?<!:):\w+')

from seerdb.common.tns_consts import (
    TNS_TYPE_DATE,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_VARCHAR,
)
from seerdb.server import BackendError, Capability, ColumnMeta, Result

# ORA-00900: invalid SQL statement — the generic code for a SQL the backend
# rejected (syntax, unknown table, ...).
_ORA_INVALID_SQL = 900


def _adapt_int(value: int) -> int | float:
    # SQLite's INTEGER is 64-bit; an in-range int stays exact, a larger one (an
    # Oracle NUMBER can hold ~38 digits) falls back to REAL.
    if -(2**63) <= value < 2**63:
        return value
    return float(value)


# SQLite stores no real temporal type, so DATE/TIMESTAMP survive a round trip
# only if we (de)serialise them ourselves. The stdlib's built-in date/timestamp
# adapters are deprecated (3.12) and gone in newer Python, so register explicit
# ISO-8601 ones — module-global, matching sqlite3's own registry scope. A
# TIMESTAMP column round-trips microseconds; a DATE column keeps day precision.
def _register_codecs() -> None:
    sqlite3.register_adapter(datetime.date, datetime.date.isoformat)
    sqlite3.register_adapter(datetime.datetime, lambda dt: dt.isoformat(sep=' '))
    # A DATE bind arrives over the wire as a midnight datetime, so a DATE column
    # may hold 'YYYY-MM-DD HH:MM:SS'; keep only the date part (leading 10 chars).
    sqlite3.register_converter(
        'date', lambda blob: datetime.date.fromisoformat(blob.decode()[:10])
    )
    sqlite3.register_converter(
        'timestamp', lambda blob: datetime.datetime.fromisoformat(blob.decode())
    )
    # A fractional NUMBER bind decodes to a Decimal, which sqlite3 refuses
    # natively. SQLite has no exact-decimal storage class, so bind it as REAL
    # (float) — the same lossy-but-numeric form this backend already infers for
    # NUMBER columns. Integral NUMBERs arrive as int and need no adapter.
    sqlite3.register_adapter(Decimal, float)
    # An Oracle NUMBER integer beyond SQLite's 64-bit INTEGER range can't be
    # stored as one; _adapt_int keeps in-range ints exact and spills larger ones
    # to REAL (lossy, like Decimal) rather than leaking sqlite3's "int too large"
    # as an ORA-00600.
    sqlite3.register_adapter(int, _adapt_int)


def _adapt_int(value: int) -> int | float:
    if -(2**63) <= value < 2**63:
        return value
    return float(value)


_register_codecs()


def _column_meta(name: str, values: list) -> ColumnMeta:
    # Infer an Oracle column type from the first non-NULL value. Oracle folds
    # unquoted identifiers to upper-case, so match that on the name.
    ident = name.upper().encode('utf-8')
    sample = next((v for v in values if v is not None), None)
    if isinstance(sample, bool):
        # bool is an int subclass; a NUMBER either way, matched first for clarity.
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22
        )
    if isinstance(sample, (int, float)):
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22
        )
    if isinstance(sample, datetime.datetime):
        # datetime is a date subclass, so match it before the plain-date branch:
        # a declared TIMESTAMP column keeps its time-of-day and sub-second parts.
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_TIMESTAMP, data_length=11, max_size=11
        )
    if isinstance(sample, datetime.date):
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_DATE, data_length=7, max_size=7
        )
    if isinstance(sample, bytes):
        width = max((len(v) for v in values if isinstance(v, bytes)), default=1)
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_RAW, data_length=width, max_size=width
        )
    width = max((len(str(v)) for v in values if v is not None), default=1)
    return ColumnMeta(
        name=ident, data_type=TNS_TYPE_VARCHAR, data_length=width, max_size=width
    )


class SqliteBackend:
    """A :class:`~seerdb.server.Backend` over a stdlib ``sqlite3`` connection.

    One instance per Mirror session. Use ``:memory:`` for an isolated
    per-session database, or a file path to share and persist data across
    sessions.
    """

    capabilities = frozenset({Capability.TRANSACTIONS})

    def __init__(self, database: str = ':memory:') -> None:
        # PARSE_DECLTYPES turns a column declared DATE / TIMESTAMP back into a
        # datetime.date / datetime.datetime via the converters registered above.
        self._conn = sqlite3.connect(database, detect_types=sqlite3.PARSE_DECLTYPES)

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        if binds:
            sql = _ORACLE_BIND.sub('?', sql)
        try:
            cursor = self._conn.execute(sql, tuple(binds))
        except sqlite3.Error as exc:
            # A SQLite failure surfaces as a clean ORA error — never a desync.
            raise BackendError(str(exc), ora_code=_ORA_INVALID_SQL) from exc
        if cursor.description is None:
            # DDL / DML: no result set, just an affected-row count.
            return Result(rowcount=max(cursor.rowcount, 0))
        rows = cursor.fetchall()
        columns = [
            _column_meta(description[0], [row[index] for row in rows])
            for index, description in enumerate(cursor.description)
        ]
        return Result(columns=columns, rows=rows)

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()
