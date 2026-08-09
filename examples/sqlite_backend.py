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

import re
import sqlite3
from collections.abc import Sequence

# Oracle numbered/named binds (:1, :name) → SQLite positional '?'. The negative
# lookbehind leaves any '::' cast untouched.
_ORACLE_BIND = re.compile(r'(?<!:):\w+')

from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_RAW, TNS_TYPE_VARCHAR
from seerdb.server import BackendError, Capability, ColumnMeta, Result

# ORA-00900: invalid SQL statement — the generic code for a SQL the backend
# rejected (syntax, unknown table, ...).
_ORA_INVALID_SQL = 900


def _column_meta(name: str, values: list) -> ColumnMeta:
    # Infer an Oracle column type from the first non-NULL value. Oracle folds
    # unquoted identifiers to upper-case, so match that on the name.
    ident = name.upper().encode('utf-8')
    sample = next((v for v in values if v is not None), None)
    if isinstance(sample, (bool, int, float)):
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22
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
        self._conn = sqlite3.connect(database)

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
