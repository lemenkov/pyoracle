# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""An Oracle/sqlplus session-bootstrap shim over any Backend.

Classic sqlplus fires a fixed chain of Oracle-specific queries the moment it
connects — ``SELECT USER FROM DUAL``, a ``DECODE()`` compatibility probe,
``SYSTEM.PRODUCT_PRIVS`` lookups, ``DBMS_OUTPUT`` / ``DBMS_APPLICATION_INFO``
PL/SQL calls — before it shows a prompt, and it *aborts* if some of them answer
wrong (the DECODE probe especially). A generic backend (SQLite, PostgreSQL)
can't evaluate those Oracle idioms.

``OracleCompatBackend`` wraps any backend and answers just that fixed bootstrap
set itself, passing every real statement straight through to the inner backend.
It is deliberately **not** a general Oracle→backend SQL translator — only the
narrow, known set sqlplus needs to establish a session. With it, a real sqlplus
reaches the ``SQL>`` prompt against a plain SQLite/PostgreSQL Mirror and can then
run actual DDL/DML/queries.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
from seerdb.server import Backend, BackendError, ColumnMeta, Result

# Oracle's one-row ``DUAL`` table has no equal on a plain backend, but a bare
# ``SELECT <expr>`` (no FROM) is the same thing there — so drop a trailing
# ``FROM DUAL`` before delegating. Only the exact idiom, nothing cleverer.
_FROM_DUAL = re.compile(r'\s+FROM\s+DUAL\s*$', re.IGNORECASE)

# ORA-00942: table or view does not exist — sqlplus's PRODUCT_PRIVS lookup hits
# this on a backend without the profile table, and tolerates it (it prints the
# familiar "Product user profile information not loaded" warning and continues).
_ORA_NO_SUCH_TABLE = 942

# The sqlplus ``VARIABLE v NUMBER`` / ``EXEC :v := 42`` flow sends a PL/SQL block
# that assigns literals to OUT binds — ``BEGIN :n := 42; :s := 'hi'; END;``. A
# non-Oracle backend can't run PL/SQL, but this one idiom (assign a literal to a
# bind) is trivially evaluable, and covers the common case: bind a value, then use
# it in a following statement. Only literal assignments — nothing that reads state.
_OUT_BIND_ASSIGN = re.compile(
    r":\w+\s*:=\s*('(?:[^']|'')*'|-?\d+(?:\.\d+)?)", re.IGNORECASE
)


def _plsql_out_bind_values(sql: str) -> list:
    """Extract the OUT values from ``BEGIN :v := <literal>; ... END;``.

    Returns the assigned values in statement (= bind) order. Empty when the block
    has no simple literal assignments (a real PL/SQL call we just acknowledge).
    """
    values: list = []
    for match in _OUT_BIND_ASSIGN.finditer(sql):
        literal = match.group(1)
        if literal.startswith("'"):
            values.append(literal[1:-1].replace("''", "'"))
        elif '.' in literal:
            values.append(float(literal))
        else:
            values.append(int(literal))
    return values


def _varchar(name: bytes, width: int) -> ColumnMeta:
    return ColumnMeta(
        name=name, data_type=TNS_TYPE_VARCHAR, data_length=width, max_size=width
    )


class OracleCompatBackend:
    """Answer sqlplus's session-bootstrap queries; delegate the rest."""

    def __init__(self, inner: Backend) -> None:
        self._inner = inner
        self._user = 'USER'

    @property
    def capabilities(self):  # type: ignore[no-untyped-def]
        return self._inner.capabilities

    def authenticate(self, username: str) -> str | None:
        secret = self._inner.authenticate(username)
        if secret is not None:
            # Oracle folds an unquoted identifier to upper case; SELECT USER
            # reports it that way.
            self._user = username.upper()
        return secret

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        normalized = ' '.join(sql.strip().upper().split())
        if normalized.startswith('BEGIN'):
            # A PL/SQL block. The ``EXEC :v := <literal>`` form assigns OUT binds
            # the client reads back — evaluate those literal assignments. Any other
            # PL/SQL session call (DBMS_OUTPUT.DISABLE, SET_MODULE) has no effect on
            # a non-Oracle backend, so acknowledge success and move on.
            out_binds = _plsql_out_bind_values(sql)
            return Result(out_binds=out_binds) if out_binds else Result()
        if 'PRODUCT_PRIVS' in normalized:
            raise BackendError(
                'table or view does not exist', ora_code=_ORA_NO_SUCH_TABLE
            )
        if normalized == 'SELECT USER FROM DUAL':
            return Result(columns=[_varchar(b'USER', 30)], rows=[(self._user,)])
        if "DECODE('A','A','1','2')" in normalized.replace(' ', ''):
            # sqlplus's compatibility probe — DECODE('A','A','1','2') is '1'.
            return Result(columns=[_varchar(b'DECODE', 1)], rows=[('1',)])
        # A bare `SELECT <expr> FROM DUAL` maps to `SELECT <expr>` on the backend.
        if _FROM_DUAL.search(sql):
            return self._inner.execute(_FROM_DUAL.sub('', sql.strip()), binds)
        # Every other statement is a real one — the inner backend runs it (and,
        # being dialect-specific, translates Oracle SQL to its own dialect there).
        return self._inner.execute(sql, binds)

    def commit(self) -> None:
        self._inner.commit()

    def rollback(self) -> None:
        self._inner.rollback()

    def close(self) -> None:
        self._inner.close()
