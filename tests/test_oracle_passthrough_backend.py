# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline unit tests for the Oracle-passthrough example backend's error relay.

The passthrough is the Mirror's conformance harness (it relays each statement to
a real Oracle). A real Oracle error already reads ``ORA-NNNNN: ...``; the Mirror
(``BackendError``) re-adds that prefix from the code, so relaying the text
verbatim doubled it. ``_relay_error`` strips the leading prefix so exactly one is
emitted — the behaviour these tests pin without needing a database.
"""

from __future__ import annotations

import sys
from pathlib import Path

import seerdb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'examples'))
from oracle_passthrough_backend import (  # noqa: E402
    OraclePassthroughBackend,
    _relay_error,
)


def test_strips_the_redundant_ora_prefix():
    exc = seerdb.DatabaseError('ORA-00904: "X": invalid identifier', 904)
    err = _relay_error(exc)
    # The Mirror re-adds "ORA-00904: " from the code — the relayed message must be
    # bare so the final text carries the prefix exactly once.
    assert err.ora_code == 904
    assert err.ora_message == 'ORA-00904: "X": invalid identifier'


def test_recovers_the_code_from_the_prefix_when_absent():
    # Some client exceptions carry no numeric code; take it from the text.
    exc = seerdb.DatabaseError('ORA-01008: not all variables bound', None)
    err = _relay_error(exc)
    assert err.ora_code == 1008
    assert err.ora_message == 'ORA-01008: not all variables bound'


def test_message_without_a_prefix_is_left_alone():
    exc = seerdb.DatabaseError('some non-Oracle failure', None)
    err = _relay_error(exc)
    assert err.ora_code == 900  # ORA-00900, the BackendError default
    assert err.ora_message == 'ORA-00900: some non-Oracle failure'


def test_code_argument_wins_over_the_prefix_digits():
    # exc.code is authoritative when present, even if the text's digits differ.
    exc = seerdb.DatabaseError('ORA-00942: table or view does not exist', 942)
    err = _relay_error(exc)
    assert err.ora_code == 942
    assert err.ora_message == 'ORA-00942: table or view does not exist'


def test_relays_the_error_offset():
    # oracledb's DatabaseError.offset (the parse offset) is carried into the
    # BackendError so the Mirror draws its caret under the right column.
    exc = seerdb.DatabaseError('ORA-00904: "X": invalid identifier', 904)
    exc.offset = 7
    err = _relay_error(exc)
    assert err.error_offset == 7


def test_missing_offset_is_none():
    exc = seerdb.DatabaseError('ORA-00942: table or view does not exist', 942)
    # .offset defaults to None on a DatabaseError with no parse position.
    err = _relay_error(exc)
    assert err.error_offset is None


class _FakeVar:
    def __init__(self, value=None):
        self._value = value

    def setvalue(self, _pos, value):
        self._value = value

    def getvalue(self):
        return self._value


class _FakeCursor:
    """Records what _execute_plsql binds, without a database."""

    def __init__(self, out_values=None):
        self.bound = None
        self.declared = None
        self.description = None
        self.rowcount = 0
        self._out_values = out_values or {}

    def var(self, dbtype, size=None):
        return _FakeVar()

    def setinputsizes(self, *args):
        self.declared = args

    def execute(self, sql, variables):
        self.bound = list(variables)
        # Seed each Var with a fake OUT value so getvalue() returns something.
        for i, v in enumerate(self.bound):
            if isinstance(v, _FakeVar):
                v.setvalue(0, self._out_values.get(i))


def _plsql_binds(*binds):
    from seerdb.server.backend import BindVar

    return [BindVar(value=v, tns_type=t, max_size=m) for (v, t, m) in binds]


def test_typed_null_of_an_ordinary_statement_is_declared_upstream():
    # A NULL bind arrives as a BindVar with the type the client declared for
    # it (#699); the passthrough declares that type on its own cursor the same
    # way (setinputsizes) and binds the NULL, rather than taking the BindVar
    # for a PL/SQL OUT bind.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server.backend import BindVar

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _FakeCursor()
    backend._conn = type('Conn', (), {'cursor': lambda self: cursor})()
    (typed,) = _plsql_binds((None, TNS_TYPE_NUMBER, 22))
    result = backend.execute('SELECT id FROM t WHERE :1 IS NULL', [typed, 'x'])
    assert cursor.declared == (seerdb.DB_TYPE_NUMBER, None)
    assert cursor.bound == [None, 'x']
    assert result.rowcount == 0 and not result.out_binds
    assert not isinstance(cursor.bound[0], BindVar)


def test_large_lob_in_bind_is_bound_as_a_plain_value_not_a_var():
    # A large CLOB / BLOB IN bind (#91) resolves to plain str / bytes; the
    # passthrough must bind that value directly (seerdb re-promotes it upstream),
    # not a cursor.var(LOB) — which has no client-side OAC (ORA-00600 "Unsupported
    # Var OAC type"). Its OUT slot is None; a real OUT Var still returns its value.
    from seerdb.common.tns_consts import TNS_TYPE_CLOB, TNS_TYPE_NUMBER

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _FakeCursor(out_values={1: 42})
    binds = _plsql_binds(
        ('X' * 40000, TNS_TYPE_CLOB, 160000), (None, TNS_TYPE_NUMBER, 1)
    )
    result = backend._execute_plsql(cursor, 'BEGIN :r := f(:p); END;', binds)
    # :p bound as the plain string; :r bound as a Var.
    assert cursor.bound[0] == 'X' * 40000
    assert isinstance(cursor.bound[1], _FakeVar)
    # OUT binds: the LOB IN slot is None (discarded by the client); the Var yields
    # its assigned value.
    assert result.out_binds == [None, 42]
