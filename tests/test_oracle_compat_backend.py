# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""OracleCompatBackend answers sqlplus's session-bootstrap queries.

The shim intercepts the fixed Oracle-specific queries sqlplus fires on login
(SELECT USER, the DECODE probe, PRODUCT_PRIVS, PL/SQL calls, FROM DUAL) and
passes everything else straight to the inner backend — verified here without a
wire in sight.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from seerdb.server import BackendError, Result

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'examples'))
from oracle_compat_backend import OracleCompatBackend  # noqa: E402


class _FakeInner:
    capabilities = frozenset()

    def __init__(self) -> None:
        self.calls: list[str] = []

    def authenticate(self, username: str) -> str | None:
        return 'pyo123' if username.upper() == 'PYO' else None

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        self.calls.append(sql)
        return Result(rowcount=1)

    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def close(self) -> None: ...


def test_answers_select_user_with_the_authenticated_name() -> None:
    inner = _FakeInner()
    backend = OracleCompatBackend(inner)
    backend.authenticate('pyo')
    result = backend.execute('SELECT USER FROM DUAL')
    assert result.rows == [('PYO',)]  # Oracle folds the name to upper case
    assert inner.calls == []  # answered by the shim, not delegated


def test_answers_the_decode_compat_probe() -> None:
    result = OracleCompatBackend(_FakeInner()).execute(
        "SELECT DECODE('A','A','1','2') FROM DUAL"
    )
    assert result.rows == [('1',)]


def test_product_privs_lookup_raises_ora_942() -> None:
    with pytest.raises(BackendError) as excinfo:
        OracleCompatBackend(_FakeInner()).execute(
            'SELECT ATTRIBUTE FROM SYSTEM.PRODUCT_PRIVS WHERE 1=1'
        )
    assert excinfo.value.ora_code == 942


def test_plsql_block_is_a_noop_success() -> None:
    inner = _FakeInner()
    result = OracleCompatBackend(inner).execute('BEGIN DBMS_OUTPUT.DISABLE; END;')
    assert result.columns == [] and inner.calls == []


def test_from_dual_is_stripped_before_delegation() -> None:
    inner = _FakeInner()
    OracleCompatBackend(inner).execute('select 1 from dual')
    assert inner.calls == ['select 1']


def test_real_statements_pass_through_untouched() -> None:
    inner = _FakeInner()
    OracleCompatBackend(inner).execute('SELECT * FROM t')
    assert inner.calls == ['SELECT * FROM t']


def test_exec_assigns_out_binds_for_the_variable_flow() -> None:
    # sqlplus `VARIABLE n NUMBER; EXEC :n := 7` sends a PL/SQL block that assigns
    # a literal to an OUT bind; the shim evaluates it and returns the value so the
    # client reads it back (the assignment order is the bind order).
    inner = _FakeInner()
    result = OracleCompatBackend(inner).execute("BEGIN :n := 7; :s := 'hi'; END;")
    assert result.out_binds == [7, 'hi']
    assert inner.calls == []  # evaluated by the shim, never delegated


def test_plsql_without_assignments_stays_a_noop() -> None:
    # A real PL/SQL session call (no literal OUT-bind assignment) has no OUT binds
    # to return — still a plain success, not an OUT-bind reply.
    result = OracleCompatBackend(_FakeInner()).execute(
        'BEGIN DBMS_OUTPUT.DISABLE; END;'
    )
    assert result.out_binds == []
