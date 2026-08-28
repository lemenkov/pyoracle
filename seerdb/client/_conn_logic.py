# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Non-I/O connection logic shared by the sync and async connections (#553).

`OracleConnect` (sync) and `AsyncOracleConnect` (async) duplicate a large body
of methods whose logic contains no ``await`` and touches no socket — pure state
manipulation and wire-bytes assembly. The README's design intent is that "the
duplication is just the I/O layer", so those methods belong in one place.

`_ConnectionLogic` is a mixin holding that shared logic; both concrete
connection classes inherit it, so a single definition serves both and the
sync/async parity holds by construction. The mixin never does I/O itself: it
only reads the attributes the concrete ``__init__`` sets and calls the
concrete I/O methods, both declared below for the type checker.

This first slice covers the end-to-end tracing attributes (MODULE / ACTION /
CLIENT_IDENTIFIER / CLIENT_INFO / DBOP, #183/#184); further slices move more of
the pure methods here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from seerdb.common.exceptions import NotSupportedError
from seerdb.common.tns import encode_end_to_end_piggyback
from seerdb.common.tns_consts import FIELD_VERSION_12_1


class _ConnectionLogic:
    """Shared non-I/O logic for `OracleConnect` / `AsyncOracleConnect` (#553)."""

    # --- Provided by the concrete connection's __init__ / I/O layer. Declared
    # here (no runtime assignment) so the type checker resolves the references
    # in the pure methods below; the concrete classes own the real values.
    field_version: int
    _e2e_values: dict
    _e2e_pending: dict

    if TYPE_CHECKING:

        def _next_seq(self) -> int: ...

    # --- End-to-end tracing attributes (#183/#184) -------------------------

    def _set_e2e(self, name: str, value) -> None:
        # Record a new end-to-end attribute value and mark it to flush before
        # the next execute (oracledb sends only what changed). The
        # SET_END_TO_END_ATTR piggyback (func 135) is a 12c+ message — a pre-12c
        # server closes the connection on it — so gate it (oracledb thin is
        # itself 12.1+ only). #183.
        if self.field_version < FIELD_VERSION_12_1:
            raise NotSupportedError(
                'end-to-end tracing attributes require an Oracle 12.1+ server'
            )
        self._e2e_values[name] = value
        self._e2e_pending[name] = value

    def _pending_e2e_with_module_action(self) -> dict:
        # The server rejects a module update that does not also carry action
        # (Oracle's SET_MODULE always sets both — a module-only piggyback is
        # ORA-03137). So when module flushes, send action too, at its current
        # value (None -> empty), matching oracledb. #184.
        Pending = dict(self._e2e_pending)
        if 'module' in Pending and 'action' not in Pending:
            Pending['action'] = self._e2e_values.get('action')
        return Pending

    def _flush_end_to_end_bytes(self) -> bytes:
        # Build the SET_END_TO_END_ATTR piggyback for the attributes changed
        # since the last flush, then clear the pending set. Empty when nothing
        # changed. Allocate the piggyback's seq here so it precedes the execute.
        if not self._e2e_pending:
            return b''
        Pending = self._pending_e2e_with_module_action()
        Seq = self._next_seq()
        Bytes = encode_end_to_end_piggyback(Seq, self.field_version, Pending)
        self._e2e_pending = {}
        return Bytes

    @property
    def module(self):
        """The session's MODULE for end-to-end tracing (V$SESSION.MODULE /
        SYS_CONTEXT('USERENV','MODULE')). Set it before running a statement;
        the change is sent with the next execute. oracledb-compatible (#183)."""
        return self._e2e_values.get('module')

    @module.setter
    def module(self, value) -> None:
        self._set_e2e('module', value)

    @property
    def action(self):
        """The session's ACTION for end-to-end tracing (#183)."""
        return self._e2e_values.get('action')

    @action.setter
    def action(self, value) -> None:
        self._set_e2e('action', value)

    @property
    def client_identifier(self):
        """The session's CLIENT_IDENTIFIER for end-to-end tracing (#183)."""
        return self._e2e_values.get('client_identifier')

    @client_identifier.setter
    def client_identifier(self, value) -> None:
        self._set_e2e('client_identifier', value)

    @property
    def clientinfo(self):
        """The session's CLIENT_INFO for end-to-end tracing
        (SYS_CONTEXT('USERENV','CLIENT_INFO')); oracledb-compatible (#184)."""
        return self._e2e_values.get('client_info')

    @clientinfo.setter
    def clientinfo(self, value) -> None:
        self._set_e2e('client_info', value)

    @property
    def dbop(self):
        """The session's database operation for monitoring (DBMS_SQL_MONITOR /
        SYS_CONTEXT('USERENV','DBOP')); oracledb-compatible (#184)."""
        return self._e2e_values.get('dbop')

    @dbop.setter
    def dbop(self, value) -> None:
        self._set_e2e('dbop', value)
