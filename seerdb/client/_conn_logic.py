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

from seerdb.client.dialect import Dialect, Fv2Dialect, O8iDialect
from seerdb.common.end_user_sec import EndUserSecurityContext
from seerdb.common.exceptions import NotSupportedError, ProgrammingError
from seerdb.common.tns import (
    CCAP_FEATURE_BACKPORT2,
    CCAP_FEATURE_BACKPORT2_END_USER_SEC,
    CCAP_TTC4,
    CCAP_TTC4_EXPLICIT_BOUNDARY,
    RCAP_TTC,
    RCAP_TTC_SESSION_STATE_OPS,
    encode_close_cursors_piggyback,
    encode_end_to_end_piggyback,
    encode_end_user_sec_piggyback,
    encode_session_state_piggyback,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_10_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_23_1,
    TNS_SESSION_STATE_REQUEST_BEGIN,
    DictionaryType,
)


class _ConnectionLogic:
    """Shared non-I/O logic for `OracleConnect` / `AsyncOracleConnect` (#553)."""

    # --- Provided by the concrete connection's __init__ / I/O layer. Declared
    # here (no runtime assignment) so the type checker resolves the references
    # in the pure methods below; the concrete classes own the real values.
    field_version: int
    ssl: object
    host: str
    port: int
    sid: str
    service_name: str
    user: str
    proxy_user: str | None
    password: str
    cclass: str | None
    purity: int
    socket_options: object
    conn_state: int
    timeout: int
    autocommit: bool
    fetch: int
    role: int
    charset: str
    prelim: int
    app_name: str
    sdu: int
    _e2e_values: dict
    _e2e_pending: dict
    _cursors_to_close: list[int]
    _server_compile_caps: bytes
    _server_runtime_caps: bytes
    _end_user_sec_context: bytes | None
    _session_state_desired: int
    _in_request: bool
    _supports_eor: bool
    _timed_out: bool
    _dialect: Dialect | None

    if TYPE_CHECKING:

        def _next_seq(self) -> int: ...

        def _send_break(self) -> None: ...

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

    # --- Session-state piggybacks (#191/#460/#464) -------------------------
    # Each rides in front of the next call; its seq is allocated here so it
    # precedes the call's. All are pure builders — the concrete class does the
    # actual send.

    def _flush_cursor_closes_bytes(self) -> bytes:
        # Build an OCCA (close-cursors) piggyback for the server cursors queued
        # for close (#191), then clear the queue. Empty when nothing is queued.
        if not self._cursors_to_close:
            return b''
        Seq = self._next_seq()
        Data = encode_close_cursors_piggyback(
            Seq, self.field_version, self._cursors_to_close
        )
        self._cursors_to_close = []
        return Data

    def _supports_end_user_sec(self) -> bool:
        # The server advertises end-user security context via a compile-cap bit
        # (#460).
        Caps = self._server_compile_caps
        return len(Caps) > CCAP_FEATURE_BACKPORT2 and bool(
            Caps[CCAP_FEATURE_BACKPORT2] & CCAP_FEATURE_BACKPORT2_END_USER_SEC
        )

    def _flush_end_user_sec_bytes(self) -> bytes:
        # func-205 piggyback re-sent in front of every call while a context is
        # set (#460). Empty when none is set.
        if self._end_user_sec_context is None:
            return b''
        Seq = self._next_seq()
        return encode_end_user_sec_piggyback(
            Seq, self.field_version, self._end_user_sec_context
        )

    def set_end_user_security_context(self, context: EndUserSecurityContext) -> None:
        """Attach an end-user security context to the connection (#460).

        Once set, the context is sent (as a func-205 piggyback) in front of every
        subsequent database operation until :meth:`clear_end_user_security_context`
        is called. Build ``context`` with
        :func:`seerdb.create_end_user_security_context`.

        The reference thin client restricts this feature to TLS (tcps)
        transports and to servers that advertise it (Oracle 26ai and later), and
        seerdb mirrors both guards.
        """
        if not isinstance(context, EndUserSecurityContext):
            raise TypeError('expecting an EndUserSecurityContext instance')
        if not self.ssl:
            raise ProgrammingError(
                'end_user_security_context requires use of the tcps protocol'
            )
        if not self._supports_end_user_sec():
            raise NotSupportedError(
                'the database does not support end-user security context '
                '(requires Oracle 26ai or later)'
            )
        self._end_user_sec_context = context.oson_bytes

    def clear_end_user_security_context(self) -> None:
        """Clear any end-user security context previously set on the connection
        (#460), reverting to operations without an attached context."""
        self._end_user_sec_context = None

    def _supports_request_boundaries(self) -> bool:
        # Explicit request boundaries need a compile-cap bit AND a runtime-cap
        # bit (#464).
        Cc = self._server_compile_caps
        Rc = self._server_runtime_caps
        return (
            len(Cc) > CCAP_TTC4
            and bool(Cc[CCAP_TTC4] & CCAP_TTC4_EXPLICIT_BOUNDARY)
            and len(Rc) > RCAP_TTC
            and bool(Rc[RCAP_TTC] & RCAP_TTC_SESSION_STATE_OPS)
        )

    def _flush_session_state_bytes(self) -> bytes:
        # One-shot request-boundary piggyback (#464). Empty when nothing armed.
        if self._session_state_desired == 0:
            return b''
        Seq = self._next_seq()
        Data = encode_session_state_piggyback(
            Seq, self.field_version, self._session_state_desired
        )
        self._session_state_desired = 0
        return Data

    def _begin_request(self) -> None:
        # Arm a REQUEST_BEGIN marker for a pooled logical request (#464).
        if self._supports_request_boundaries():
            self._session_state_desired = TNS_SESSION_STATE_REQUEST_BEGIN
            self._in_request = True

    # --- Request-dictionary builder ----------------------------------------

    def _make_dict(self, Type: DictionaryType, **extra) -> dict:
        d = {
            'env': {
                'host': self.host,
                'port': self.port,
                'user': self.user,
                'proxy_user': self.proxy_user,
                'cclass': self.cclass,
                'purity': self.purity,
                'password': self.password,
                'sid': self.sid,
                'service_name': self.service_name,
                'ssl': self.ssl,
                'socket_options': self.socket_options,
                'conn_state': self.conn_state,
                'timeout': self.timeout,
                'autocommit': self.autocommit,
                'fetch': self.fetch,
                'role': self.role,
                'charset': self.charset,
                'prelim': self.prelim,
                'app_name': self.app_name,
            },
            'sdu': self.sdu,
            'type': Type,
            'req': self.charset,
            'seq': self._next_seq(),
            'field_version': self.field_version,
            'supports_eor': self._supports_eor,
        }
        d.update(extra)
        return d

    # --- Capability / dialect / misc pure helpers --------------------------

    def _nego_cache_key(self) -> tuple[str, int, str]:
        # Identify the connection target for the negotiation cache (#438).
        return (self.host, self.port, self.service_name or self.sid or '')

    def _select_dialect(self, is_8i: bool = False) -> None:
        # Pick the wire dialect once the negotiated version is final — the single
        # discriminator the rest of the driver reads (#369). 8i and 9i both
        # advertise fv2, so the 8i banner (passed in) is what tells them apart;
        # modern (10g->23ai) keeps _dialect None and takes the TTI_ALL8 path.
        if is_8i:
            self._dialect = O8iDialect(self._next_seq)
        elif self.field_version < FIELD_VERSION_10_2:
            self._dialect = Fv2Dialect()
        else:
            self._dialect = None

    def _fv2_raise_for_error(self, Packet: bytes) -> None:
        # Thin delegate to the shared colorless helper — still used by the inline
        # 8i methods until they migrate to a dialect (#369).
        from seerdb.client.dialect import fv2_raise_for_error

        fv2_raise_for_error(Packet)

    def _check_sessionless_support(self) -> None:
        if self.field_version < FIELD_VERSION_23_1:
            raise NotSupportedError(
                'sessionless transactions require an Oracle 23ai+ server'
            )

    def _pipeline_wire_eligible(self, pipeline) -> bool:
        # The single-round-trip wire path (#158) needs end-of-response framing
        # (23ai) and covers only the exec-family ops, whose token framing is
        # verified against a capture. A pipeline with a commit / callproc /
        # callfunc op runs serially instead (correct results, no optimisation).
        from seerdb.client.pipeline import PipelineOpType as T

        WireOps = (T.EXECUTE, T.EXECUTE_MANY, T.FETCH_ONE, T.FETCH_MANY, T.FETCH_ALL)
        if not self._supports_eor or not pipeline.operations:
            return False
        return all(Op.op_type in WireOps for Op in pipeline.operations)

    def _on_call_timeout(self) -> None:
        # call_timeout timer callback: flag the timeout and break the call.
        self._timed_out = True
        self._send_break()
