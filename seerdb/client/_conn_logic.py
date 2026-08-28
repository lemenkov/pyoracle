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

import struct
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
    TNS_DATA,
    TNS_SESSION_STATE_REQUEST_BEGIN,
    DictionaryType,
)

if TYPE_CHECKING:
    from seerdb.client.connection import Xid
    from seerdb.common.ano_session import AnoChannel


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
    _wallet_server_dn: str | None
    _large_packets: bool
    _ano: AnoChannel | None
    _call_timeout: int
    _cursor_cache: dict[tuple[str, bytes], int]
    _cursor_cache_max: int
    server_version: int

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

    # --- TLS wallet / ANO encryption helpers -------------------------------

    def _apply_wallet(
        self,
        WalletLocation: str | None,
        WalletPassword: str | None,
        ConfigDir: str | None,
        Dsn: str | None,
    ) -> None:
        # Resolve an Oracle wallet into connect parameters + a client SSLContext
        # (#127). Imported lazily so the `cryptography` dependency is only needed
        # when a wallet connection is actually requested.
        from seerdb.client import wallet as _wallet

        Location = WalletLocation or ConfigDir
        if not Location:
            raise _wallet.WalletError('wallet_location or config_dir is required')
        Wal = _wallet.open_wallet(Location, WalletPassword, Dsn)
        Info = Wal.connect
        if Info is not None:
            # A resolved DSN supplies host/port/service — but an explicitly
            # passed host/port/service still wins (left at the constructor
            # defaults means "take it from the wallet").
            if self.host == 'localhost':
                self.host = Info.host
            if self.port == 1521:
                self.port = Info.port
            if not self.service_name and Info.service_name:
                self.service_name = Info.service_name
            if not self.sid and Info.sid:
                self.sid = Info.sid
            if Info.dn_match and Info.server_dn:
                self._wallet_server_dn = Info.server_dn
        self.ssl = _wallet.build_client_context(Wal)

    def _check_server_dn(self, PeerCert: dict | None) -> None:
        # Oracle SSL_SERVER_DN_MATCH (#127): the server is authenticated by its
        # certificate subject DN, not its hostname. The chain was already
        # verified by the TLS stack against the wallet CA; here we assert the DN.
        if self._wallet_server_dn is None:
            return
        import ssl as _ssl

        from seerdb.client import wallet as _wallet

        if not _wallet.server_dn_matches(self._wallet_server_dn, PeerCert):
            raise _ssl.SSLError(
                f'server certificate DN does not match {self._wallet_server_dn!r}'
            )

    def _encode_ano_packet(self, Data: bytes) -> tuple[bytes, bytes | None]:
        # One encrypted TNS_DATA packet (#437): a plaintext chunk small enough
        # that, after the MAC + cipher padding + fold flag, the framed packet
        # still fits the SDU. Non-final packets carry data flags 0x0020.
        from seerdb.common.tns import _packet_header

        assert self._ano is not None  # only called while the ANO cipher is active
        MaxPlain = self.sdu - 64
        Chunk = Data[:MaxPlain]
        Rest = Data[MaxPlain:] or None
        Payload = self._ano.wrap(Chunk)
        DataFlag = 0x0000 if Rest is None else 0x0020
        Header = _packet_header(len(Payload) + 10, TNS_DATA, self._large_packets)
        return (Header + struct.pack('>H', DataFlag) + Payload, Rest)

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

    # --- Statement cache / call-timeout / cancel ---------------------------

    @property
    def stmtcachesize(self) -> int:
        """Number of server-side cursors kept in the statement cache (PEP 249
        extension / oracledb-compatible). Setting it smaller evicts the oldest
        entries immediately; 0 disables caching."""
        return self._cursor_cache_max

    @stmtcachesize.setter
    def stmtcachesize(self, value: int) -> None:
        self._cursor_cache_max = max(0, int(value))
        while len(self._cursor_cache) > self._cursor_cache_max:
            Oldest = next(iter(self._cursor_cache))
            self._cursor_cache.pop(Oldest, None)

    @property
    def call_timeout(self) -> int:
        """Per-call timeout in milliseconds (0 = none). A call that runs longer
        is interrupted with an in-band break and raises a timeout error
        (#123/#144, oracledb-compatible)."""
        return self._call_timeout

    @call_timeout.setter
    def call_timeout(self, value: int) -> None:
        self._call_timeout = max(0, int(value or 0))

    def cancel(self) -> None:
        """Interrupt the call currently executing on this connection (#123/#144).

        Sends a break (an out-of-band urgent byte when the server advertised
        attention support, otherwise an in-band INTERRUPT marker); the thread
        blocked in the call drains the server's interrupt response and raises
        ORA-01013. Safe to call from another thread (e.g. a timer/signal)."""
        self._send_break()

    @property
    def version(self) -> str | None:
        """Server version as a dotted release string (e.g. '11.2.0.2.0'), or
        None before authentication. Decoded from the packed AUTH_VERSION_NO the
        server returns at logon; oracledb-compatible."""
        # Lazy import: _format_version lives in connection.py, which imports
        # this mixin — a module-level import would be circular.
        from seerdb.client.connection import _format_version

        return _format_version(self.server_version)

    def xid(self, format_id: int, global_transaction_id, branch_qualifier) -> Xid:
        """Build a global transaction id (Xid) for the TPC methods."""
        from seerdb.client.connection import Xid

        return Xid(format_id, global_transaction_id, branch_qualifier)

    def subscribe(self, *args: object, **kwargs: object) -> None:
        """Register a Continuous Query Notification subscription — not supported
        (#129). Accepts any arguments for API compatibility and raises
        NotSupportedError; see ``_reject_cqn``."""
        from seerdb.client.connection import _reject_cqn

        _reject_cqn()

    def unsubscribe(self, *args: object, **kwargs: object) -> None:
        """Remove a CQN subscription — not supported (#129); the counterpart to
        ``subscribe``, raising NotSupportedError for the same reason."""
        from seerdb.client.connection import _reject_cqn

        _reject_cqn()

    def _rows(self, result: object) -> list:
        # The row block of an execute() result (execute is typed `object`); [] if
        # the result carries no rows.
        return (
            result[4]
            if isinstance(result, tuple) and len(result) > 4 and result[4]
            else []
        )

    def msgproperties(
        self,
        payload=None,
        correlation=None,
        delay=0,
        expiration=-1,
        priority=0,
        exceptionq=None,
        recipients=None,
    ):
        """Build a MessageProperties for enqueue."""
        from seerdb.client.aq import MessageProperties

        return MessageProperties(
            payload=payload,
            correlation=correlation,
            delay=delay,
            expiration=expiration,
            priority=priority,
            exceptionq=exceptionq,
            recipients=recipients,
        )

    def _raise_lobops_error(self, Packet: bytes) -> None:
        # Decode the OER trailing a content-free LOBOPS response and raise on a
        # real ORA error. decode_lobops_oer skips the RPA's binary locator and
        # matches the OER regardless of call status (which is 5, not 1,
        # immediately after a PL/SQL execute — the case that desynced the temp
        # LOB write following a temp-LOB-bind exec).
        from seerdb.common.exceptions import from_ora_code
        from seerdb.common.tns import decode_lobops_oer

        (ErrCode, Message) = decode_lobops_oer(Packet, self.field_version)
        if ErrCode and ErrCode not in (0, 1403):
            raise from_ora_code(ErrCode)(Message or f'ORA-{ErrCode:05d}', code=ErrCode)
