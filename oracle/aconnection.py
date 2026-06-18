# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Async-native counterpart to `oracle.connection.OracleConnect`.

Shares the pure protocol code in `oracle.tns` (encode_packet,
assemble_packet, decode_packet, the encoders/decoders for every
TTI token) — those are byte-in / decoded-out and don't care which
transport drives them. The duplication here is just the I/O layer
and the connection-level state machine: TCP/TLS via
`asyncio.open_connection`, and `async def` versions of `send`,
`recv`, `handle_login`, `execute`, `fetch_more`.

Why not a thin sync wrapper around this async code: see the
discussion in the README on architecture choices. Calling
`asyncio.run()` from a sync API explodes inside any context that
already has a running event loop (web frameworks, Jupyter), and
the `nest_asyncio` workarounds are fragile. Two native paths are
cleaner.
"""

import asyncio
import logging
import socket
import struct

from oracle.crypto import validate
from oracle.exceptions import InterfaceError, OperationalError
from oracle.tns import assemble_packet
from oracle.tns import decode_packet
from oracle.tns import decode_token_pro
from oracle.tns import decode_token_rpa
from oracle.tns import encode_dictionary
from oracle.tns import encode_packet
from oracle.tns import exec_oac_signature
from oracle.tns import set_decode_dml_rowcounts, set_decode_return_binds
from oracle.tns import (CCAP_FIELD_VERSION, FIELD_VERSION_10_2,
                        FIELD_VERSION_12_1,
                        encode_fast_auth, find_fast_auth_rpa)
from oracle.tns import (encode_o7_open, encode_o7_parse, encode_o7_describe,
                        encode_o7_exec, encode_o7_close, encode_o7_block,
                        encode_tokens_rxd, decode_fv2_describe,
                        decode_fv2_exec_response, decode_fv2_dml_response,
                        decode_fv2_oer_error, decode_fv2_block_out,
                        encode_o7_lob_getlen,
                        encode_o7_lob_read, decode_fv2_lob_getlen,
                        decode_fv2_lob_chunks, encode_o7_bfile_open,
                        encode_o7_bfile_close, decode_fv2_opened_locator)
from oracle.connection import _format_version, _MAX_REDIRECTS
from oracle.tns_consts import (
    CONN_STATE_AUTHENTICATED, CONN_STATE_AUTH_NEGOTIATE,
    CONN_STATE_CONNECTED, CONN_STATE_DISCONNECTED,
    DictionaryType, FIELD_VERSION_23_1, FIELD_VERSION_23_4, TNS_ACCEPT,
    TNS_CONNECT, TNS_DATA, TNS_MARKER, TNS_REDIRECT, TNS_REFUSE, TNS_RESEND,
    TTI_DTY, TTI_OER, TTI_PRO, TTI_RPA, TTI_SESS, TTI_WRN,
)


logger = logging.getLogger(__name__)


class AsyncOracleConnect:
    """Async equivalent of `OracleConnect`. Same constructor surface so
    pool / cursor / app code can swap one for the other given an
    appropriate sync vs async caller."""

    def __init__(self, host: str = "localhost", port: int = 1521,
                 user: str = "", password: str = "", sid: str = "",
                 service_name: str = "", ssl: object = None,
                 socket_options: object = None, timeout: int = 15000,
                 autocommit: bool = True, fetch: int = 15, role: int = 0,
                 prelim: int = 0, sdu: int = 8192, charset: str = "utf-8",
                 app_name: str = "pyoracle",
                 field_version: int = FIELD_VERSION_23_4):
        self.host = host
        self.port = port
        # Proxy auth (#126): split proxy_user[schema] (see OracleConnect).
        from oracle.connection import _split_proxy_user
        (self.user, self.proxy_user) = _split_proxy_user(user)
        self.password = password
        self.sid = sid
        self.service_name = service_name
        self.ssl = ssl
        self.socket_options = socket_options
        self.conn_state = CONN_STATE_DISCONNECTED
        self.timeout = timeout
        self.autocommit = autocommit
        self.fetch = fetch
        self.role = role
        self.sdu = sdu
        self.charset = charset
        self.prelim = prelim
        self.app_name = app_name

        # asyncio StreamReader / StreamWriter pair, set by `connect()`.
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.seq = 1
        # Break/reset state, mirrors OracleConnect (#45): bytes held past a
        # marker for the next recv(), and a latch so we answer a server break
        # with exactly one reset then drain the rest silently (2:1 ratio).
        self._pending = b""
        self._in_break = False
        # Query cancellation / call_timeout (#123), mirrors OracleConnect.
        self._break_in_progress = False
        self._call_timeout = 0
        self._timed_out = False
        self.conn_key = None
        self.server_version = 0
        self.session_id = None
        # Negotiated TTC field version; see OracleConnect for the full note.
        self.field_version = field_version
        self.cursors: dict[int, int] = {}
        # Cursor cache — same shape as the sync `OracleConnect`. DML only.
        # Keyed on (SQL, bind OAC signature); see OracleConnect for why the
        # bind signature has to be part of the key.
        self._cursor_cache: dict[tuple[str, bytes], int] = {}
        self._cursor_cache_max = 32
        # Ordered attribute layout per SQL object type (#115), keyed by
        # (owner, type_name); see OracleConnect._object_type_layout.
        self._object_type_cache: dict[tuple[str, str], list] = {}

    @property
    def stmtcachesize(self) -> int:
        """Number of server-side cursors kept in the statement cache. See
        `OracleConnect.stmtcachesize`."""
        return self._cursor_cache_max

    @stmtcachesize.setter
    def stmtcachesize(self, value: int) -> None:
        self._cursor_cache_max = max(0, int(value))
        while len(self._cursor_cache) > self._cursor_cache_max:
            Oldest = next(iter(self._cursor_cache))
            self._cursor_cache.pop(Oldest, None)

    @property
    def version(self) -> str | None:
        """Server version as a dotted release string. See
        `OracleConnect.version`."""
        return _format_version(self.server_version)

    # ----- bookkeeping shared with the sync class -----
    # These are copy-pasted from connection.py rather than imported via a
    # mixin because the sync class also has them and any future divergence
    # (timeouts, async-only fields) should stay local to each side.

    def _next_seq(self) -> int:
        from oracle.tns_consts import MAX_SEQ_NUM
        seq = self.seq
        self.seq = self.seq % MAX_SEQ_NUM + 1
        return seq

    def _make_dict(self, Type: DictionaryType, **extra) -> dict:
        # Same shape as `OracleConnect._make_dict`. Kept verbatim so the
        # pure encoders in `oracle.tns` work unchanged across both APIs.
        d = {
            'env': {
                'host': self.host,
                'port': self.port,
                'user': self.user,
                'proxy_user': self.proxy_user,
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
        }
        d.update(extra)
        return d

    # ----- I/O primitives -----

    async def _open_transport(self) -> None:
        # Open the TCP (optionally TLS) socket to the current host/port and send
        # the initial CONNECT. Shared by connect() and the TNS_REDIRECT handler.
        SslArg = self._ssl_kwarg()
        # Force IPv4 to match the sync path. asyncio.open_connection
        # otherwise defers to getaddrinfo's default ordering, which
        # often hands back ::1 first; some Oracle listener configs
        # only bind IPv4 and silently drop IPv6 connects.
        Loop = asyncio.get_running_loop()
        Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        Sock.setblocking(False)
        await Loop.sock_connect(Sock, (self.host, self.port))
        self._reader, self._writer = await asyncio.open_connection(
            sock=Sock,
            ssl=SslArg,
            server_hostname=self.host if SslArg else None,
        )
        Data = encode_dictionary(self._make_dict(DictionaryType.login))
        await self.send(TNS_CONNECT, Data)

    async def connect(self) -> bool:
        """Open the TCP (optionally TLS) connection and run the
        TNS / TTC / O5LOGON handshake."""
        self._redirects = 0
        await self._open_transport()
        await self.handle_login()
        return True

    def _ssl_kwarg(self):
        """Resolve `self.ssl` into something `asyncio.open_connection`
        accepts (None / True / SSLContext)."""
        if not self.ssl:
            return None
        import ssl as _ssl
        if isinstance(self.ssl, _ssl.SSLContext):
            return self.ssl
        if isinstance(self.ssl, dict):
            Opts = dict(self.ssl)
            Opts.pop("server_hostname", None)  # not for asyncio kwarg
            Ctx = _ssl.create_default_context(cafile=Opts.pop("ca_certs", None))
            Ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
            if "check_hostname" in Opts:
                Ctx.check_hostname = bool(Opts.pop("check_hostname"))
            if "verify_mode" in Opts:
                Ctx.verify_mode = Opts.pop("verify_mode")
            CertFile = Opts.pop("certfile", None)
            KeyFile = Opts.pop("keyfile", None)
            if CertFile:
                Ctx.load_cert_chain(CertFile, KeyFile)
            if Opts:
                raise ValueError(f"unknown ssl options: {sorted(Opts)}")
            return Ctx
        return True

    async def send(self, Type: int, Data: bytes | None) -> None:
        """Iterative split-and-send; mirrors `OracleConnect.send`."""
        while Data is not None:
            (Packet, Rest) = encode_packet(Type, Data, self.sdu)
            self._writer.write(Packet)
            Data = Rest
        await self._writer.drain()
        logger.debug("Send OK (async)")

    async def recv(self, Acc: bytes, Data: bytes) -> tuple[int, bytes] | bool:
        """Same packet-reassembly state machine as `OracleConnect.recv`,
        but awaiting the StreamReader instead of `sock.recv`. Seeds from and
        preserves into self._pending so a coalesced break|reset|error is not
        dropped (#45)."""
        Acc = self._pending + Acc
        self._pending = b""
        while True:
            while len(Acc) >= 8:
                (Flag, Type, Body, Rest) = assemble_packet(Acc, self.sdu)
                if Flag is True and Type == TNS_MARKER:
                    self._pending = Rest
                    return (TNS_MARKER, b"")
                if Flag is True and Rest == b"":
                    return (Type, Data + Body)
                if Flag is True and Rest != b"":
                    Acc = Rest
                    Data = Data + Body
                    continue
                if Body is not None:
                    Acc = Rest or b""
                    Data = Data + Body
                    continue
                break
            try:
                if self.timeout:
                    NetworkData = await asyncio.wait_for(
                        self._reader.read(self.sdu), self.timeout / 1000)
                else:
                    NetworkData = await self._reader.read(self.sdu)
            except asyncio.IncompleteReadError:
                return False
            except (asyncio.TimeoutError, TimeoutError) as exc:
                from oracle.exceptions import OperationalError
                raise OperationalError(
                    f"network read timed out after {self.timeout} ms "
                    f"(connection timeout)") from exc
            if not NetworkData:
                return False
            Acc = Acc + NetworkData

    async def _next_data_packet(self, Acc: bytes = b"", Data: bytes = b"") \
            -> tuple[int, bytes] | bool:
        """Async port of `OracleConnect._next_data_packet` (#45): receive the
        next DATA packet, answering a server break with a single reset and
        draining the rest (the server's terminal reset) silently."""
        while True:
            Received = await self.recv(Acc, Data)
            if Received is False:
                return False
            (Type, Packet) = Received
            if Type != TNS_MARKER:
                self._in_break = False
                return (Type, Packet)
            if not self._in_break:
                await self.send(TNS_MARKER, b"\x01\x00\x02")
                self._in_break = True

    # ----- login state machine -----

    async def handle_login(self) -> int | None:
        """Async port of `OracleConnect.handle_login`."""
        while True:
            Received = await self.recv(b"", b"")
            if Received is False:
                logger.debug("handle_login (async): peer closed")
                return 1
            (Type, Packet) = Received
            if Type != TNS_MARKER:
                self._in_break = False
            match Type:
                case t if t == TNS_ACCEPT:
                    (Ver, Opts, Sdu) = struct.unpack(">hhh", Packet[:6])
                    self.sdu = Sdu
                    self.conn_state = CONN_STATE_CONNECTED
                    Data = encode_dictionary(self._make_dict(DictionaryType.pro))
                    await self.send(TNS_DATA, Data)
                    continue
                case t if t == TNS_DATA:
                    match Packet[0]:
                        case p if p == TTI_PRO:
                            self._negotiate_capabilities(Packet)
                            if self.field_version > FIELD_VERSION_23_1:
                                # 23ai (#89): fv >= 18 needs the fast-auth bundle
                                # (the legacy OSESSKEY is rejected). See the sync
                                # OracleConnect._fast_auth_login.
                                return await self._fast_auth_login()
                            Data = encode_dictionary(self._make_dict(DictionaryType.dty))
                            await self.send(TNS_DATA, Data)
                        case p if p == TTI_DTY:
                            if self.field_version < FIELD_VERSION_10_2:
                                # Pre-10g (9i): O3LOGON thin auth (#90). Async
                                # port of OracleConnect's branch.
                                from oracle.tns import encode_o3logon_phase1
                                self._o3_phase = 1
                                await self.send(TNS_DATA, encode_o3logon_phase1(
                                    self._next_seq(), self.user.encode('utf-8')))
                            else:
                                Data = encode_dictionary(self._make_dict(DictionaryType.sess))
                                await self.send(TNS_DATA, Data)
                        case p if p == TTI_RPA:
                            if getattr(self, "_o3_phase", 0) == 1:
                                await self._send_o3logon_phase2(Packet)
                                continue
                            return await self._handle_rpa(Packet[1:])
                        case p if p == TTI_WRN:
                            logger.debug("handle_login: recv WRN %s", Packet[1:])
                        case p if p == TTI_OER:
                            from oracle.tns import decode_packet, decode_ub4
                            from oracle.exceptions import (DatabaseError,
                                                           from_ora_code)
                            if getattr(self, "_o3_phase", 0) == 2:
                                # 9i's OER is the short pre-10g form: skip
                                # call_status, seq, rowcount, then the ORA code.
                                Rest = Packet[1:]
                                for _ in range(3):
                                    (_, Rest) = decode_ub4(Rest)
                                (ErrCode, _) = decode_ub4(Rest)
                                Message = None
                            else:
                                Result = decode_packet(Packet, (None, None, []),
                                                       self.field_version)
                                ErrCode = Result[1]
                                Message = Result[5] if len(Result) > 5 else None
                            if ErrCode and ErrCode not in (0, 1403):
                                raise from_ora_code(ErrCode)(
                                    Message or f"ORA-{ErrCode:05d}", code=ErrCode)
                            if getattr(self, "_o3_phase", 0) == 2:
                                self.conn_state = CONN_STATE_AUTHENTICATED
                                return 0
                            raise DatabaseError("authentication failed")
                        case _:
                            logger.debug("handle_login: unknown token %s",
                                         Packet[0])
                    continue
                case t if t == TNS_MARKER:
                    # Single reset per break episode, then drain (#45).
                    if not self._in_break:
                        await self.send(TNS_MARKER, b"\x01\x00\x02")
                        self._in_break = True
                    continue
                case t if t == TNS_REDIRECT:
                    from oracle.tns import parse_redirect_address
                    (NewHost, NewPort) = parse_redirect_address(Packet)
                    if NewHost is None:
                        return 1
                    self._redirects = getattr(self, "_redirects", 0) + 1
                    if self._redirects > _MAX_REDIRECTS:
                        from oracle.exceptions import OperationalError
                        raise OperationalError(
                            f"too many TNS redirects (> {_MAX_REDIRECTS})")
                    self.host, self.port = NewHost, NewPort
                    await self.disconnect()
                    await self._open_transport()
                    continue
                case t if t == TNS_REFUSE:
                    await self.disconnect()
                    return 1
                case t if t == TNS_RESEND:
                    self.conn_state = CONN_STATE_AUTH_NEGOTIATE
                    Data = encode_dictionary(self._make_dict(DictionaryType.login))
                    await self.send(TNS_CONNECT, Data)
                    continue
                case _:
                    logger.debug("handle_login (async): unexpected %s", Type)
                    return 1

    async def _fast_auth_login(self) -> int | None:
        # Async port of OracleConnect._fast_auth_login (23ai fast-auth, #89):
        # send PRO + DTY + OSESSKEY bundled in one FAST_AUTH packet, then hand the
        # auth-challenge RPA out of the bundled reply to the phase-two path.
        Pro = encode_dictionary(self._make_dict(DictionaryType.pro))
        Dty = encode_dictionary(self._make_dict(DictionaryType.dty))
        Sess = encode_dictionary(self._make_dict(DictionaryType.sess))
        await self.send(TNS_DATA, encode_fast_auth(Pro, Dty, Sess))
        Received = await self._next_data_packet()
        if Received is False:
            logger.debug("fast_auth (async): connection closed by peer")
            return 1
        (Type, Packet) = Received
        Off = find_fast_auth_rpa(Packet) if Type == TNS_DATA else -1
        if Off < 0:
            from oracle.exceptions import OperationalError
            logger.error("fast_auth (async): no auth challenge in bundled reply")
            raise OperationalError("fast-auth handshake failed")
        return await self._handle_rpa(Packet[Off + 1:])

    def _negotiate_capabilities(self, Packet: bytes) -> None:
        # Parse the server's PRO response and lower the field version to the
        # server's if older — min(client, server). See OracleConnect for the
        # full rationale. Best-effort: keep the default on any parse error.
        try:
            Pro = decode_token_pro(Packet)
            Caps = Pro['compile_caps']
            if len(Caps) > CCAP_FIELD_VERSION:
                self.field_version = min(self.field_version, Caps[CCAP_FIELD_VERSION])
            logger.debug("handle_login: PRO server_version=%s banner=%r "
                         "field_version=%s", Pro['server_version'],
                         Pro['banner'], self.field_version)
        except Exception:
            logger.debug("handle_login: could not parse PRO caps", exc_info=True)

    async def _handle_rpa(self, Data: bytes) -> int | None:
        from oracle.tns_consts import TTI_AUTH
        Result = decode_token_rpa(Data, None)
        if Result[0] == TTI_SESS:
            # First RPA: auth challenge from the server.
            (_, SessKey, Salt, DerivedSalt) = Result
            self.conn_state = CONN_STATE_AUTH_NEGOTIATE
            Auth = {
                'sess': bytes.fromhex(SessKey.decode('utf-8')) if SessKey else None,
                'salt': bytes.fromhex(Salt.decode('utf-8')) if Salt else None,
                'derived_salt': bytes.fromhex(DerivedSalt.decode('utf-8')) if DerivedSalt else None,
            }
            (Data2, ConnKey) = encode_dictionary(
                self._make_dict(DictionaryType.auth, auth=Auth))
            self.conn_key = ConnKey
            await self.send(TNS_DATA, Data2)
            # Server's second RPA carries the auth result — re-enter the
            # login loop so it gets routed through the right state.
            return await self.handle_login()
        elif Result[0] == TTI_AUTH:
            # Second RPA: auth result.
            (_, Resp, Ver, SessId) = Result
            if validate(bytes.fromhex(Resp.decode('utf-8')), self.conn_key):
                self.server_version = Ver
                self.session_id = SessId
                self.conn_state = CONN_STATE_AUTHENTICATED
                return 0
            await self.disconnect()
            return 1
        return 1

    # ----- response handling -----

    async def _handle_response(self, Acc: tuple | None = None) -> object:
        if Acc is None:
            Acc = (None, None, [])
        Received = await self._next_data_packet(b"", b"")
        if Received is False:
            raise InterfaceError("connection closed while awaiting response")
        (Type, Packet) = Received
        if Type == TNS_DATA:
            return decode_packet(Packet, Acc, self.field_version)
        raise Exception("Unexpected response type", Type)

    # ----- execute / fetch (kept minimal for the first cut) -----

    async def execute(self, Query: str, Bind: list | None = None,
                      Def: list | None = None, Batch: list | None = None,
                      BatchErrors: bool = False,
                      ArrayDmlRowCounts: bool = False, ReturnBinds=None) -> object:
        """Same shape as `OracleConnect.execute` but async.

        Cursor caching for DML works the same way as in the sync path —
        the cache is on `self`, keyed by SQL text."""
        if Bind is None:
            Bind = []
        if Def is None:
            Def = []
        if Batch is None:
            Batch = []
        Head = Query.strip().upper()
        # Oracle 9i (field version < 10g) speaks the old TTI_ALL7 query dialect
        # (#97, PROTOCOL.md §19); route SELECTs through the fv2 path.
        if self.field_version < FIELD_VERSION_10_2:
            if Head.startswith('SELECT'):
                return await self._drain_cursor(
                    await self._execute_fv2(Query, Bind))
            # Anonymous PL/SQL block over the fv2 block path (#102, IN binds).
            if Head.startswith('BEGIN') or Head.startswith('DECLARE'):
                return await self._execute_fv2_block(Query, Bind)
            return await self._execute_fv2_dml(Query, Bind)
        if Head.startswith('SELECT'):
            Type = 'select'
        elif Head.startswith('BEGIN') or Head.startswith('DECLARE'):
            # Anonymous PL/SQL block: dedicated 'block' exec option set, not the
            # DML 'change' path (else ORA-00600 [12259]). Mirrors the sync path.
            Type = 'block'
        else:
            Type = 'change'
        CachedCursor = 0
        CacheKey = None
        # The cursor cache reuses a parsed handle and skips re-sending the
        # SQL/OAC — an 11g optimization that doesn't translate to 12c+, where a
        # cached re-execute fails (ORA-01009 / ORA-03115) because the server
        # expects the binds/OAC declared every execute. Disable on 12c+ (mirrors
        # the sync OracleConnect.execute guard).
        if Type == 'change' and not Def \
                and self.field_version < FIELD_VERSION_12_1:
            CacheKey = (Query, exec_oac_signature(Bind, Batch))
            CachedCursor = self._cursor_cache.get(CacheKey, 0)
        SendQuery = "" if CachedCursor else Query
        QueryDict = {
            'type': Type,
            'auto': 1 if self.autocommit else 0,
            'fetch': self.fetch,
            'server_version': self.server_version,
            'cursor': CachedCursor,
            'query': SendQuery,
            'bind': Bind,
            'batch': Batch,
            'def': Def,
            'batcherrors': BatchErrors,
            'arraydmlrowcounts': ArrayDmlRowCounts,
            'return_binds': ReturnBinds or None,
        }
        Data = encode_dictionary(self._make_dict(DictionaryType.exec, query=QueryDict))
        await self.send(TNS_DATA, Data)
        # Arm row-count extraction for this response only (#18).
        set_decode_dml_rowcounts(ArrayDmlRowCounts)
        # Arm RETURNING out-bind decoding for this response only (#120).
        set_decode_return_binds(ReturnBinds)
        # call_timeout (#123): schedule a break if the call runs too long; the
        # read coroutine then receives the server's interrupt (ORA-01013), which
        # we remap to a call-timeout error.
        Timer = None
        if self._call_timeout:
            self._timed_out = False
            Timer = asyncio.get_running_loop().call_later(
                self._call_timeout / 1000.0, self._on_call_timeout)
        try:
            # Seed the decoder with the binds so the IOV decoder can tell a
            # REF CURSOR OUT bind from a scalar one.
            Result = await self._handle_response((None, None, [], Bind))
        except Exception as exc:
            if CachedCursor:
                self._cursor_cache.pop(CacheKey, None)
            if self._timed_out:
                raise OperationalError(
                    f"call timeout of {self._call_timeout} ms exceeded "
                    f"(ORA-03136)") from exc
            raise
        finally:
            if Timer is not None:
                Timer.cancel()
            self._break_in_progress = False
            self._timed_out = False
        if (CacheKey is not None and Type == 'change' and not Def
                and isinstance(Result, tuple) and len(Result) >= 3
                and isinstance(Result[2], int) and Result[2] > 0
                and Result[1] in (0, 1403)):
            # Gate the write on CacheKey too so 12c+ (cache disabled) never
            # parks a stray {None: cursor_id} entry (#80); mirrors the sync fix.
            CursorId = Result[2]
            self._cursor_cache.pop(CacheKey, None)
            self._cursor_cache[CacheKey] = CursorId
            while len(self._cursor_cache) > self._cursor_cache_max:
                Oldest = next(iter(self._cursor_cache))
                self._cursor_cache.pop(Oldest, None)
        return await self._drain_cursor(Result)

    async def _send_o3logon_phase2(self, Packet: bytes) -> None:
        # Async port of OracleConnect._send_o3logon_phase2 (#90): decrypt the
        # session key from the TTI_3LOGA RPA with the account DES verifier,
        # DES-encrypt the zero-padded password, send TTI_3LOGON.
        from binascii import hexlify, unhexlify
        from oracle.crypto import o3logon, des_verifier
        from oracle.tns import encode_o3logon_phase2
        Length = Packet[2]
        SessKey = unhexlify(Packet[3:3 + Length])
        UserB = self.user.encode('utf-8')
        PassB = self.password.encode('utf-8')
        Verifier = des_verifier(UserB, PassB)
        (AuthPass, _, _) = o3logon(SessKey, Verifier, PassB)
        PadCount = (8 - len(PassB) % 8) % 8
        PwdField = (hexlify(AuthPass).decode('ascii').upper()
                    + str(PadCount)).encode('ascii')
        self._o3_phase = 2
        await self.send(TNS_DATA, encode_o3logon_phase2(
            self._next_seq(), UserB, PwdField))

    def _fv2_raise_for_error(self, Packet: bytes) -> None:
        # Raise the server's error if `Packet` is a 9i OER with a real ORA code
        # (mirror of OracleConnect._fv2_raise_for_error, #102).
        (ErrCode, Message) = decode_fv2_oer_error(Packet)
        if ErrCode and ErrCode not in (0, 1403):
            from oracle.exceptions import from_ora_code
            raise from_ora_code(ErrCode)(
                Message or f"ORA-{ErrCode:05d}", code=ErrCode)

    async def _execute_fv2_dml(self, Query: str,
                               Bind: list | None = None) -> object:
        # Async port of OracleConnect._execute_fv2_dml (#101).
        await self.send(TNS_DATA, encode_o7_open(0))
        await self._next_data_packet()
        await self.send(TNS_DATA, encode_o7_parse(0, Query, Bind))
        Resp = await self._next_data_packet()
        if Resp is False:
            raise Exception("Connection closed during 9i DML")
        (_, Packet) = Resp
        self._fv2_raise_for_error(Packet)            # e.g. ORA-00942
        (RowCount, ErrCode) = decode_fv2_dml_response(Packet)
        await self.send(TNS_DATA, encode_o7_close(0))
        await self._next_data_packet()
        if ErrCode and ErrCode not in (0, 1403):
            from oracle.exceptions import from_ora_code
            raise from_ora_code(ErrCode)(f"ORA-{ErrCode:05d}", code=ErrCode)
        if self.autocommit:
            await self.commit()
        return (0, 0, 0, (RowCount, None), [], None, None, [], None)

    async def _execute_fv2_block(self, Query: str,
                                 Bind: list | None = None) -> object:
        # Async port of OracleConnect._execute_fv2_block (#102, PROTOCOL §19.6 /
        # §19.7). OOPEN + block parse-execute with an OAC per bind; the server
        # prompts, the client sends the IN / IN OUT input values as a standalone
        # RXD, and the reply carries any OUT / IN OUT return values before the
        # RPA + OER. OUT values come back as an {out_positions, out_values}
        # record the cursor decodes into the Var objects.
        from oracle.datatypes import Var
        Bind = Bind or []
        InputValues = [(B._value if isinstance(B, Var) else B)
                       for B in Bind
                       if not isinstance(B, Var) or B.has_value]
        OutPositions = [I for I, B in enumerate(Bind) if isinstance(B, Var)]
        await self.send(TNS_DATA, encode_o7_open(0))
        await self._next_data_packet()               # OOPEN RPA
        await self.send(TNS_DATA, encode_o7_block(0, Query, Bind))
        Resp = await self._next_data_packet()
        if Resp is False:
            raise Exception("Connection closed during 9i PL/SQL block")
        (_, Packet) = Resp
        if InputValues:
            self._fv2_raise_for_error(Packet)        # parse/compile error
            await self.send(TNS_DATA, encode_tokens_rxd(InputValues, b""))
            Resp = await self._next_data_packet()
            if Resp is False:
                raise Exception("Connection closed during 9i PL/SQL bind send")
            (_, Packet) = Resp
        self._fv2_raise_for_error(Packet)            # runtime error
        (OutValues, RowCount, ErrCode) = decode_fv2_block_out(
            Packet, len(OutPositions))
        await self.send(TNS_DATA, encode_o7_close(0))
        await self._next_data_packet()               # close STA
        if ErrCode and ErrCode not in (0, 1403):
            from oracle.exceptions import from_ora_code
            raise from_ora_code(ErrCode)(f"ORA-{ErrCode:05d}", code=ErrCode)
        if self.autocommit:
            await self.commit()
        if OutPositions:
            Record = {'out_positions': OutPositions, 'out_values': OutValues}
            return (0, 0, 0, (None, None), [Record], None, None, [], None)
        return (0, 0, 0, (RowCount, None), [], None, None, [], None)

    async def _execute_fv2(self, Query: str, Bind: list | None = None) -> object:
        # Async port of OracleConnect._execute_fv2: the four-call (plus OOPEN)
        # Oracle 9i TTI_ALL7 SELECT sequence (#97, PROTOCOL.md §19).
        await self.send(TNS_DATA, encode_o7_open(0))
        await self._next_data_packet()               # OOPEN RPA (cursor id)
        await self.send(TNS_DATA, encode_o7_parse(0, Query, Bind))
        Resp = await self._next_data_packet()        # parse ack — or an OER
        if Resp is not False:
            self._fv2_raise_for_error(Resp[1])       # e.g. ORA-00942
        await self.send(TNS_DATA, encode_o7_describe(0))
        Resp = await self._next_data_packet()
        if Resp is False:
            raise Exception("Connection closed during 9i describe")
        (_, Packet) = Resp
        Columns = decode_fv2_describe(Packet)
        # CLOB/BLOB via GETLEN+READ, BFILE via FILE_OPEN/READ/CLOSE — all
        # resolved before the cursor close in _resolve_fv2_lobs (#102).
        # Fetch in batches: re-send the same exec+fetch TTI_ALL7 until the
        # server returns ORA-01403 (#99). Mirrors the sync path.
        AllRows: list = []
        ErrCode = 0
        while True:
            await self.send(TNS_DATA, encode_o7_exec(0, Columns))
            Resp = await self._next_data_packet()
            if Resp is False:
                raise Exception("Connection closed during 9i fetch")
            (_, Packet) = Resp
            (Rows, ErrCode) = decode_fv2_exec_response(Packet, Columns)
            AllRows.extend(Rows)
            if ErrCode == 1403 or not Rows:
                break
        # Resolve LOB cells while the cursor is still open (mirrors sync, #102).
        await self._resolve_fv2_lobs(AllRows, Columns)
        await self.send(TNS_DATA, encode_o7_close(0))
        await self._next_data_packet()               # close STA
        if ErrCode and ErrCode not in (0, 1403):
            from oracle.exceptions import from_ora_code
            raise from_ora_code(ErrCode)(f"ORA-{ErrCode:05d}", code=ErrCode)
        return (0, 0, 0, (len(AllRows), Columns), AllRows, None, None, [], None)

    async def _lob_read_fv2(self, Locator: bytes) -> bytes:
        # Async port of the sync `_lob_read_fv2`: 9i two-call TTI_LOBOPS
        # GETLEN + READ, returning raw content bytes (PROTOCOL.md §19.5, #102).
        await self.send(TNS_DATA, encode_o7_lob_getlen(0, Locator))
        Resp = await self._next_data_packet(b"", b"")
        if Resp is False:
            raise Exception("Connection closed during 9i LOB GETLEN")
        Amount = decode_fv2_lob_getlen(Resp[1])
        if Amount <= 0:
            return b""
        await self.send(TNS_DATA, encode_o7_lob_read(0, Locator, Amount))
        return await self._read_fv2_lob_content()

    async def _bfile_read_fv2(self, Locator: bytes) -> bytes:
        # Async port of the sync `_bfile_read_fv2`: FILE_OPEN → GETLEN → READ →
        # FILE_CLOSE; subsequent ops use the open-flagged locator FILE_OPEN
        # returns (PROTOCOL §19.8, #102).
        await self.send(TNS_DATA, encode_o7_bfile_open(0, Locator))
        Resp = await self._next_data_packet(b"", b"")
        if Resp is False:
            raise Exception("Connection closed during 9i BFILE FILE_OPEN")
        self._fv2_raise_for_error(Resp[1])
        Opened = decode_fv2_opened_locator(Resp[1])
        if Opened is None:
            raise Exception("Unexpected 9i BFILE FILE_OPEN reply",
                            Resp[1][:8].hex())
        try:
            await self.send(TNS_DATA, encode_o7_lob_getlen(0, Opened))
            Resp = await self._next_data_packet(b"", b"")
            if Resp is False:
                raise Exception("Connection closed during 9i BFILE GETLEN")
            Amount = decode_fv2_lob_getlen(Resp[1])
            if Amount <= 0:
                return b""
            await self.send(TNS_DATA, encode_o7_lob_read(0, Opened, Amount))
            return await self._read_fv2_lob_content()
        finally:
            await self.send(TNS_DATA, encode_o7_bfile_close(0, Opened))
            await self._next_data_packet(b"", b"")

    async def _read_fv2_lob_content(self) -> bytes:
        # Async port of the sync `_read_fv2_lob_content`: accumulate packets and
        # re-parse with decode_fv2_lob_chunks until the zero-length terminator
        # (the fv2 READ reply carries no OER call-status). (#102)
        Data = b""
        while True:
            Received = await self._next_data_packet(b"", b"")
            if Received is False:
                raise Exception("Connection closed during 9i LOB READ")
            Data += Received[1]
            (Content, Complete) = decode_fv2_lob_chunks(Data)
            if Complete:
                return Content

    async def _resolve_fv2_lobs(self, Rows: list, Columns: list) -> None:
        # Async port of the sync `_resolve_fv2_lobs` (#102).
        from oracle.lob import LOB
        from oracle.types import decode_fv2_lob
        for Row in Rows:
            for I, Val in enumerate(Row):
                if isinstance(Val, LOB):
                    if Val.data_type == 114:        # BFILE: open / read / close
                        Content = await self._bfile_read_fv2(Val.raw)
                    else:                           # CLOB / BLOB: GETLEN + READ
                        Content = await self._lob_read_fv2(Val.raw)
                    Row[I] = decode_fv2_lob(Columns[I].get('data_type'),
                                            Content,
                                            Columns[I].get('charset') or 0)

    async def _drain_cursor(self, Result: object) -> object:
        """Mirror of the sync drain loop: pulls follow-up FETCH packets
        when the server signals more rows pending."""
        if not isinstance(Result, tuple) or len(Result) < 6:
            return Result
        (CallStatus, OraCode, CursorId, RetFormat, Rows, *Tail) = Result
        AllRows = list(Rows or [])
        RowFormat = None
        if isinstance(RetFormat, tuple) and len(RetFormat) > 1 \
                and isinstance(RetFormat[1], list):
            RowFormat = RetFormat[1]
        if RowFormat and CursorId and CallStatus == 1 and OraCode != 1403:
            while True:
                FetchResult = await self.fetch_more(CursorId, self.fetch,
                                                    RowFormat=RowFormat)
                if not isinstance(FetchResult, tuple) or len(FetchResult) < 6:
                    break
                (CallStatus, OraCode, _, _, MoreRows, *_) = FetchResult
                if MoreRows:
                    AllRows.extend(MoreRows)
                if OraCode == 1403 or CallStatus != 1:
                    break
        if OraCode == 1403:
            OraCode = 0
        return (CallStatus, OraCode, CursorId, RetFormat, AllRows) + tuple(Tail)

    async def fetch_more(self, CursorId: int, Rows: int | None = None,
                         RowFormat: list | None = None) -> object:
        if Rows is None:
            Rows = self.fetch
        Data = encode_dictionary(self._make_dict(DictionaryType.fetch,
                                                  cursor=CursorId, fetch=Rows))
        await self.send(TNS_DATA, Data)
        return await self._handle_response(Acc=(None, RowFormat, []))

    async def fetch_all_rows(self, CursorId: int, RowFormat: list) -> list:
        # Async drain of a server cursor (e.g. a REF CURSOR). Mirrors
        # OracleConnect.fetch_all_rows.
        AllRows: list = []
        while True:
            Result = await self.fetch_more(CursorId, self.fetch,
                                           RowFormat=RowFormat)
            if not isinstance(Result, tuple) or len(Result) < 6:
                break
            (CallStatus, OraCode, _, _, MoreRows, *_) = Result
            if MoreRows:
                AllRows.extend(MoreRows)
            if OraCode == 1403 or CallStatus != 1:
                break
        return AllRows

    # ----- LOB read (async mirror of `OracleConnect.lob_read`) -----

    async def lob_read(self, Locator: bytes, DataType: int,
                       prefixed: bool = False) -> str | bytes:
        """Async port of the sync `lob_read`. See its docstring for
        the wire format we walk through. `prefixed` opts into the
        ub2-length-prefixed locator form required for temp LOBs (#91)."""
        from oracle.tns_consts import TNS_TYPE_CLOB
        Data = encode_dictionary(self._make_dict(DictionaryType.lobops,
                                                  locator=Locator,
                                                  locator_prefixed=prefixed))
        await self.send(TNS_DATA, Data)
        Content = await self._read_lob_response()
        if DataType == TNS_TYPE_CLOB:
            return Content.decode('utf-16-be', errors='replace')
        return Content

    async def gettype(self, name: str) -> 'DbObjectType':
        """Async port of `OracleConnect.gettype` (#116): look up a SQL object
        type by (optionally schema-qualified) name and return a DbObjectType."""
        if '.' in name:
            Schema, _, TypeName = name.partition('.')
            Schema = Schema.strip('"') if '"' in Schema else Schema.upper()
        else:
            Schema, TypeName = None, name
        TypeName = TypeName.strip('"') if '"' in TypeName else TypeName.upper()
        Typ = await self._describe_object_type(Schema, TypeName)
        if Typ is None or (not Typ.attrs and not Typ.is_collection):
            from oracle.exceptions import DatabaseError
            raise DatabaseError(f"object type {name!r} not found")
        return Typ

    async def _describe_object_type(self, schema: str | None,
                                    name: str | None) -> 'DbObjectType | None':
        """Async port of `OracleConnect._describe_object_type` (#115/#116):
        the type's 16-byte OID + version + ordered attribute layout, cached."""
        if not name:
            return None
        from oracle.dbobject import DbObjectType, type_name_to_tns
        Owner = schema
        if Owner is None:
            Result = await self.execute("SELECT USER FROM dual")
            Rows = Result[4] if len(Result) > 4 and Result[4] else []
            Owner = Rows[0][0] if Rows else None
        if not Owner:
            return None
        Key = (Owner, name)
        Cached = self._object_type_cache.get(Key)
        if Cached is not None:
            return Cached
        OidRes = await self.execute(
            "SELECT type_oid, typecode FROM all_types "
            "WHERE owner = :1 AND type_name = :2", Bind=[Owner, name])
        OidRows = OidRes[4] if len(OidRes) > 4 and OidRes[4] else []
        Oid = bytes(OidRows[0][0]) if OidRows and OidRows[0][0] else b""
        TypeCode = OidRows[0][1] if OidRows else None
        Result = await self.execute(
            "SELECT attr_name, attr_type_name, length, precision, scale "
            "FROM all_type_attrs WHERE owner = :1 AND type_name = :2 "
            "ORDER BY attr_no", Bind=[Owner, name])
        Rows = Result[4] if len(Result) > 4 and Result[4] else []
        Attrs = []
        for Row in Rows:
            TypeName = Row[1]
            Attrs.append({
                'name': Row[0],
                'type_name': TypeName,
                'data_type': type_name_to_tns(TypeName),
                'charset': None,
            })
        CollKW = await self._collection_describe(Owner, name, TypeCode)
        Typ = DbObjectType(Owner, name, Oid, 1, Attrs, **CollKW)
        self._object_type_cache[Key] = Typ
        return Typ

    async def _collection_describe(self, owner, name, typecode) -> dict:
        """Async port of `OracleConnect._collection_describe` (#117/#118)."""
        if typecode != 'COLLECTION':
            return {}
        from oracle.dbobject import (
            type_name_to_tns, COLLECTION_VARRAY, COLLECTION_NESTED_TABLE)
        Res = await self.execute(
            "SELECT coll_type, elem_type_name, length, precision, scale, "
            "upper_bound FROM all_coll_types WHERE owner = :1 AND type_name = :2",
            Bind=[owner, name])
        Rows = Res[4] if len(Res) > 4 and Res[4] else []
        if not Rows:
            return {'is_collection': True}
        (CollType, ElemType, _Len, _Prec, _Scale, Upper) = Rows[0][:6]
        return {
            'is_collection': True,
            'collection_type': (COLLECTION_VARRAY if CollType == 'VARYING ARRAY'
                                else COLLECTION_NESTED_TABLE),
            'element': {'name': 'element', 'type_name': ElemType,
                        'data_type': type_name_to_tns(ElemType), 'charset': None},
            'max_elements': int(Upper) if Upper else 0,
        }

    async def _object_type_layout(self, schema: str | None, name: str | None) -> list:
        """The ordered attribute layout (#115 read path), via the type describe."""
        Typ = await self._describe_object_type(schema, name)
        return Typ.attrs if Typ is not None else []

    async def create_temp_lob(self, is_blob: bool = False) -> bytes:
        """Async port of the sync `create_temp_lob` (#91). Allocates a
        session-duration temporary LOB and returns its locator. 12c+ only."""
        from oracle.tns_consts import TTI_RPA
        Data = encode_dictionary(self._make_dict(DictionaryType.lobops,
                                                 create_temp=True,
                                                 is_blob=is_blob))
        await self.send(TNS_DATA, Data)
        Received = await self._next_data_packet(b"", b"")
        if Received is False:
            raise Exception("Connection closed during CREATE_TEMP")
        (_, Packet) = Received
        if not Packet or Packet[0] != TTI_RPA:
            raise Exception("Unexpected CREATE_TEMP response",
                            Packet[:8].hex() if Packet else None)
        LocLen = (Packet[1] << 8) | Packet[2]
        return Packet[3:3 + LocLen]

    async def write_temp_lob(self, Locator: bytes, Data: bytes,
                             is_blob: bool = False) -> None:
        """Async port of the sync `write_temp_lob` (#91)."""
        from oracle.tns_consts import TNS_LOB_OP_WRITE
        Payload = Data if is_blob else Data.encode('utf-16-be')
        Dict = self._make_dict(DictionaryType.lobops, locator=Locator,
                               data=Payload, operation=TNS_LOB_OP_WRITE)
        await self.send(TNS_DATA, encode_dictionary(Dict))
        await self._confirm_lobops()

    async def _confirm_lobops(self) -> None:
        """Async port of the sync `_confirm_lobops`: receive a content-free
        LOBOPS response (WRITE / temp / BFILE open-close) and raise on a
        non-zero OER."""
        Received = await self._next_data_packet(b"", b"")
        if Received is False:
            raise Exception("Connection closed during LOBOPS")
        self._raise_lobops_error(Received[1])

    def _raise_lobops_error(self, Packet: bytes) -> None:
        """Decode the OER trailing a content-free LOBOPS response and raise on a
        real ORA error (call status agnostic — see the sync docstring)."""
        from oracle.tns import decode_lobops_oer
        from oracle.exceptions import from_ora_code
        (ErrCode, Message) = decode_lobops_oer(Packet, self.field_version)
        if ErrCode and ErrCode not in (0, 1403):
            raise from_ora_code(ErrCode)(
                Message or f"ORA-{ErrCode:05d}", code=ErrCode)

    async def bfile_read_native(self, Locator: bytes) -> bytes:
        """Async port of the sync `bfile_read_native` (#46): FILE_OPEN ->
        READ -> FILE_CLOSE over TTI_LOBOPS, using the open-flagged locator the
        server returns from FILE_OPEN."""
        from oracle.tns_consts import (TTI_RPA, TNS_LOB_OP_FILE_OPEN,
                                       TNS_LOB_OP_FILE_CLOSE)
        # See the sync bfile_read_native: strip LOB.raw's leading ub2
        # inner-length so the encoder's prefix isn't doubled.
        if len(Locator) >= 2 and ((Locator[0] << 8) | Locator[1]) == len(Locator) - 2:
            Locator = Locator[2:]
        await self.send(TNS_DATA, encode_dictionary(self._make_dict(
            DictionaryType.lobops, locator=Locator,
            operation=TNS_LOB_OP_FILE_OPEN)))
        Received = await self._next_data_packet(b"", b"")
        if Received is False:
            raise Exception("Connection closed during BFILE FILE_OPEN")
        (_, Packet) = Received
        self._raise_lobops_error(Packet)
        if not Packet or Packet[0] != TTI_RPA:
            raise Exception("Unexpected FILE_OPEN response",
                            Packet[:8].hex() if Packet else None)
        OpenLen = (Packet[1] << 8) | Packet[2]
        Opened = Packet[3:3 + OpenLen]
        try:
            await self.send(TNS_DATA, encode_dictionary(self._make_dict(
                DictionaryType.lobops, locator=Opened, locator_prefixed=True)))
            Content = await self._read_lob_response()
        finally:
            await self.send(TNS_DATA, encode_dictionary(self._make_dict(
                DictionaryType.lobops, locator=Opened,
                operation=TNS_LOB_OP_FILE_CLOSE)))
            await self._confirm_lobops()
        return Content

    async def bfile_read(self, directory_name: str, file_name: str) -> bytes:
        """Read a BFILE by directory object + filename. Resolves the locator
        with a `SELECT BFILENAME` and reads it natively (#46); the cursor's LOB
        auto-resolve runs `bfile_read_native` under the hood."""
        Cur = self.cursor()
        await Cur.execute("SELECT BFILENAME(:d, :f) FROM DUAL",
                          {"d": directory_name, "f": file_name})
        Row = await Cur.fetchone()
        return Row[0]

    async def _read_lob_response(self) -> bytes:
        """Async port of the sync `_read_lob_response`. Same token
        walk; everything between TTI_LOB content and TTI_OER is RPA
        metadata we don't decode."""
        from oracle.tns_consts import TTI_LOB, TTI_OER
        Buffer = b""
        while True:
            Received = await self._next_data_packet(b"", b"")
            if Received is False:
                raise InterfaceError("connection closed during LOBOPS response")
            (Type, Packet) = Received
            if Type != TNS_DATA:
                raise Exception("Unexpected LOBOPS response type", Type)
            Pos = 0
            OerSeen = False
            while Pos < len(Packet):
                Token = Packet[Pos]
                if Token == TTI_LOB:
                    Pos += 1
                    if Pos >= len(Packet):
                        break
                    Length = Packet[Pos]
                    Pos += 1
                    if Length == 0:
                        continue
                    if Length == 0xFE:
                        # Chunked content. 12c+ prefixes each chunk with a ub4
                        # length (terminated by a zero-length chunk); 11g uses a
                        # single length byte per chunk. Without the 12c+ branch
                        # the chunk lengths misparse and the LOB read desyncs,
                        # hanging the next recv (mirrors the sync handler).
                        if self.field_version >= 8:        # FIELD_VERSION_12_2
                            while Pos < len(Packet):
                                NLen = Packet[Pos]
                                Pos += 1
                                if NLen == 0:
                                    break
                                ChunkLen = int.from_bytes(
                                    Packet[Pos:Pos + NLen], "big")
                                Pos += NLen
                                Buffer += Packet[Pos:Pos + ChunkLen]
                                Pos += ChunkLen
                        else:
                            while Pos < len(Packet):
                                ChunkLen = Packet[Pos]
                                Pos += 1
                                if ChunkLen == 0:
                                    break
                                Buffer += Packet[Pos:Pos + ChunkLen]
                                Pos += ChunkLen
                    else:
                        Buffer += Packet[Pos:Pos + Length]
                        Pos += Length
                elif Token == TTI_OER:
                    OerSeen = True
                    break
                else:
                    # Likely TTI_RPA carrying the updated locator/amount — skip
                    # to the trailing OER. Match the stable `04 01 01` prefix as
                    # well as the historical `04 01 XX 01` form (mirrors sync;
                    # 12c+ uses the former, so missing it hangs the read).
                    Found = -1
                    for I in range(Pos, len(Packet) - 3):
                        if (Packet[I] == TTI_OER and Packet[I + 1] == 0x01
                                and (Packet[I + 2] == 0x01
                                     or Packet[I + 3] == 0x01)):
                            Found = I
                            break
                    if Found >= 0:
                        Pos = Found
                        continue
                    break
            if OerSeen:
                return Buffer

    # ----- transaction control -----

    async def commit(self) -> None:
        from oracle.tns_consts import TTI_COMMIT
        Data = encode_dictionary(self._make_dict(DictionaryType.tran,
                                                  req=TTI_COMMIT))
        await self.send(TNS_DATA, Data)
        await self._handle_response()

    async def rollback(self) -> None:
        from oracle.tns_consts import TTI_ROLLBACK
        Data = encode_dictionary(self._make_dict(DictionaryType.tran,
                                                  req=TTI_ROLLBACK))
        await self.send(TNS_DATA, Data)
        await self._handle_response()

    async def ping(self) -> None:
        from oracle.tns_consts import TTI_PING
        Data = encode_dictionary(self._make_dict(DictionaryType.tran,
                                                  req=TTI_PING))
        await self.send(TNS_DATA, Data)
        await self._handle_response()

    async def changepassword(self, old_password: str,
                             new_password: str) -> None:
        """Change the connected user's password (#21). Async mirror of
        `OracleConnect.changepassword` — same single TTI_AUTH password-change
        call reusing the login session key, same error behaviour."""
        from oracle.exceptions import from_ora_code
        if self.conn_state != CONN_STATE_AUTHENTICATED or self.conn_key is None:
            raise InterfaceError(
                "changepassword requires an authenticated connection")
        Auth = {
            'conn_key': self.conn_key,
            'old_password': old_password,
            'new_password': new_password,
        }
        Data = encode_dictionary(
            self._make_dict(DictionaryType.chgpwd, auth=Auth))
        await self.send(TNS_DATA, Data)
        Result = await self._handle_response()
        ErrCode = Result[1] if isinstance(Result, tuple) and len(Result) > 1 else 0
        if ErrCode and ErrCode not in (0, 1403):
            Message = Result[5] if len(Result) > 5 else None
            raise from_ora_code(ErrCode)(
                Message or f"ORA-{ErrCode:05d}", code=ErrCode)
        self.password = new_password

    # ----- teardown -----

    @property
    def call_timeout(self) -> int:
        """Per-call timeout in milliseconds (0 = none); see OracleConnect (#123)."""
        return self._call_timeout

    @call_timeout.setter
    def call_timeout(self, value: int) -> None:
        self._call_timeout = max(0, int(value or 0))

    def cancel(self) -> None:
        """Interrupt the call currently executing on this connection (#123).
        Async port of OracleConnect.cancel(); a plain (non-coroutine) method so
        it can fire from a timer/callback. Sends an out-of-band break."""
        self._send_break()

    def _on_call_timeout(self) -> None:
        self._timed_out = True
        self._send_break()

    def _send_break(self) -> None:
        # OOB break via the StreamWriter's underlying socket (see OracleConnect
        # for why OOB only). asyncio wraps the socket in a TransportSocket that
        # forbids direct send(), so reach the real socket via its private _sock;
        # if that's unavailable the break is a best-effort no-op (no protocol
        # residue). Relies on the network path carrying urgent data. #123,
        # untested locally (the container port-forward does not deliver OOB).
        if self._break_in_progress or self._writer is None:
            return
        self._break_in_progress = True
        Sock = self._writer.get_extra_info('socket')
        Raw = getattr(Sock, '_sock', None) if Sock is not None else None
        Target = Raw if Raw is not None and hasattr(Raw, 'send') else Sock
        if Target is not None and hasattr(Target, 'send'):
            try:
                Target.send(b"!", socket.MSG_OOB)
            except OSError:
                pass

    async def close(self) -> None:
        """Send TNS logoff, then close the underlying writer."""
        if self._writer is None:
            return
        try:
            Data = encode_dictionary(self._make_dict(DictionaryType.close))
            await self.send(TNS_DATA, Data)
        except Exception:
            # Best-effort logoff: if the server already hung up we still
            # want to tear down the local socket below.
            pass
        await self.disconnect()

    async def disconnect(self) -> None:
        if self._writer is not None:
            try:
                if self._writer.can_write_eof():
                    self._writer.write_eof()
            except (OSError, AttributeError):
                # The transport may not support EOF or may already be
                # closed; proceed straight to close() either way.
                pass
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except OSError:
                # The socket may already be torn down by the peer; the
                # writer is being discarded regardless.
                pass
            self._writer = None
            self._reader = None

    # ----- factory (cursor created lazily in step 2) -----

    def cursor(self):
        """Returns an `AsyncCursor` bound to this connection."""
        # Lazy import to avoid a circular dep with acursor importing us.
        from oracle.acursor import AsyncCursor
        return AsyncCursor(self)

    # ----- async context manager -----

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()
