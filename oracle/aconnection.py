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
from oracle.exceptions import InterfaceError
from oracle.tns import assemble_packet
from oracle.tns import decode_packet
from oracle.tns import decode_token_pro
from oracle.tns import decode_token_rpa
from oracle.tns import encode_dictionary
from oracle.tns import encode_packet
from oracle.tns import exec_oac_signature
from oracle.tns import CCAP_FIELD_VERSION, FIELD_VERSION_11_2
from oracle.connection import _format_version
from oracle.tns_consts import (
    CONN_STATE_AUTHENTICATED, CONN_STATE_AUTH_NEGOTIATE,
    CONN_STATE_CONNECTED, CONN_STATE_DISCONNECTED,
    DictionaryType, TNS_ACCEPT, TNS_CONNECT, TNS_DATA, TNS_MARKER,
    TNS_REDIRECT, TNS_REFUSE, TNS_RESEND, TTI_DTY, TTI_PRO, TTI_RPA,
    TTI_SESS, TTI_WRN,
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
                 app_name: str = "pyoracle"):
        self.host = host
        self.port = port
        self.user = user
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
        self.conn_key = None
        self.server_version = 0
        self.session_id = None
        # Negotiated TTC field version; see OracleConnect for the full note.
        self.field_version = FIELD_VERSION_11_2
        self.cursors: dict[int, int] = {}
        # Cursor cache — same shape as the sync `OracleConnect`. DML only.
        # Keyed on (SQL, bind OAC signature); see OracleConnect for why the
        # bind signature has to be part of the key.
        self._cursor_cache: dict[tuple[str, bytes], int] = {}
        self._cursor_cache_max = 32

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

    async def connect(self) -> bool:
        """Open the TCP (optionally TLS) connection and run the
        TNS / TTC / O5LOGON handshake."""
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
        but awaiting the StreamReader instead of `sock.recv`."""
        while True:
            try:
                NetworkData = await self._reader.read(self.sdu)
            except asyncio.IncompleteReadError:
                return False
            if not NetworkData:
                return False
            Acc = Acc + NetworkData
            while len(Acc) >= 8:
                (Flag, Type, Body, Rest) = assemble_packet(Acc, self.sdu)
                if Flag is True and Type == TNS_MARKER:
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

    # ----- login state machine -----

    async def handle_login(self) -> int | None:
        """Async port of `OracleConnect.handle_login`."""
        while True:
            Received = await self.recv(b"", b"")
            if Received is False:
                logger.debug("handle_login (async): peer closed")
                return 1
            (Type, Packet) = Received
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
                            Data = encode_dictionary(self._make_dict(DictionaryType.dty))
                            await self.send(TNS_DATA, Data)
                        case p if p == TTI_DTY:
                            Data = encode_dictionary(self._make_dict(DictionaryType.sess))
                            await self.send(TNS_DATA, Data)
                        case p if p == TTI_RPA:
                            return await self._handle_rpa(Packet[1:])
                        case p if p == TTI_WRN:
                            logger.debug("handle_login: recv WRN %s", Packet[1:])
                        case _:
                            logger.debug("handle_login: unknown token %s",
                                         Packet[0])
                    continue
                case t if t == TNS_MARKER:
                    await self.send(TNS_MARKER, b"\x01\x00\x02")
                    continue
                case t if t == TNS_REDIRECT:
                    return 1
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
        while True:
            Received = await self.recv(b"", b"")
            if Received is False:
                raise InterfaceError("connection closed while awaiting response")
            (Type, Packet) = Received
            match Type:
                case t if t == TNS_DATA:
                    return decode_packet(Packet, Acc, self.field_version)
                case t if t == TNS_MARKER:
                    await self.send(TNS_MARKER, b"\x01\x00\x02")
                    continue
                case _:
                    raise Exception("Unexpected response type", Type)

    # ----- execute / fetch (kept minimal for the first cut) -----

    async def execute(self, Query: str, Bind: list | None = None,
                      Def: list | None = None, Batch: list | None = None) -> object:
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
        if Type == 'change' and not Def:
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
        }
        Data = encode_dictionary(self._make_dict(DictionaryType.exec, query=QueryDict))
        await self.send(TNS_DATA, Data)
        try:
            # Seed the decoder with the binds so the IOV decoder can tell a
            # REF CURSOR OUT bind from a scalar one.
            Result = await self._handle_response((None, None, [], Bind))
        except Exception:
            if CachedCursor:
                self._cursor_cache.pop(CacheKey, None)
            raise
        if (Type == 'change' and not Def
                and isinstance(Result, tuple) and len(Result) >= 3
                and isinstance(Result[2], int) and Result[2] > 0
                and Result[1] in (0, 1403)):
            CursorId = Result[2]
            self._cursor_cache.pop(CacheKey, None)
            self._cursor_cache[CacheKey] = CursorId
            while len(self._cursor_cache) > self._cursor_cache_max:
                Oldest = next(iter(self._cursor_cache))
                self._cursor_cache.pop(Oldest, None)
        return await self._drain_cursor(Result)

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

    async def lob_read(self, Locator: bytes, DataType: int) -> str | bytes:
        """Async port of the sync `lob_read`. See its docstring for
        the wire format we walk through."""
        from oracle.tns_consts import TNS_TYPE_CLOB
        Data = encode_dictionary(self._make_dict(DictionaryType.lobops,
                                                  locator=Locator))
        await self.send(TNS_DATA, Data)
        Content = await self._read_lob_response()
        if DataType == TNS_TYPE_CLOB:
            return Content.decode('utf-16-be', errors='replace')
        return Content

    async def bfile_read(self, directory_name: str, file_name: str) -> bytes:
        """Async port of the sync `bfile_read`. Uses the same server-side
        helper function (auto-installed on first use)."""
        from oracle.connection import _BFILE_HELPER_NAME, _BFILE_HELPER_SQL
        from oracle.exceptions import DatabaseError
        Cur = self.cursor()
        try:
            await Cur.execute(
                f"SELECT {_BFILE_HELPER_NAME}(:d, :f) FROM DUAL",
                {"d": directory_name, "f": file_name},
            )
        except DatabaseError as exc:
            if exc.code not in (904, 6550):
                raise
            Install = self.cursor()
            await Install.execute(_BFILE_HELPER_SQL)
            Cur = self.cursor()
            await Cur.execute(
                f"SELECT {_BFILE_HELPER_NAME}(:d, :f) FROM DUAL",
                {"d": directory_name, "f": file_name},
            )
        Row = await Cur.fetchone()
        return Row[0]

    async def _read_lob_response(self) -> bytes:
        """Async port of the sync `_read_lob_response`. Same token
        walk; everything between TTI_LOB content and TTI_OER is RPA
        metadata we don't decode."""
        from oracle.tns_consts import TTI_LOB, TTI_OER
        Buffer = b""
        while True:
            Received = await self.recv(b"", b"")
            if Received is False:
                raise InterfaceError("connection closed during LOBOPS response")
            (Type, Packet) = Received
            if Type != TNS_DATA:
                if Type == TNS_MARKER:
                    await self.send(TNS_MARKER, b"\x01\x00\x02")
                    continue
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
                    Found = -1
                    for I in range(Pos, len(Packet) - 3):
                        if (Packet[I] == TTI_OER and Packet[I + 1] == 0x01
                                and Packet[I + 3] == 0x01):
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

    # ----- teardown -----

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
