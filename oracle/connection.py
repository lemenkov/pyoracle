# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

from oracle.crypto import validate
from oracle.tns import assemble_packet
from oracle.tns import decode_token_pro
from oracle.tns import decode_token_rpa
from oracle.tns import encode_dictionary
from oracle.tns import encode_packet
from oracle.tns import exec_oac_signature
from oracle.tns import CCAP_FIELD_VERSION, FIELD_VERSION_11_2, FIELD_VERSION_12_1
from oracle.tns_consts import (
    CONN_STATE_AUTH_NEGOTIATE, CONN_STATE_AUTHENTICATED,
    CONN_STATE_CONNECTED, CONN_STATE_DISCONNECTED, DictionaryType,
    MAX_SEQ_NUM, TNS_ACCEPT, TNS_CONNECT, TNS_DATA, TNS_MARKER,
    TNS_REDIRECT, TNS_REFUSE, TNS_RESEND, TTI_AUTH, TTI_DTY, TTI_PRO,
    TTI_OER, TTI_RPA, TTI_SESS, TTI_WRN,
)
import logging
import socket
import struct

logger = logging.getLogger(__name__)

# Server-side helper used by `OracleConnect.bfile_read`. Reads a BFILE
# end-to-end into a temporary BLOB and returns that BLOB by value, which
# lets the client get the file contents back over the regular CLOB/BLOB
# wire path without needing a BFILE-specific TTI_LOBOPS OPEN opcode.
# Created lazily on first BFILE read; CREATE OR REPLACE so a stale
# version from an earlier driver release gets overwritten.
_BFILE_HELPER_NAME = "pyoracle_bfile_read"
_BFILE_HELPER_SQL = """\
CREATE OR REPLACE FUNCTION pyoracle_bfile_read (
    p_dir IN VARCHAR2,
    p_file IN VARCHAR2
) RETURN BLOB IS
    loc BFILE := BFILENAME(p_dir, p_file);
    result BLOB;
    src_offset INTEGER := 1;
    dst_offset INTEGER := 1;
    src_len INTEGER;
BEGIN
    DBMS_LOB.CREATETEMPORARY(result, TRUE);
    DBMS_LOB.FILEOPEN(loc, DBMS_LOB.LOB_READONLY);
    src_len := DBMS_LOB.GETLENGTH(loc);
    DBMS_LOB.LOADBLOBFROMFILE(result, loc, src_len, dst_offset, src_offset);
    DBMS_LOB.FILECLOSE(loc);
    RETURN result;
END;
"""


def _format_version(Packed: int) -> str | None:
    # Oracle packs the release into a single integer: major (8 bits),
    # minor (4), update (8), patch (4), port-specific update (8). Verified
    # against product_component_version on XE 11.2.0.2.0 (0x0b200200).
    if not Packed:
        return None
    return "%d.%d.%d.%d.%d" % (
        (Packed >> 24) & 0xFF, (Packed >> 20) & 0x0F, (Packed >> 12) & 0xFF,
        (Packed >> 8) & 0x0F, Packed & 0xFF)


class OracleConnect:
    def __init__(self, host: str = "localhost", port: int = 1521, user: str = "", password: str = "", sid: str = "", service_name: str = "", ssl: object = None, socket_options: object = None, timeout: int = 15000, autocommit: bool = True, fetch: int = 15, role: int = 0, prelim: int = 0, sdu: int = 8192, charset: str = "utf-8", app_name: str = "pyoracle", field_version: int = FIELD_VERSION_11_2):
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

        self.sock = None
        self.seq = 1
        self.conn_key = None
        self.server_version = 0
        self.session_id = None
        # Negotiated TTC field version. Starts at the client's advertised max
        # (the field_version arg; 11.2 by default) and is lowered to the
        # server's during the PRO handshake — min(client, server), see
        # handle_login. Decoders use this to pick version-gated wire formats
        # (issue #27). Pass field_version=FIELD_VERSION_21_1 to speak 12c+.
        self.field_version = field_version
        self.cursors: dict[int, int] = {}
        # Cursor cache: (SQL text, bind OAC signature) → server-side cursor
        # handle. Lets repeat `execute()` of the same SQL skip the parse step
        # on the server. The bind signature is part of the key because a cached
        # re-execute does not re-send the OAC, so the cursor may only be reused
        # for binds matching the size/type it was parsed with (see
        # exec_oac_signature). Capped to keep memory predictable; LRU eviction
        # via insertion order (Python's regular dict).
        self._cursor_cache: dict[tuple[str, bytes], int] = {}
        self._cursor_cache_max = 32

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
    def version(self) -> str | None:
        """Server version as a dotted release string (e.g. '11.2.0.2.0'), or
        None before authentication. Decoded from the packed AUTH_VERSION_NO the
        server returns at logon; oracledb-compatible."""
        return _format_version(self.server_version)

    def _next_seq(self) -> int:
        seq = self.seq
        self.seq = self.seq % MAX_SEQ_NUM + 1
        return seq

    def _make_dict(self, Type: DictionaryType, **extra) -> dict:
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

    def state_to_dict(self, Type: DictionaryType) -> dict:
        return self._make_dict(Type)

    def connect(self) -> bool:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        if self.ssl:
            try:
                self.sock = self._wrap_socket_tls(self.sock)
            except BaseException:
                # If the TLS wrap fails (bad config, cert verification, etc.)
                # release the raw TCP socket before surfacing the error.
                try:
                    self.sock.close()
                finally:
                    self.sock = None
                raise
        Data = encode_dictionary(self._make_dict(DictionaryType.login))

        self.send(TNS_CONNECT, Data)
        self.handle_login()

        return True

    def _wrap_socket_tls(self, RawSock: socket.socket) -> socket.socket:
        # Promote the freshly-connected TCP socket to TLS before any TNS bytes
        # are exchanged. The ``ssl`` constructor argument accepts:
        #
        #   True      — system trust store, hostname verification on
        #   dict      — keyword arguments forwarded to a default context:
        #                 ca_certs, certfile, keyfile, check_hostname,
        #                 verify_mode (ssl.CERT_NONE / CERT_REQUIRED), and
        #                 server_hostname (override the SNI hostname)
        #   SSLContext — used verbatim
        import ssl as _ssl
        Server = self.host
        if isinstance(self.ssl, _ssl.SSLContext):
            Ctx = self.ssl
        elif isinstance(self.ssl, dict):
            Opts = dict(self.ssl)
            Server = Opts.pop("server_hostname", Server)
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
        else:
            Ctx = _ssl.create_default_context()
            Ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
        return Ctx.wrap_socket(RawSock, server_hostname=Server)

    def handle_login(self) -> int | None:
        # Iterative login state machine. Each round either: completes the
        # handshake (TTI_RPA → _handle_rpa), terminates (TNS_REFUSE /
        # unexpected / EOF), or sends the next request and loops to read
        # the server's reply. Was previously recursive — a few-round
        # handshake could approach Python's default recursion limit, and
        # an EOF during the handshake crashed unpacking `recv() → False`.
        while True:
            Received = self.recv(b"", b"")
            if Received is False:
                # Peer closed during handshake.
                logger.debug("handle_login: connection closed by peer")
                return 1
            (Type, Packet) = Received
            match Type:
                case t if t == TNS_ACCEPT:
                    logger.debug("handle_login: accept")
                    # Extract negotiated SDU from the accept body
                    (Ver, Opts, Sdu) = struct.unpack(">hhh", Packet[:6])
                    self.sdu = Sdu
                    self.conn_state = CONN_STATE_CONNECTED
                    logger.debug("handle_login: Ver=%s, Opts=%s, Sdu=%s", Ver, Opts, Sdu)
                    Data = encode_dictionary(self._make_dict(DictionaryType.pro))
                    self.send(TNS_DATA, Data)
                    continue
                case t if t == TNS_DATA:
                    match Packet[0]:
                        case p if p == TTI_PRO:
                            logger.debug("handle_login: recv PRO")
                            self._negotiate_capabilities(Packet)
                            Data = encode_dictionary(self._make_dict(DictionaryType.dty))
                            self.send(TNS_DATA, Data)
                        case p if p == TTI_DTY:
                            logger.debug("handle_login: recv DTY")
                            Data = encode_dictionary(self._make_dict(DictionaryType.sess))
                            self.send(TNS_DATA, Data)
                        case p if p == TTI_RPA:
                            logger.debug("handle_login: recv RPA")
                            return self._handle_rpa(Packet[1:])
                        case p if p == TTI_WRN:
                            logger.debug("handle_login: recv WRN %s", Packet[1:])
                        case p if p == TTI_OER:
                            # The server reports an auth-time failure (bad
                            # password, rejected password change, ...) as an OER
                            # token, sometimes preceded by a break marker.
                            # Decode it and raise rather than looping forever on
                            # an empty socket.
                            logger.debug("handle_login: recv OER")
                            from oracle.tns import decode_packet
                            from oracle.exceptions import DatabaseError, from_ora_code
                            # Via decode_packet so the negotiated field version
                            # is published for the (version-gated) OER decode.
                            Result = decode_packet(Packet, (None, None, []),
                                                   self.field_version)
                            ErrCode = Result[1]
                            Message = Result[5] if len(Result) > 5 else None
                            if ErrCode and ErrCode not in (0, 1403):
                                raise from_ora_code(ErrCode)(
                                    Message or f"ORA-{ErrCode:05d}", code=ErrCode)
                            raise DatabaseError("authentication failed")
                        case _:
                            logger.debug("handle_login: unknown token %s", Packet[0])
                    continue
                case t if t == TNS_MARKER:
                    logger.debug("handle_login: marker")
                    # Respond to marker with same marker pattern
                    self.send(TNS_MARKER, b"\x01\x00\x02")
                    continue
                case t if t == TNS_REDIRECT:
                    logger.debug("handle_login: redirect %s", Packet)
                    # FIXME: parse redirect address and reconnect
                    return 1
                case t if t == TNS_REFUSE:
                    logger.debug("handle_login: refuse")
                    self.disconnect()
                    return 1
                case t if t == TNS_RESEND:
                    logger.debug("handle_login: resend")
                    self.conn_state = CONN_STATE_AUTH_NEGOTIATE
                    Data = encode_dictionary(self._make_dict(DictionaryType.login))
                    self.send(TNS_CONNECT, Data)
                    continue
                case _:
                    logger.debug("handle_login: unexpected %s", Type)
                    return 1

    def _negotiate_capabilities(self, Packet: bytes) -> None:
        # Parse the server's PRO response and lower our field version to the
        # server's if it is older — the effective version is min(client,
        # server), the same rule python-oracledb applies. Sent next in our DTY
        # so both sides agree. Best-effort: a parse failure must not break a
        # handshake that works today, so we keep the default on any error.
        try:
            Pro = decode_token_pro(Packet)
            Caps = Pro['compile_caps']
            if len(Caps) > CCAP_FIELD_VERSION:
                ServerFv = Caps[CCAP_FIELD_VERSION]
                self.field_version = min(self.field_version, ServerFv)
            logger.debug("handle_login: PRO server_version=%s banner=%r "
                         "field_version=%s", Pro['server_version'],
                         Pro['banner'], self.field_version)
        except Exception:
            # Unknown PRO layout — keep the default field version (11.2).
            logger.debug("handle_login: could not parse PRO caps", exc_info=True)

    def _handle_rpa(self, Data: bytes) -> int | None:
        Result = decode_token_rpa(Data, None)
        if Result[0] == TTI_SESS:
            # Auth challenge: (TTI_SESS, SessKey, Salt, DerivedSalt)
            (_, SessKey, Salt, DerivedSalt) = Result
            logger.debug("handle_login: auth challenge received")
            self.conn_state = CONN_STATE_AUTH_NEGOTIATE
            Auth = {
                'sess': bytes.fromhex(SessKey.decode('utf-8')) if SessKey else None,
                'salt': bytes.fromhex(Salt.decode('utf-8')) if Salt else None,
                'derived_salt': bytes.fromhex(DerivedSalt.decode('utf-8')) if DerivedSalt else None,
            }
            Result = encode_dictionary(self._make_dict(DictionaryType.auth, auth=Auth))
            (Data, ConnKey) = Result
            self.conn_key = ConnKey
            self.send(TNS_DATA, Data)
            return self.handle_login()
        elif Result[0] == TTI_AUTH:
            # Auth result: (TTI_AUTH, Resp, Ver, SessId)
            (_, Resp, Ver, SessId) = Result
            logger.debug("handle_login: auth result Ver=%s SessId=%s", Ver, SessId)
            if validate(bytes.fromhex(Resp.decode('utf-8')), self.conn_key):
                self.server_version = Ver
                self.session_id = SessId
                self.conn_state = CONN_STATE_AUTHENTICATED
                logger.debug("handle_login: authenticated")
                return 0
            else:
                logger.error("handle_login: server validation failed")
                self.disconnect()
                return 1
        else:
            logger.error("handle_login: unexpected RPA result %s", Result[0])
            return 1

    def execute(self, Query: str, Bind: list | None = None, Def: list | None = None,
                Batch: list | None = None) -> object:
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
            # Anonymous PL/SQL block: uses the dedicated 'block' exec option
            # set (set_opts), not the DML 'change' path — otherwise the server
            # rejects a block carrying binds with ORA-00600 [12259].
            Type = 'block'
        else:
            Type = 'change'
        Auto = 1 if self.autocommit else 0
        # Cursor cache lookup: if we've executed this SQL before and the
        # server returned a non-zero cursor id, reuse that handle and
        # skip the parse step. Limited to DML for now — caching SELECT
        # would also need to remember the row format the server sent in
        # the DCB during the first parse (a cached SELECT doesn't get
        # a fresh DCB), and that's a wider change. `Def` (output
        # definitions) varying also breaks the cache contract.
        CachedCursor = 0
        CacheKey = None
        # The cursor cache reuses a server cursor handle and skips re-sending
        # the SQL/OAC. That 11g optimization doesn't translate to 12c+: a
        # cached re-execute there fails (ORA-01009 / ORA-03115) because the
        # server expects the binds (and OAC) declared every execute. Disable
        # the cache on 12c+ — each execute re-parses, which is correct, just
        # without the handle-reuse speedup.
        if Type == 'change' and not Def and self.field_version < FIELD_VERSION_12_1:
            CacheKey = (Query, exec_oac_signature(Bind, Batch))
            CachedCursor = self._cursor_cache.get(CacheKey, 0)
        SendQuery = "" if CachedCursor else Query
        QueryDict = {
            'type': Type,
            'auto': Auto,
            'fetch': self.fetch,
            'server_version': self.server_version,
            'cursor': CachedCursor,
            'query': SendQuery,
            'bind': Bind,
            'batch': Batch,
            'def': Def,
        }
        Data = encode_dictionary(self._make_dict(DictionaryType.exec, query=QueryDict))
        self.send(TNS_DATA, Data)
        try:
            # Seed the decoder with the bind list so the IOV decoder can tell a
            # REF CURSOR OUT bind from a scalar one.
            Result = self._handle_response((None, None, [], Bind))
        except Exception:
            # If reusing a cached cursor blew up, drop it from the cache
            # so the next attempt re-parses from scratch.
            if CachedCursor:
                self._cursor_cache.pop(CacheKey, None)
            raise
        # Stash the cursor id the server returned so the next execute of
        # the same SQL can skip parsing. Same scoping as the lookup:
        # DML only, no Def overrides.
        if (Type == 'change' and not Def
                and isinstance(Result, tuple) and len(Result) >= 3
                and isinstance(Result[2], int) and Result[2] > 0
                and Result[1] in (0, 1403)):
            CursorId = Result[2]
            # LRU bump: move the entry to the end on hit; evict the oldest
            # entry when the cache fills up.
            self._cursor_cache.pop(CacheKey, None)
            self._cursor_cache[CacheKey] = CursorId
            while len(self._cursor_cache) > self._cursor_cache_max:
                Oldest = next(iter(self._cursor_cache))
                self._cursor_cache.pop(Oldest, None)
        return self._drain_cursor(Result)

    def _drain_cursor(self, Result: object) -> object:
        # The EXEC response either bundles all rows inline (small SELECTs,
        # all DDL/DML) or only returns column metadata and signals "more on
        # this cursor" via OER.call_status == 1. In the latter case the
        # client is expected to issue follow-up TTI_FETCH calls until the
        # server returns ORA-01403 (end-of-fetch). This applies to any
        # large result set and to *every* SELECT that touches a LOB column,
        # regardless of size — see docs/PROTOCOL.md §5.2.
        if not isinstance(Result, tuple) or len(Result) < 6:
            return Result
        (CallStatus, OraCode, CursorId, RetFormat, Rows, *Tail) = Result
        AllRows = list(Rows or [])
        RowFormat = None
        if isinstance(RetFormat, tuple) and len(RetFormat) > 1 \
                and isinstance(RetFormat[1], list):
            RowFormat = RetFormat[1]
        # No row format means there's nothing further to fetch (DDL / DML
        # responses), and CursorId == 0 means no cursor to fetch from.
        if RowFormat and CursorId and CallStatus == 1 and OraCode != 1403:
            while True:
                FetchResult = self.fetch_more(CursorId, self.fetch,
                                              RowFormat=RowFormat)
                if not isinstance(FetchResult, tuple) or len(FetchResult) < 6:
                    break
                (CallStatus, OraCode, _, _, MoreRows, *_) = FetchResult
                if MoreRows:
                    AllRows.extend(MoreRows)
                # ORA-01403 is the server saying "you've drained the cursor";
                # call_status != 1 means the same thing via a different field.
                if OraCode == 1403 or CallStatus != 1:
                    break
        # Hide the ORA-01403 sentinel from callers; it was an internal
        # protocol marker, not a user-visible error.
        if OraCode == 1403:
            OraCode = 0
        return (CallStatus, OraCode, CursorId, RetFormat, AllRows) + tuple(Tail)

    def fetch_more(self, CursorId: int, Rows: int | None = None,
                   RowFormat: list | None = None) -> object:
        # FETCH responses carry RXH / RXD / OER but no DCB — the column
        # metadata was already established during the original EXEC. Seed
        # the decoder Acc with the prior RowFormat so the per-row DALC
        # parser knows how many columns to read.
        if Rows is None:
            Rows = self.fetch
        Data = encode_dictionary(self._make_dict(DictionaryType.fetch,
                                                  cursor=CursorId, fetch=Rows))
        self.send(TNS_DATA, Data)
        return self._handle_response(Acc=(None, RowFormat, []))

    def fetch_all_rows(self, CursorId: int, RowFormat: list) -> list:
        # Drain a server cursor (e.g. a REF CURSOR returned by a procedure)
        # by issuing TTI_FETCH until the server signals end-of-fetch.
        AllRows: list = []
        while True:
            Result = self.fetch_more(CursorId, self.fetch, RowFormat=RowFormat)
            if not isinstance(Result, tuple) or len(Result) < 6:
                break
            (CallStatus, OraCode, _, _, MoreRows, *_) = Result
            if MoreRows:
                AllRows.extend(MoreRows)
            if OraCode == 1403 or CallStatus != 1:
                break
        return AllRows

    def lob_read(self, Locator: bytes, DataType: int) -> str | bytes:
        # Send TTI_LOBOPS READ for the given locator and decode the response.
        # The response carries:
        #
        #   TNS_MSG_TYPE_LOB_DATA (= 14)  →  length-prefixed content chunk
        #   TTI_RPA                       →  return parameters (locator update +
        #                                    actual amount); we skip these
        #   TTI_OER                       →  end-of-call status
        #
        # CLOB / NCLOB content is sent as UTF-16BE on the wire; BLOB / BFILE
        # is raw bytes. We decode CLOB to `str` and surface BLOB as `bytes`.
        from oracle.tns_consts import TNS_TYPE_CLOB
        Data = encode_dictionary(self._make_dict(DictionaryType.lobops,
                                                  locator=Locator))
        self.send(TNS_DATA, Data)
        Content = self._read_lob_response()
        if DataType == TNS_TYPE_CLOB:
            return Content.decode('utf-16-be', errors='replace')
        return Content

    def bfile_read(self, directory_name: str, file_name: str) -> bytes:
        # BFILE READ goes through a server-side helper that does the
        # DBMS_LOB.FILEOPEN / READ / FILECLOSE dance into a temporary
        # BLOB, then returns that BLOB by value. The driver creates
        # the helper on first use, then re-uses it across calls.
        #
        # Why the helper instead of inlining everything in TTI_LOBOPS:
        # BFILEs need an explicit FILEOPEN before READ, and the LOBOPS
        # opcode for that hasn't been reverse-engineered (the unmodified
        # READ opcode returns empty bytes against an unopened BFILE).
        # The helper sidesteps the opcode question by going through
        # PL/SQL — and uses two same-type VARCHAR2 binds so it also
        # sidesteps the mixed-type bind bug (#13).
        from oracle.exceptions import DatabaseError
        Cur = self.cursor()
        try:
            Cur.execute(
                f"SELECT {_BFILE_HELPER_NAME}(:d, :f) FROM DUAL",
                {"d": directory_name, "f": file_name},
            )
        except DatabaseError as exc:
            # ORA-00904 (invalid identifier) or ORA-06550 (PL/SQL compile
            # — "PLS-00201: identifier must be declared") both mean the
            # helper isn't installed yet. Install it and retry.
            if exc.code not in (904, 6550):
                raise
            Install = self.cursor()
            Install.execute(_BFILE_HELPER_SQL)
            Cur = self.cursor()
            Cur.execute(
                f"SELECT {_BFILE_HELPER_NAME}(:d, :f) FROM DUAL",
                {"d": directory_name, "f": file_name},
            )
        return Cur.fetchone()[0]

    def _read_lob_response(self) -> bytes:
        # Walk the LOBOPS response packets, accumulating LOB_DATA chunks
        # until we hit the trailing OER. A LOBOPS response packet on 11g
        # carries: TTI_LOB (content) + TTI_RPA (updated locator) + TTI_OER
        # (call status). We pull the content out of the LOB chunk(s) and
        # use OER as the stop signal; everything between LOB and OER is
        # RPA-shaped metadata we don't need.
        from oracle.tns_consts import TNS_MARKER, TTI_LOB, TTI_OER
        Buffer = b""
        while True:
            (Type, Packet) = self.recv(b"", b"")
            if Type != TNS_DATA:
                if Type == TNS_MARKER:
                    self.send(TNS_MARKER, b"\x01\x00\x02")
                    continue
                raise Exception("Unexpected LOBOPS response type", Type)
            Pos = 0
            OerSeen = False
            while Pos < len(Packet):
                Token = Packet[Pos]
                if Token == TTI_LOB:
                    # Content chunk. Format: token + 1-byte length + data, or
                    # token + 0xFE + chunked sequence of <ub1 len><bytes>.
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
                        # single length byte per chunk.
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
                    # End of call. Anything after is fluff.
                    OerSeen = True
                    break
                else:
                    # Likely TTI_RPA (0x08) carrying the updated locator and
                    # actual amount read — we don't decode it. Scan forward for
                    # the OER and stop. The OER opens with TTI_OER + call_status
                    # (ub4 len 1, value 1) = `04 01 01`, then the end-to-end
                    # seq# whose length byte (the original 11g signature's 4th
                    # byte) varies per call — so match the stable `04 01 01`
                    # prefix as well as the historical `04 01 XX 01` form.
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
                    # No OER in this packet — fall out and recv the next one.
                    break
            if OerSeen:
                return Buffer
            # Packet exhausted without hitting OER; loop and recv the next.

    def commit(self) -> None:
        from oracle.tns_consts import TTI_COMMIT
        Data = encode_dictionary(self._make_dict(DictionaryType.tran, req=TTI_COMMIT))
        self.send(TNS_DATA, Data)
        self._handle_response()

    def rollback(self) -> None:
        from oracle.tns_consts import TTI_ROLLBACK
        Data = encode_dictionary(self._make_dict(DictionaryType.tran, req=TTI_ROLLBACK))
        self.send(TNS_DATA, Data)
        self._handle_response()

    def ping(self) -> None:
        from oracle.tns_consts import TTI_PING
        Data = encode_dictionary(self._make_dict(DictionaryType.tran, req=TTI_PING))
        self.send(TNS_DATA, Data)
        self._handle_response()

    def close(self) -> None:
        # Best-effort orderly shutdown, then always disconnect so the OS socket
        # gets reclaimed even if the server-side handshake has gone sideways.
        if self.conn_state == CONN_STATE_DISCONNECTED:
            return
        try:
            if self.conn_state == CONN_STATE_AUTHENTICATED:
                if not self.autocommit:
                    self.rollback()
                # Close all cached cursors via piggyback
                if self.cursors:
                    from oracle.tns_consts import TTI_OCCA
                    Data = encode_dictionary(self._make_dict(DictionaryType.pig, req=TTI_OCCA, cursor=list(self.cursors.values())))
                    self.send(TNS_DATA, Data)
                # Logoff (the TTI_LOGOFF function call + its response)
                Data = encode_dictionary(self._make_dict(DictionaryType.close))
                self.send(TNS_DATA, Data)
                self._handle_response()
                # Final empty TNS_DATA packet with the EOF data flag, telling
                # the server to fully release the session. Without this the
                # session lingers server-side and accumulates over rapid
                # reconnect cycles. Format: 10-byte header (PacketSize,
                # PacketFlags, Type, Flags, DataFlags=0x0040 EOF).
                if self.sock is not None:
                    self.sock.send(struct.pack(">hhBBh", 10, 0, TNS_DATA, 0, 0x0040))
        except (OSError, Exception):
            # If the server already hung up or our state is out of sync, we
            # still want to release the local socket.
            pass
        finally:
            self.disconnect()

    def _handle_response(self, Acc: tuple | None = None) -> object:
        # Acc seeds the decoder context (Cursor, RowFormat, Rows). The
        # default `(None, None, [])` is right for any response that starts
        # with a DCB (which sets RowFormat for the subsequent RXDs). FETCH
        # responses skip the DCB and need the prior RowFormat passed in.
        from oracle.tns import decode_packet
        if Acc is None:
            Acc = (None, None, [])
        # Iterative TNS_MARKER passthrough — keep replying to markers
        # until a real TNS_DATA arrives. (Was recursive; the recursion
        # depth could in principle grow if the server sent many markers
        # in a row, and EOF crashed unpacking `recv() → False`.)
        while True:
            Received = self.recv(b"", b"")
            if Received is False:
                raise Exception("Connection closed while awaiting response")
            (Type, Packet) = Received
            match Type:
                case t if t == TNS_DATA:
                    return decode_packet(Packet, Acc, self.field_version)
                case t if t == TNS_MARKER:
                    logger.debug("response: marker")
                    self.send(TNS_MARKER, b"\x01\x00\x02")
                    continue
                case _:
                    raise Exception("Unexpected response type", Type)

    def send(self, Type: int, Data: bytes | None) -> bool | None:
        # Iterative split-and-send. Was previously recursive, which blew
        # Python's default recursion limit on payloads big enough to
        # cross more than a few SDU boundaries (test_basic crashed with
        # RecursionError on the auth handshake).
        while Data is not None:
            (Packet, Rest) = encode_packet(Type, Data, self.sdu)
            self.sock.send(Packet)
            Data = Rest
        logger.debug("Send OK")
        return True

    def recv(self, Acc: bytes, Data: bytes) -> tuple[int, bytes] | bool:
        # Iterative receive + reassemble. Was previously recursive — for a
        # multi-KiB response (e.g. a LOB content fetch that spans many
        # SDU-sized TCP segments) the recursion depth blew the default
        # Python limit during the auth handshake on some setups.
        while True:
            NetworkData = self.sock.recv(self.sdu)
            if not NetworkData:
                # Peer closed the connection.
                return False
            Acc = Acc + NetworkData
            # Drain as many complete packets as `Acc` already contains
            # before going back to the socket for more bytes. Need at
            # least 8 bytes for a TNS header before assemble_packet can
            # do anything useful.
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
                    # Continuation fragment: Flag=False but a Body was
                    # extracted. Consume the body and keep reading; the
                    # next packet's header is in Rest (may be empty,
                    # in which case the outer loop will read more).
                    Acc = Rest or b""
                    Data = Data + Body
                    continue
                # Not enough bytes yet for a full packet — back to recv.
                break

    def disconnect(self) -> None:
        if self.sock:
            # Half-close (SHUT_WR) flushes our pending writes (including the
            # EOF marker close() just queued) and tells the server we won't
            # send anything else, so it can complete session teardown before
            # the local socket goes away. Without this, the server can hold a
            # half-closed connection long enough that the next connect() trips
            # over Oracle XE's per-second new-connection rate limit (which
            # surfaces on the client as ORA-01013).
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except OSError:
                # The peer may have already closed its side; we still
                # close() the local socket immediately below.
                pass
            self.sock.close()
            self.sock = None
        self.conn_state = CONN_STATE_DISCONNECTED

    def cursor(self):
        # PEP 249 cursor factory.
        from oracle.cursor import Cursor
        return Cursor(self)

    def __enter__(self):
        if self.sock is None:
            self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
