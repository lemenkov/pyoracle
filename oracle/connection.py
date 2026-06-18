# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

from oracle.crypto import validate
from oracle.tns import assemble_packet
from oracle.tns import decode_token_pro
from oracle.tns import decode_token_rpa
from oracle.tns import encode_dictionary
from oracle.tns import encode_packet
from oracle.tns import exec_oac_signature
from oracle.tns import set_decode_dml_rowcounts
from oracle.tns import (encode_o7_open, encode_o7_parse, encode_o7_describe, encode_o7_exec,
                        encode_o7_close, encode_o7_block, encode_tokens_rxd,
                        decode_fv2_describe,
                        decode_fv2_exec_response, decode_fv2_dml_response,
                        decode_fv2_oer_error, decode_fv2_block_out,
                        encode_o7_lob_getlen,
                        encode_o7_lob_read, decode_fv2_lob_getlen,
                        decode_fv2_lob_chunks, encode_o7_bfile_open,
                        encode_o7_bfile_close, decode_fv2_opened_locator)
from oracle.exceptions import OperationalError
from oracle.tns import (CCAP_FIELD_VERSION, FIELD_VERSION_10_2,
                        FIELD_VERSION_12_1,
                        encode_fast_auth, find_fast_auth_rpa)
from oracle.tns_consts import (
    CONN_STATE_AUTH_NEGOTIATE, CONN_STATE_AUTHENTICATED,
    CONN_STATE_CONNECTED, CONN_STATE_DISCONNECTED, DictionaryType,
    FIELD_VERSION_23_1, FIELD_VERSION_23_4, MAX_SEQ_NUM,
    TNS_ACCEPT, TNS_CONNECT, TNS_DATA, TNS_MARKER,
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
# Cap how many times we'll chase a TNS_REDIRECT during one login, so a
# misconfigured listener that redirects in a loop fails fast instead of
# spinning forever.
_MAX_REDIRECTS = 5

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
    def __init__(self, host: str = "localhost", port: int = 1521, user: str = "", password: str = "", sid: str = "", service_name: str = "", ssl: object = None, socket_options: object = None, timeout: int = 15000, autocommit: bool = True, fetch: int = 15, role: int = 0, prelim: int = 0, sdu: int = 8192, charset: str = "utf-8", app_name: str = "pyoracle", field_version: int = FIELD_VERSION_23_4):
        # field_version is the highest TTC field version pyoracle advertises;
        # the server negotiates it down (min(client, server)). The default is the
        # 23ai max (24), reached via fast-auth (#89) — older servers settle at
        # their own version and take the legacy handshake unchanged.
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
        # Bytes received past a marker packet, held for the next recv() so a
        # coalesced break|reset|error is not lost (#45). Empty between calls.
        self._pending = b""
        # True while a server break/reset handshake is in progress: we answer a
        # server break with exactly ONE reset, then drain the server's terminal
        # reset (and any straggler markers) WITHOUT replying, matching
        # python-oracledb's 2:1 server:client marker ratio. Replying to every
        # marker — the old behaviour — ping-pongs into a reset storm that
        # discards real data (#45). Cleared when a real DATA packet arrives.
        self._in_break = False
        self.conn_key = None
        self.server_version = 0
        self.session_id = None
        # Negotiated TTC field version. Starts at the client's advertised max
        # (the field_version arg; 21.1 by default) and is lowered to the
        # server's during the PRO handshake — min(client, server), see
        # handle_login. Decoders use this to pick version-gated wire formats
        # (issue #27). Against 11g it negotiates back down to 6 (=11.2), so the
        # high default is transparent; pass field_version=FIELD_VERSION_11_2 to
        # force the legacy vector.
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
        # Ordered attribute layout per SQL object type (#115), keyed by
        # (owner, type_name). Populated on demand from ALL_TYPE_ATTRS the first
        # time an object of that type is fetched.
        self._object_type_cache: dict[tuple[str, str], list] = {}

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

    def _apply_socket_timeout(self) -> None:
        # Bound every blocking socket operation (connect / send / recv) by the
        # connection `timeout` (milliseconds). Without this the param was dead
        # and a server that went quiet — e.g. an XE session held by the
        # logon-storm throttle — wedged `recv` forever. A timeout of 0 / None
        # keeps the historical fully-blocking behaviour. The bound is per
        # socket operation, not per query: healthy data keeps each recv short,
        # so it only fires on a genuine stall.
        if self.sock is not None:
            self.sock.settimeout(self.timeout / 1000 if self.timeout else None)

    def _open_transport(self) -> None:
        # Open the TCP (and optional TLS) socket to the current host/port and
        # send the initial CONNECT. Shared by connect() and the TNS_REDIRECT
        # handler, which re-points host/port and re-opens against the address
        # the server handed back.
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._apply_socket_timeout()
        self.sock.connect((self.host, self.port))
        if self.ssl:
            try:
                self.sock = self._wrap_socket_tls(self.sock)
                # The TLS handshake produced a fresh socket object; re-arm it.
                self._apply_socket_timeout()
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

    def connect(self) -> bool:
        self._redirects = 0
        self._open_transport()
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
            if Type != TNS_MARKER:
                # A real packet ends any in-flight break/reset episode (#45).
                self._in_break = False
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
                            if self.field_version > FIELD_VERSION_23_1:
                                # 23ai (#89): the negotiated field version is
                                # >= 18, where the legacy OSESSKEY is rejected
                                # (ORA-03146). Switch to the fast-auth bundle —
                                # the only path to fv >= 18, which is in turn the
                                # prerequisite for column annotations. The PRO
                                # exchange just done is harmlessly repeated inside
                                # the bundle. Only reached when the caller opts in
                                # with field_version >= 18 (default stays 21.1).
                                return self._fast_auth_login()
                            Data = encode_dictionary(self._make_dict(DictionaryType.dty))
                            self.send(TNS_DATA, Data)
                        case p if p == TTI_DTY:
                            logger.debug("handle_login: recv DTY")
                            if self.field_version < FIELD_VERSION_10_2:
                                # Pre-10g (9i, field version 2): O3LOGON thin
                                # auth — TTI_3LOGA fetches the session key (#90).
                                from oracle.tns import encode_o3logon_phase1
                                self._o3_phase = 1
                                self.send(TNS_DATA, encode_o3logon_phase1(
                                    self._next_seq(), self.user.encode('utf-8')))
                            else:
                                Data = encode_dictionary(self._make_dict(DictionaryType.sess))
                                self.send(TNS_DATA, Data)
                        case p if p == TTI_RPA:
                            logger.debug("handle_login: recv RPA")
                            if getattr(self, "_o3_phase", 0) == 1:
                                self._send_o3logon_phase2(Packet)
                                continue
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
                            from oracle.tns import decode_packet, decode_ub4
                            from oracle.exceptions import DatabaseError, from_ora_code
                            if getattr(self, "_o3_phase", 0) == 2:
                                # 9i's OER is shorter than the 11g+ form
                                # decode_token_oer expects (no batch-error
                                # arrays), so decode just the leading fields:
                                # call_status, seq, rowcount, then the ORA code.
                                Rest = Packet[1:]
                                for _ in range(3):
                                    (_, Rest) = decode_ub4(Rest)
                                (ErrCode, _) = decode_ub4(Rest)
                                Message = None
                            else:
                                # Via decode_packet so the negotiated field
                                # version is published for the version-gated
                                # OER decode.
                                Result = decode_packet(Packet, (None, None, []),
                                                       self.field_version)
                                ErrCode = Result[1]
                                Message = Result[5] if len(Result) > 5 else None
                            if ErrCode and ErrCode not in (0, 1403):
                                raise from_ora_code(ErrCode)(
                                    Message or f"ORA-{ErrCode:05d}", code=ErrCode)
                            if getattr(self, "_o3_phase", 0) == 2:
                                # O3LOGON phase two answered with a clean OER =
                                # authenticated (#90). No AUTH_SVR_RESPONSE to
                                # validate on the pre-10g path.
                                self.conn_state = CONN_STATE_AUTHENTICATED
                                logger.debug("handle_login: authenticated (O3LOGON)")
                                return 0
                            raise DatabaseError("authentication failed")
                        case _:
                            logger.debug("handle_login: unknown token %s", Packet[0])
                    continue
                case t if t == TNS_MARKER:
                    logger.debug("handle_login: marker")
                    # Single reset per break episode, then drain (#45) — never
                    # echo every marker, which storms the line.
                    if not self._in_break:
                        self.send(TNS_MARKER, b"\x01\x00\x02")
                        self._in_break = True
                    continue
                case t if t == TNS_REDIRECT:
                    from oracle.tns import parse_redirect_address
                    (NewHost, NewPort) = parse_redirect_address(Packet)
                    if NewHost is None:
                        logger.debug("handle_login: unparseable redirect %r",
                                     Packet)
                        return 1
                    self._redirects = getattr(self, "_redirects", 0) + 1
                    if self._redirects > _MAX_REDIRECTS:
                        raise OperationalError(
                            f"too many TNS redirects (> {_MAX_REDIRECTS})")
                    logger.debug("handle_login: redirect -> %s:%s",
                                 NewHost, NewPort)
                    # Reconnect to the address the server handed back and start
                    # the handshake over against it.
                    self.host, self.port = NewHost, NewPort
                    self.disconnect()
                    self._open_transport()
                    continue
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

    def _fast_auth_login(self) -> int | None:
        # 23ai fast-auth (#89): send PRO, DTY and OSESSKEY bundled in one
        # FAST_AUTH packet (the field version was already negotiated to >= 18 in
        # _negotiate_capabilities). The server replies with the three responses
        # concatenated; pick out the auth-challenge RPA and hand it to the normal
        # phase-two path (_handle_rpa), which finishes the login exactly as the
        # legacy handshake does.
        Pro = encode_dictionary(self._make_dict(DictionaryType.pro))
        Dty = encode_dictionary(self._make_dict(DictionaryType.dty))
        Sess = encode_dictionary(self._make_dict(DictionaryType.sess))
        self.send(TNS_DATA, encode_fast_auth(Pro, Dty, Sess))
        Received = self._next_data_packet()
        if Received is False:
            logger.debug("fast_auth: connection closed by peer")
            return 1
        (Type, Packet) = Received
        Off = find_fast_auth_rpa(Packet) if Type == TNS_DATA else -1
        if Off < 0:
            logger.error("fast_auth: no auth challenge in bundled reply "
                         "(type=%s, head=%r)", Type, Packet[:16])
            raise OperationalError("fast-auth handshake failed")
        return self._handle_rpa(Packet[Off + 1:])

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

    def _send_o3logon_phase2(self, Packet: bytes) -> None:
        # O3LOGON phase two (#90): the TTI_3LOGA response RPA carries the
        # session key as a positional length-prefixed ASCII-hex string
        # (TTI_RPA, ub1 count, ub1 length, <hex>). Decrypt it with the account's
        # DES verifier to recover the plaintext session key, DES-encrypt the
        # zero-padded password under it, and send TTI_3LOGON with AUTH_PASSWORD
        # = upper-hex(cipher) + decimal(pad count).
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
        self.send(TNS_DATA, encode_o3logon_phase2(
            self._next_seq(), UserB, PwdField))

    def execute(self, Query: str, Bind: list | None = None, Def: list | None = None,
                Batch: list | None = None, BatchErrors: bool = False,
                ArrayDmlRowCounts: bool = False) -> object:
        if Bind is None:
            Bind = []
        if Def is None:
            Def = []
        if Batch is None:
            Batch = []
        Head = Query.strip().upper()
        # Oracle 9i (field version < 10g) speaks the old TTI_ALL7 query dialect,
        # not the TTI_ALL8 the rest of execute() builds. Route SELECTs through
        # the dedicated four-call fv2 path (#97, PROTOCOL.md §19).
        if self.field_version < FIELD_VERSION_10_2:
            if Head.startswith('SELECT'):
                return self._drain_cursor(self._execute_fv2(Query, Bind))
            # Anonymous PL/SQL blocks (BEGIN/DECLARE) over the fv2 block path
            # (#102, IN binds only) — they need their own ALL7 option word, not
            # the DML one (which the server rejects with ORA-00600).
            if Head.startswith('BEGIN') or Head.startswith('DECLARE'):
                return self._execute_fv2_block(Query, Bind)
            # DML (INSERT/UPDATE/DELETE) over the fv2 TTI_ALL7 path (#101).
            return self._execute_fv2_dml(Query, Bind)
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
            'batcherrors': BatchErrors,
            'arraydmlrowcounts': ArrayDmlRowCounts,
        }
        Data = encode_dictionary(self._make_dict(DictionaryType.exec, query=QueryDict))
        self.send(TNS_DATA, Data)
        # Arm row-count extraction for this response only (#18).
        set_decode_dml_rowcounts(ArrayDmlRowCounts)
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
        if (CacheKey is not None and Type == 'change' and not Def
                and isinstance(Result, tuple) and len(Result) >= 3
                and isinstance(Result[2], int) and Result[2] > 0
                and Result[1] in (0, 1403)):
            # CacheKey is None whenever the cache is disabled for this execute
            # (12c+, where a cached re-execute fails) — gating the write on it
            # too keeps a stray {None: cursor_id} entry out of the cache (#80).
            CursorId = Result[2]
            # LRU bump: move the entry to the end on hit; evict the oldest
            # entry when the cache fills up.
            self._cursor_cache.pop(CacheKey, None)
            self._cursor_cache[CacheKey] = CursorId
            while len(self._cursor_cache) > self._cursor_cache_max:
                Oldest = next(iter(self._cursor_cache))
                self._cursor_cache.pop(Oldest, None)
        return self._drain_cursor(Result)

    def _fv2_raise_for_error(self, Packet: bytes) -> None:
        # Raise the server's error if `Packet` is a 9i OER carrying a real ORA
        # code (not success/end-of-fetch). Lets a parse-time failure surface as
        # its true code + message instead of a downstream desync (#102).
        (ErrCode, Message) = decode_fv2_oer_error(Packet)
        if ErrCode and ErrCode not in (0, 1403):
            from oracle.exceptions import from_ora_code
            raise from_ora_code(ErrCode)(
                Message or f"ORA-{ErrCode:05d}", code=ErrCode)

    def _execute_fv2(self, Query: str, Bind: list | None = None) -> object:
        # Oracle 9i (field version 2) SELECT: the four-call TTI_ALL7 sequence
        # (PROTOCOL.md §19) — parse, describe columns, execute+fetch, close.
        # Returns the same tuple shape as a normal execute response so the
        # cursor/_drain_cursor machinery is unchanged.
        self.send(TNS_DATA, encode_o7_open(0))       # allocate a server cursor
        self._next_data_packet()                     # OOPEN RPA (cursor id)
        self.send(TNS_DATA, encode_o7_parse(0, Query, Bind))
        Resp = self._next_data_packet()              # parse RPA ack — or an OER
        if Resp is not False:                        # surface a parse error
            self._fv2_raise_for_error(Resp[1])       # (e.g. ORA-00942)
        self.send(TNS_DATA, encode_o7_describe(0))
        Resp = self._next_data_packet()
        if Resp is False:
            raise Exception("Connection closed during 9i describe")
        (_, Packet) = Resp
        Columns = decode_fv2_describe(Packet)
        # CLOB (112) / BLOB (113) are read by the two-call TTI_LOBOPS GETLEN +
        # READ, BFILE (114) by FILE_OPEN/READ/CLOSE — all resolved before the
        # cursor close, see _resolve_fv2_lobs. (LONG / LONG RAW are handled inline
        # in decode_fv2_exec_response.) (#102)
        # Execute, then fetch in batches: each batch is the SAME exec+fetch
        # TTI_ALL7 re-sent; the server continues the cursor and signals the end
        # with ORA-01403 (#99). A batch with no rows also terminates the loop so
        # a malformed response can't spin forever.
        AllRows: list = []
        ErrCode = 0
        while True:
            self.send(TNS_DATA, encode_o7_exec(0, Columns))
            Resp = self._next_data_packet()
            if Resp is False:
                raise Exception("Connection closed during 9i fetch")
            (_, Packet) = Resp
            (Rows, ErrCode) = decode_fv2_exec_response(Packet, Columns)
            AllRows.extend(Rows)
            if ErrCode == 1403 or not Rows:
                break
        # Resolve any LOB cells while the cursor is still open — JDBC reads the
        # locators before the close, and so do we (#102). decode_fv2_exec_response
        # left LOB objects in the rows; replace each with its content.
        self._resolve_fv2_lobs(AllRows, Columns)
        self.send(TNS_DATA, encode_o7_close(0))
        self._next_data_packet()                     # close STA
        if ErrCode and ErrCode not in (0, 1403):
            from oracle.exceptions import from_ora_code
            raise from_ora_code(ErrCode)(f"ORA-{ErrCode:05d}", code=ErrCode)
        # (call_status, ora_code, cursor_id, (rowcount, row_format), rows, ...)
        # call_status 0 + ora_code 0 => _drain_cursor won't issue TTI_FETCHes.
        return (0, 0, 0, (len(AllRows), Columns), AllRows, None, None, [], None)

    def _lob_read_fv2(self, Locator: bytes) -> bytes:
        # 9i (fv2) LOB content read: the two-call TTI_LOBOPS GETLEN + READ
        # (PROTOCOL.md §19.5). GETLEN returns the length; READ pulls that many
        # chars/bytes. Returns raw bytes (CLOB decoding happens in the caller
        # with the column charset). An empty LOB (amount 0) reads nothing.
        self.send(TNS_DATA, encode_o7_lob_getlen(0, Locator))
        Resp = self._next_data_packet(b"", b"")
        if Resp is False:
            raise Exception("Connection closed during 9i LOB GETLEN")
        Amount = decode_fv2_lob_getlen(Resp[1])
        if Amount <= 0:
            return b""
        self.send(TNS_DATA, encode_o7_lob_read(0, Locator, Amount))
        return self._read_fv2_lob_content()

    def _bfile_read_fv2(self, Locator: bytes) -> bytes:
        # 9i (fv2) BFILE read: FILE_OPEN → GETLEN → READ → FILE_CLOSE over
        # TTI_LOBOPS (PROTOCOL §19.8). FILE_OPEN returns an *updated* locator
        # (open flag set); GETLEN/READ/CLOSE must use that one. Returns the file
        # bytes. The FILE_CLOSE runs in a finally so an opened file is always
        # closed even if the read fails.
        self.send(TNS_DATA, encode_o7_bfile_open(0, Locator))
        Resp = self._next_data_packet(b"", b"")
        if Resp is False:
            raise Exception("Connection closed during 9i BFILE FILE_OPEN")
        self._fv2_raise_for_error(Resp[1])           # e.g. ORA-22285
        Opened = decode_fv2_opened_locator(Resp[1])
        if Opened is None:
            raise Exception("Unexpected 9i BFILE FILE_OPEN reply",
                            Resp[1][:8].hex())
        try:
            self.send(TNS_DATA, encode_o7_lob_getlen(0, Opened))
            Resp = self._next_data_packet(b"", b"")
            if Resp is False:
                raise Exception("Connection closed during 9i BFILE GETLEN")
            Amount = decode_fv2_lob_getlen(Resp[1])
            if Amount <= 0:
                return b""
            self.send(TNS_DATA, encode_o7_lob_read(0, Opened, Amount))
            return self._read_fv2_lob_content()
        finally:
            self.send(TNS_DATA, encode_o7_bfile_close(0, Opened))
            self._next_data_packet(b"", b"")         # drain FILE_CLOSE RPA + OER

    def _read_fv2_lob_content(self) -> bytes:
        # Read the content of a 9i (fv2) TTI_LOBOPS READ reply by accumulating
        # packets and re-parsing with decode_fv2_lob_chunks until it reports the
        # zero-length terminator. The fv2 reply carries no OER call-status, so
        # that terminator (not an OER) is the stop signal. (#102)
        Data = b""
        while True:
            Received = self._next_data_packet(b"", b"")
            if Received is False:
                raise Exception("Connection closed during 9i LOB READ")
            Data += Received[1]
            (Content, Complete) = decode_fv2_lob_chunks(Data)
            if Complete:
                return Content

    def _resolve_fv2_lobs(self, Rows: list, Columns: list) -> None:
        # Replace LOB objects left by decode_fv2_exec_response with their
        # content, in place, by round-tripping each locator (#102). Done while
        # the 9i cursor is still open.
        from oracle.lob import LOB
        from oracle.types import decode_fv2_lob
        for Row in Rows:
            for I, Val in enumerate(Row):
                if isinstance(Val, LOB):
                    if Val.data_type == 114:        # BFILE: open / read / close
                        Content = self._bfile_read_fv2(Val.raw)
                    else:                           # CLOB / BLOB: GETLEN + READ
                        Content = self._lob_read_fv2(Val.raw)
                    Row[I] = decode_fv2_lob(Columns[I].get('data_type'),
                                            Content,
                                            Columns[I].get('charset') or 0)

    def _execute_fv2_dml(self, Query: str, Bind: list | None = None) -> object:
        # Oracle 9i DML over TTI_ALL7 (#101): OOPEN, then a single parse that
        # also executes the statement (option 02 80 21) — no describe/fetch. The
        # affected-row count comes back in the response OER. Commit explicitly
        # when autocommit is on (9i's parse doesn't carry an autocommit bit).
        self.send(TNS_DATA, encode_o7_open(0))
        self._next_data_packet()                     # OOPEN RPA
        self.send(TNS_DATA, encode_o7_parse(0, Query, Bind))
        Resp = self._next_data_packet()
        if Resp is False:
            raise Exception("Connection closed during 9i DML")
        (_, Packet) = Resp
        self._fv2_raise_for_error(Packet)            # e.g. ORA-00942 / constraint
        (RowCount, ErrCode) = decode_fv2_dml_response(Packet)
        self.send(TNS_DATA, encode_o7_close(0))
        self._next_data_packet()                     # close STA
        if ErrCode and ErrCode not in (0, 1403):
            from oracle.exceptions import from_ora_code
            raise from_ora_code(ErrCode)(f"ORA-{ErrCode:05d}", code=ErrCode)
        if self.autocommit:
            self.commit()
        return (0, 0, 0, (RowCount, None), [], None, None, [], None)

    def _execute_fv2_block(self, Query: str, Bind: list | None = None) -> object:
        # Anonymous PL/SQL block over the fv2 TTI_ALL7 block path (#102,
        # PROTOCOL §19.6 / §19.7). OOPEN, then encode_o7_block parse-executes the
        # block carrying an OAC per bind (no inline values — blocks don't use the
        # DML 0x8000 inline-values mode). The server then replies with a bind
        # prompt; the client sends the INPUT values (IN + IN OUT binds, in
        # position order) as a standalone RXD, and the reply carries any OUT /
        # IN OUT return values (an RXD before the RPA + OER). A pure-OUT block
        # packs the prompt, the return values and the status into one packet and
        # expects no input; a no-bind block returns the RPA + OER directly. OUT
        # values are handed back as an {out_positions, out_values} record the
        # cursor's _assign_out_binds decodes into the Var objects.
        from oracle.datatypes import Var
        Bind = Bind or []
        # IN + IN OUT binds carry an input value to send; every Var is an OUT
        # (its returned value comes back). IN OUT = a Var with has_value set.
        InputValues = [(B._value if isinstance(B, Var) else B)
                       for B in Bind
                       if not isinstance(B, Var) or B.has_value]
        OutPositions = [I for I, B in enumerate(Bind) if isinstance(B, Var)]
        self.send(TNS_DATA, encode_o7_open(0))
        self._next_data_packet()                     # OOPEN RPA
        self.send(TNS_DATA, encode_o7_block(0, Query, Bind))
        Resp = self._next_data_packet()
        if Resp is False:
            raise Exception("Connection closed during 9i PL/SQL block")
        (_, Packet) = Resp
        if InputValues:
            # `Packet` is the bind prompt (or an OER on a compile error). Send
            # the input values; the reply carries OUT values + RPA + OER.
            self._fv2_raise_for_error(Packet)
            self.send(TNS_DATA, encode_tokens_rxd(InputValues, b""))
            Resp = self._next_data_packet()
            if Resp is False:
                raise Exception("Connection closed during 9i PL/SQL bind send")
            (_, Packet) = Resp
        self._fv2_raise_for_error(Packet)            # runtime error (ORA-06512 …)
        (OutValues, RowCount, ErrCode) = decode_fv2_block_out(
            Packet, len(OutPositions))
        self.send(TNS_DATA, encode_o7_close(0))
        self._next_data_packet()                     # close STA
        if ErrCode and ErrCode not in (0, 1403):
            from oracle.exceptions import from_ora_code
            raise from_ora_code(ErrCode)(f"ORA-{ErrCode:05d}", code=ErrCode)
        if self.autocommit:
            self.commit()
        if OutPositions:
            Record = {'out_positions': OutPositions, 'out_values': OutValues}
            return (0, 0, 0, (None, None), [Record], None, None, [], None)
        return (0, 0, 0, (RowCount, None), [], None, None, [], None)

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

    def lob_read(self, Locator: bytes, DataType: int,
                 prefixed: bool = False) -> str | bytes:
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
                                                  locator=Locator,
                                                  locator_prefixed=prefixed))
        self.send(TNS_DATA, Data)
        Content = self._read_lob_response()
        if DataType == TNS_TYPE_CLOB:
            return Content.decode('utf-16-be', errors='replace')
        return Content

    def _object_type_layout(self, schema: str | None, name: str | None) -> list:
        # Ordered attribute layout for a SQL object type, used to walk an object
        # image into a DbObject (#115). Fetched from the data dictionary
        # (ALL_TYPE_ATTRS) and cached per connection keyed by (owner, name).
        # A type the session can't see (no row) yields an empty layout, so the
        # object decodes to a DbObject with no attributes rather than raising.
        if not schema or not name:
            return []
        Key = (schema, name)
        Cached = self._object_type_cache.get(Key)
        if Cached is not None:
            return Cached
        from oracle.dbobject import type_name_to_tns
        SQL = ("SELECT attr_name, attr_type_name, length, precision, scale "
               "FROM all_type_attrs "
               "WHERE owner = :1 AND type_name = :2 "
               "ORDER BY attr_no")
        Result = self.execute(SQL, Bind=[schema, name])
        Rows = Result[4] if len(Result) > 4 and Result[4] else []
        Layout = []
        for Row in Rows:
            AttrName = Row[0]
            TypeName = Row[1]
            Layout.append({
                'name': AttrName,
                'type_name': TypeName,
                'data_type': type_name_to_tns(TypeName),
                'charset': None,
            })
        self._object_type_cache[Key] = Layout
        return Layout

    def create_temp_lob(self, is_blob: bool = False) -> bytes:
        # Create a session-duration temporary LOB on the server (TTI_LOBOPS
        # CREATE_TEMP, #91) and return its locator. Used to bind a large LOB
        # value into a PL/SQL locator parameter, where the streamed-LONG bind
        # path fails with ORA-01460. 12c+ only — 11g rejects CREATE_TEMP — so
        # callers gate on field_version. The response is a single TTI_RPA token
        # carrying the new locator: 0x08, ub2 length, then the locator bytes.
        from oracle.tns_consts import TTI_RPA
        Data = encode_dictionary(self._make_dict(DictionaryType.lobops,
                                                 create_temp=True,
                                                 is_blob=is_blob))
        self.send(TNS_DATA, Data)
        Received = self._next_data_packet(b"", b"")
        if Received is False:
            raise Exception("Connection closed during CREATE_TEMP")
        (_, Packet) = Received
        if not Packet or Packet[0] != TTI_RPA:
            raise Exception("Unexpected CREATE_TEMP response",
                            Packet[:8].hex() if Packet else None)
        LocLen = (Packet[1] << 8) | Packet[2]
        return Packet[3:3 + LocLen]

    def write_temp_lob(self, Locator: bytes, Data: bytes,
                       is_blob: bool = False) -> None:
        # Write `Data` into a (temporary) LOB via TTI_LOBOPS WRITE (op 0x0040,
        # #91), starting at offset 1. CLOB content goes on the wire as UTF-16BE;
        # BLOB content is raw bytes. The server answers with TTI_RPA (updated
        # locator + bytes written) followed by TTI_OER (call status); we walk to
        # the OER and raise on a real error. 12c+ only (paired with
        # create_temp_lob). The encoder chunks payloads > 0xFC bytes itself.
        from oracle.tns_consts import TNS_LOB_OP_WRITE
        Payload = Data if is_blob else Data.encode('utf-16-be')
        Dict = self._make_dict(DictionaryType.lobops, locator=Locator,
                               data=Payload, operation=TNS_LOB_OP_WRITE)
        self.send(TNS_DATA, encode_dictionary(Dict))
        self._confirm_lobops()

    def _confirm_lobops(self) -> None:
        # Drain a TTI_LOBOPS response that carries no content (WRITE / temp /
        # BFILE open-close ops): receive the RPA + OER packet and raise on a
        # non-zero ORA error.
        Received = self._next_data_packet(b"", b"")
        if Received is False:
            raise Exception("Connection closed during LOBOPS")
        self._raise_lobops_error(Received[1])

    def _raise_lobops_error(self, Packet: bytes) -> None:
        # Decode the OER trailing a content-free LOBOPS response and raise on a
        # real ORA error. decode_lobops_oer skips the RPA's binary locator and
        # matches the OER regardless of call status (which is 5, not 1,
        # immediately after a PL/SQL execute — the case that desynced the temp
        # LOB write following a temp-LOB-bind exec).
        from oracle.tns import decode_lobops_oer
        from oracle.exceptions import from_ora_code
        (ErrCode, Message) = decode_lobops_oer(Packet, self.field_version)
        if ErrCode and ErrCode not in (0, 1403):
            raise from_ora_code(ErrCode)(
                Message or f"ORA-{ErrCode:05d}", code=ErrCode)

    def bfile_read_native(self, Locator: bytes) -> bytes:
        # Read a BFILE natively over TTI_LOBOPS (#46): FILE_OPEN -> READ ->
        # FILE_CLOSE, no PL/SQL helper. FILE_OPEN returns an *updated* locator
        # in its RPA (with the open flag set); READ / CLOSE must use that one —
        # a READ against the original locator returns empty bytes (the symptom
        # that originally blocked native BFILE support). The locator goes on the
        # wire ub2-length-prefixed (locator_prefixed), as for temp LOBs.
        from oracle.tns_consts import (TTI_RPA, TNS_LOB_OP_FILE_OPEN,
                                       TNS_LOB_OP_FILE_CLOSE)
        # A BFILE locator as fetched (LOB.raw) leads with its own ub2
        # inner-length; the encoder re-adds that prefix, so pass the body. The
        # FILE_OPEN response RPA already hands back the body form.
        if len(Locator) >= 2 and ((Locator[0] << 8) | Locator[1]) == len(Locator) - 2:
            Locator = Locator[2:]
        self.send(TNS_DATA, encode_dictionary(self._make_dict(
            DictionaryType.lobops, locator=Locator,
            operation=TNS_LOB_OP_FILE_OPEN)))
        Received = self._next_data_packet(b"", b"")
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
            self.send(TNS_DATA, encode_dictionary(self._make_dict(
                DictionaryType.lobops, locator=Opened, locator_prefixed=True)))
            Content = self._read_lob_response()
        finally:
            self.send(TNS_DATA, encode_dictionary(self._make_dict(
                DictionaryType.lobops, locator=Opened,
                operation=TNS_LOB_OP_FILE_CLOSE)))
            self._confirm_lobops()
        return Content

    def bfile_read(self, directory_name: str, file_name: str) -> bytes:
        # Read a BFILE by directory object + filename. Resolves the locator with
        # a SELECT BFILENAME and reads it natively over TTI_LOBOPS (#46) — the
        # cursor's LOB auto-resolve runs bfile_read_native under the hood. (This
        # used to install a PL/SQL DBMS_LOB helper; the native FILE_OPEN/READ/
        # FILE_CLOSE sequence removed that, along with its CREATE PROCEDURE
        # privilege requirement and schema side effects.)
        Cur = self.cursor()
        Cur.execute("SELECT BFILENAME(:d, :f) FROM DUAL",
                    {"d": directory_name, "f": file_name})
        return Cur.fetchone()[0]

    def _read_lob_response(self) -> bytes:
        # Walk the LOBOPS response packets, accumulating LOB_DATA chunks
        # until we hit the trailing OER. A LOBOPS response packet on 11g
        # carries: TTI_LOB (content) + TTI_RPA (updated locator) + TTI_OER
        # (call status). We pull the content out of the LOB chunk(s) and
        # use OER as the stop signal; everything between LOB and OER is
        # RPA-shaped metadata we don't need.
        from oracle.tns_consts import TTI_LOB, TTI_OER
        Buffer = b""
        while True:
            # Same break/reset-aware receive as the main response path (#45):
            # a LOB read that gets cancelled mid-stream must complete the reset
            # handshake instead of echoing markers and dropping content.
            Received = self._next_data_packet(b"", b"")
            if Received is False:
                raise Exception("Connection closed during LOBOPS response")
            (Type, Packet) = Received
            if Type != TNS_DATA:
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

    def changepassword(self, old_password: str, new_password: str) -> None:
        """Change the connected user's password (#21, oracledb-compatible).

        Sends a single TTI_AUTH password-change call on the live session,
        reusing the session key established at login (no re-handshake). On
        success the connection stays usable and its stored password is updated
        so a later reconnect / pool checkout uses the new one. A wrong
        `old_password` raises ORA-01017; a rejected new password (policy /
        verifier) raises e.g. ORA-28003.
        """
        from oracle.exceptions import InterfaceError, from_ora_code
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
        self.send(TNS_DATA, Data)
        Result = self._handle_response()
        ErrCode = Result[1] if isinstance(Result, tuple) and len(Result) > 1 else 0
        if ErrCode and ErrCode not in (0, 1403):
            Message = Result[5] if len(Result) > 5 else None
            raise from_ora_code(ErrCode)(
                Message or f"ORA-{ErrCode:05d}", code=ErrCode)
        self.password = new_password

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
        # Receive the next DATA packet, transparently completing any server
        # break/reset handshake (#45). _next_data_packet sends a single reset
        # per break episode and drains the rest, so a cancelled/errored call
        # no longer storms the line or discards the trailing error/result.
        Received = self._next_data_packet(b"", b"")
        if Received is False:
            raise Exception("Connection closed while awaiting response")
        (Type, Packet) = Received
        if Type == TNS_DATA:
            return decode_packet(Packet, Acc, self.field_version)
        raise Exception("Unexpected response type", Type)

    def send(self, Type: int, Data: bytes | None) -> bool | None:
        # Iterative split-and-send. Was previously recursive, which blew
        # Python's default recursion limit on payloads big enough to
        # cross more than a few SDU boundaries (test_basic crashed with
        # RecursionError on the auth handshake).
        while Data is not None:
            (Packet, Rest) = encode_packet(Type, Data, self.sdu)
            try:
                self.sock.send(Packet)
            except TimeoutError as exc:
                raise self._timeout_error("write") from exc
            Data = Rest
        logger.debug("Send OK")
        return True

    def _timeout_error(self, op: str) -> OperationalError:
        return OperationalError(
            f"network {op} timed out after {self.timeout} ms "
            f"(connection timeout)")

    def recv(self, Acc: bytes, Data: bytes) -> tuple[int, bytes] | bool:
        # Iterative receive + reassemble. Was previously recursive — for a
        # multi-KiB response (e.g. a LOB content fetch that spans many
        # SDU-sized TCP segments) the recursion depth blew the default
        # Python limit during the auth handshake on some setups.
        #
        # Seed from any bytes preserved past the previous marker (#45): a
        # server break/reset can arrive coalesced with the trailing error/LOB
        # DATA in one TCP read, so on a marker we keep `Rest` in self._pending
        # instead of dropping it, and drain it here before touching the socket.
        Acc = self._pending + Acc
        self._pending = b""
        while True:
            # Drain as many complete packets as `Acc` already contains
            # before going back to the socket for more bytes. Need at
            # least 8 bytes for a TNS header before assemble_packet can
            # do anything useful.
            while len(Acc) >= 8:
                (Flag, Type, Body, Rest) = assemble_packet(Acc, self.sdu)
                if Flag is True and Type == TNS_MARKER:
                    # Preserve everything after the marker (the coalesced
                    # reset / error DATA) for the next recv() rather than
                    # discarding it — the break state machine in
                    # _next_data_packet drives the reset handshake.
                    self._pending = Rest
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
            try:
                NetworkData = self.sock.recv(self.sdu)
            except TimeoutError as exc:
                raise self._timeout_error("read") from exc
            if not NetworkData:
                # Peer closed the connection.
                return False
            Acc = Acc + NetworkData

    def _next_data_packet(self, Acc: bytes = b"", Data: bytes = b"") \
            -> tuple[int, bytes] | bool:
        # Receive the next TNS_DATA packet, transparently completing a server
        # break/reset handshake (#45). The 21c server cancels an errored or
        # interrupted call by sending a break marker (01 00 01) followed by a
        # reset marker (01 00 02) and then the inline error/result DATA. A
        # correct client answers with exactly ONE reset and drains the rest;
        # python-oracledb does 2 server markers : 1 client reset. Replying to
        # every marker storms the line and discards real data. self._in_break
        # latches across recv() calls so we send at most one reset per break
        # episode, and is cleared when a real DATA packet arrives.
        while True:
            Received = self.recv(Acc, Data)
            if Received is False:
                return False
            (Type, Packet) = Received
            if Type != TNS_MARKER:
                self._in_break = False
                return (Type, Packet)
            if not self._in_break:
                self.send(TNS_MARKER, b"\x01\x00\x02")
                self._in_break = True
            # else: drain the server's terminal reset (and any straggler
            # markers) silently — do NOT reply, or the server replies again.

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
