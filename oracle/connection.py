# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

from oracle.crypto import validate
from oracle.tns import assemble_packet
from oracle.tns import decode_token_rpa
from oracle.tns import encode_dictionary
from oracle.tns import encode_packet
from oracle.tns_consts import (
    CONN_STATE_AUTH_NEGOTIATE, CONN_STATE_AUTHENTICATED,
    CONN_STATE_CONNECTED, CONN_STATE_DISCONNECTED, DictionaryType,
    MAX_SEQ_NUM, TNS_ACCEPT, TNS_CONNECT, TNS_DATA, TNS_MARKER,
    TNS_REDIRECT, TNS_REFUSE, TNS_RESEND, TTI_AUTH, TTI_DTY, TTI_PRO,
    TTI_RPA, TTI_SESS, TTI_WRN,
)
import logging
import socket
import struct

logger = logging.getLogger(__name__)

class OracleConnect:
    def __init__(self, host: str = "localhost", port: int = 1521, user: str = "", password: str = "", sid: str = "", service_name: str = "", ssl: object = None, socket_options: object = None, timeout: int = 15000, autocommit: bool = True, fetch: int = 15, role: int = 0, prelim: int = 0, sdu: int = 8192, charset: str = "utf-8", app_name: str = "pyoracle"):
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
        self.cursors: dict[int, int] = {}

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
        return Ctx.wrap_socket(RawSock, server_hostname=Server)

    def handle_login(self) -> int | None:
        (Type, Packet) = self.recv(b"", b"")
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
                return self.handle_login()
            case t if t == TNS_DATA:
                match Packet[0]:
                    case p if p == TTI_PRO:
                        logger.debug("handle_login: recv PRO")
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
                    case _:
                        logger.debug("handle_login: unknown token %s", Packet[0])
                return self.handle_login()
            case t if t == TNS_MARKER:
                logger.debug("handle_login: marker")
                # Respond to marker with same marker pattern
                self.send(TNS_MARKER, b"\x01\x00\x02")
                return self.handle_login()
            case t if t == TNS_REDIRECT:
                logger.debug("handle_login: redirect %s", Packet)
                # FIXME: parse redirect address and reconnect
            case t if t == TNS_REFUSE:
                logger.debug("handle_login: refuse")
                self.disconnect()
                return 1
            case t if t == TNS_RESEND:
                logger.debug("handle_login: resend")
                self.conn_state = CONN_STATE_AUTH_NEGOTIATE
                Data = encode_dictionary(self._make_dict(DictionaryType.login))
                self.send(TNS_CONNECT, Data)
                return self.handle_login()
            case _:
                logger.debug("handle_login: unexpected %s", Type)
                return 1

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

    def execute(self, Query: str, Bind: list | None = None, Def: list | None = None) -> object:
        if Bind is None:
            Bind = []
        if Def is None:
            Def = []
        Type = 'select' if Query.strip().upper().startswith('SELECT') else 'change'
        Auto = 1 if self.autocommit else 0
        QueryDict = {
            'type': Type,
            'auto': Auto,
            'fetch': self.fetch,
            'server_version': self.server_version,
            'cursor': 0,
            'query': Query,
            'bind': Bind,
            'batch': [],
            'def': Def,
        }
        Data = encode_dictionary(self._make_dict(DictionaryType.exec, query=QueryDict))
        self.send(TNS_DATA, Data)
        Result = self._handle_response()
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
                    # actual amount read — we don't decode it. Scan forward
                    # for OER's `04 01 XX 01` signature so we don't leave
                    # unread bytes in the socket and block the next call.
                    Found = -1
                    for I in range(Pos, len(Packet) - 3):
                        if (Packet[I] == TTI_OER and Packet[I + 1] == 0x01
                                and Packet[I + 3] == 0x01):
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
        (Type, Packet) = self.recv(b"", b"")
        match Type:
            case t if t == TNS_DATA:
                return decode_packet(Packet, Acc)
            case t if t == TNS_MARKER:
                logger.debug("response: marker")
                self.send(TNS_MARKER, b"\x01\x00\x02")
                return self._handle_response(Acc)
            case _:
                raise Exception("Unexpected response type", Type)

    def send(self, Type: int, Data: bytes | None) -> bool | None:
        if Data is None:
            logger.debug("Send OK")
            return True
        else:
            (Packet, Rest) = encode_packet(Type, Data, self.sdu)
            self.sock.send(Packet)
            self.send(Type, Rest)

    def recv(self, Acc: bytes, Data: bytes) -> tuple[int, bytes] | bool:
        NetworkData = self.sock.recv(self.sdu)
        (Flag, Type, Body, Rest) = assemble_packet(Acc + NetworkData, self.sdu)
        if Flag is True and Type == TNS_MARKER:
            return (TNS_MARKER, b"")
        elif Flag is True and Rest == b"":
            return (Type, Data + Body)
        elif Flag is True and Rest != b"":
            return self.recv(Rest, Data + Body)
        else:
            return False

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
