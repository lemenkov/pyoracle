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

        # FIXME upgrade to SSL if required
        self.sock.connect((self.host, self.port))
        Data = encode_dictionary(self._make_dict(DictionaryType.login))

        self.send(TNS_CONNECT, Data)
        self.handle_login()

        return True

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
        return self._handle_response()

    def fetch_more(self, CursorId: int, Rows: int | None = None) -> object:
        if Rows is None:
            Rows = self.fetch
        Data = encode_dictionary(self._make_dict(DictionaryType.fetch, cursor=CursorId, fetch=Rows))
        self.send(TNS_DATA, Data)
        return self._handle_response()

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
        if self.conn_state == CONN_STATE_DISCONNECTED:
            return
        if self.conn_state == CONN_STATE_AUTHENTICATED:
            if not self.autocommit:
                self.rollback()
            # Close all cached cursors via piggyback
            if self.cursors:
                from oracle.tns_consts import TTI_OCCA
                Data = encode_dictionary(self._make_dict(DictionaryType.pig, req=TTI_OCCA, cursor=list(self.cursors.values())))
                self.send(TNS_DATA, Data)
            # Logoff
            Data = encode_dictionary(self._make_dict(DictionaryType.close))
            self.send(TNS_DATA, Data)
            self._handle_response()
        self.disconnect()

    def _handle_response(self) -> object:
        from oracle.tns import decode_packet
        (Type, Packet) = self.recv(b"", b"")
        match Type:
            case t if t == TNS_DATA:
                return decode_packet(Packet, (None, None, []))
            case t if t == TNS_MARKER:
                logger.debug("response: marker")
                self.send(TNS_MARKER, b"\x01\x00\x02")
                return self._handle_response()
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
