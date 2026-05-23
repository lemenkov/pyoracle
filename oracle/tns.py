# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import datetime
from decimal import Decimal
from functools import reduce
from oracle.crypto import o5logon
from oracle.cursor import cursor
from oracle.date import date
from oracle.tns_consts import (
    AL16UTF16_CHARSET, CharsetDict, DEFAULT_HOST, DEFAULT_PORT, DEFAULT_SID,
    DictionaryType, TNS_DATA, TNS_REDIRECT, TTI_ALL8, TTI_AUTH, TTI_BVC,
    TTI_DCB, TTI_DTY, TTI_FETCH, TTI_FOB, TTI_FUN, TTI_IOV, TTI_LOB,
    TTI_LOGOFF, TTI_OAC, TTI_OER, TTI_PFN, TTI_PRO, TTI_RPA, TTI_RXD,
    TTI_RXH, TTI_SESS, TTI_SPFP, TTI_STA, TTI_STRT, TTI_STOP, TTI_UDS,
    TTI_WRN, TNS_TYPE_DATE, TNS_TYPE_NUMBER, TNS_TYPE_REFCURSOR,
    TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPTZ, TNS_TYPE_VARCHAR, UTF8_CHARSET,
)
import logging
import os
import socket
import struct

logger = logging.getLogger(__name__)

def assemble_packet(Data: bytes, Length: int) -> tuple[bool, int | None, bytes | None, bytes | None]:
    (PacketSize, PacketFlags, Type, Flags, Zero) = struct.unpack(">hhBBh", Data[:8])
    if Type == TNS_DATA and Zero == 0:
        BodySize = PacketSize - 10
        Rest = Data[10:]
        if BodySize <= len(Rest):
            if (PacketSize == Length - 37) or (PacketSize == Length - 81):
                return (False, None, Rest[:BodySize], Rest[BodySize:])
            else:
                return (True, TNS_DATA, Rest[:BodySize], Rest[BodySize:])
        else:
            return (False, None, None, None)
    elif Type == TNS_REDIRECT and Zero == 0:
        (Result, Type, PacketBody, Rest) = decode_packet(Data[10:], Length)
        if Result and Type == TNS_DATA and Rest == b"":
            return (True, TNS_REDIRECT, PacketBody, b"")
        else:
            return (False, None, None, None)
    elif Zero == 0:
        BodySize = PacketSize - 8
        Rest = Data[8:]
        if BodySize <= len(Rest):
            return (True, Type, Rest[:BodySize], Rest[BodySize:])
        else:
            return (False, None, None, None)
    else:
        raise Exception("Cannot decode packet", Data, Length)

def decode_packet(Data: bytes, Acc: object) -> object:
    Token = Data[0]
    logger.debug("Token %s", Token)
    match Token:
        case t if t == TTI_BVC:
            return decode_token_bvc(Data, Acc)
        case t if t == TTI_DCB:
            return decode_token_dcb(Data, Acc)
        case t if t == TTI_FOB:  # return
            return (False, 'fob')
        case t if t == TTI_IOV:
            return decode_token_iov(Data, Acc)
        case t if t == TTI_LOB:
            return decode_token_lob(Data, Acc)
        case t if t == TTI_OAC:
            return decode_token_oac(Data, Acc)
        case t if t == TTI_OER:
            return decode_token_oer(Data, Acc)
        case t if t == TTI_RXD:
            return decode_token_rxd(Data, Acc)
        case t if t == TTI_RXH:
            return decode_token_rxh(Data, Acc)
        case t if t == TTI_RPA:
            # In auth flow, RPA is decoded directly via _handle_rpa (which strips
            # the token byte first). The only caller of decode_packet is the SQL
            # response handler, where RPA is a server-side session-state
            # piggyback that precedes the trailing OER — skip it and continue.
            return decode_token_rpa_piggyback(Data, Acc)
        case t if t == TTI_STA:  # tran
            return (True, Acc)
        case t if t == TTI_UDS:
            return decode_token_uds(Data, Acc)
        case t if t == TTI_WRN:
            return decode_token_wrn(Data, Acc)
        case _:
            raise Exception("Can't decode unknown type", Token, Data, Acc)

def decode_token_bvc(Data: bytes, Acc: object) -> tuple:
    # Bit vector identifying columns whose value is REPEATED from the previous
    # row (so the following RXD only carries the columns whose bits are set).
    # NumColumnsSent is variable ub2; bit vector size is derived from the
    # cursor's total column count. Stash the bytes onto Acc so the next RXD
    # can consult them.
    (Cursor, RowFormat, Rows, *_) = Acc
    Rest = Data[1:]
    (_, Rest) = decode_ub4(Rest)
    NumCols = len(RowFormat) if isinstance(RowFormat, list) else 0
    VecLen = (NumCols + 7) // 8
    BitVec = bytes(Rest[:VecLen])
    Rest = Rest[VecLen:]
    return decode_packet(Rest, (Cursor, RowFormat, Rows, BitVec))

def _skip_chunked_bytes(Data: bytes) -> bytes:
    # Mirrors oracledb's skip_bytes: 1-byte length, then either that many raw
    # bytes (length < 254), nothing (length == 255 NULL marker), or a chunked
    # sequence of ub4-prefixed segments terminated by a zero-length segment
    # (length == 254 LONG marker).
    Length = Data[0]
    if Length == 254:
        Rest = Data[1:]
        while True:
            (ChunkLen, Rest) = decode_ub4(Rest)
            if ChunkLen == 0:
                return Rest
            Rest = Rest[ChunkLen:]
    elif Length == 255:
        return Data[1:]
    else:
        return Data[1 + Length:]

def _skip_bytes_with_length(Data: bytes) -> bytes:
    (NumBytes, Rest) = decode_ub4(Data)
    if NumBytes > 0:
        Rest = _skip_chunked_bytes(Rest)
    return Rest

def _read_str_with_length(Data: bytes) -> tuple[bytes, bytes]:
    (NumBytes, Rest) = decode_ub4(Data)
    if NumBytes > 0:
        return decode_dalc(Rest)
    return (b"", Rest)

def decode_token_dcb(Data: bytes, Acc: object) -> tuple:
    # Describe Information block. Layout reverse-engineered against Oracle 11g
    # XE, cross-referenced with python-oracledb's _process_describe_info.
    #
    #   1B   token (TTI_DCB)
    #   ...  describe-info preamble (chunked DALC: cursor uuid + timestamp)
    #   ub4  max row size                              (skip)
    #   ub4  num_columns
    #   1B   reserved (only present when num_columns > 0)
    #   per column (see _decode_dcb_column)
    #   bytes_with_length  current date                (skip)
    #   ub4  dcbflag                                   (skip)
    #   ub4  dcbmdbz                                   (skip)
    #   ub4  dcbmnpr                                   (skip)
    #   ub4  dcbmxpr                                   (skip)
    #   bytes_with_length  dcbqcky                     (skip)
    (Cursor, _, Rows) = Acc
    Rest = Data[1:]
    Rest = _skip_chunked_bytes(Rest)
    (_, Rest) = decode_ub4(Rest)
    (NumCols, Rest) = decode_ub4(Rest)
    if NumCols > 0:
        Rest = Rest[1:]
    Columns = []
    for _ in range(NumCols):
        (Col, Rest) = _decode_dcb_column(Rest)
        Columns.append(Col)
    Rest = _skip_bytes_with_length(Rest)
    for _ in range(4):
        (_, Rest) = decode_ub4(Rest)
    Rest = _skip_bytes_with_length(Rest)
    return decode_packet(Rest, (Cursor, Columns, Rows))

def _decode_dcb_column(Rest: bytes) -> tuple[dict, bytes]:
    # Per-column metadata, 11g layout. Where 12c+ uses sb1 for precision/scale,
    # 11g uses sb1 precision but sb4-style variable encoding for scale (so
    # NUMBER's -127 default arrives as 0x81 0x7f).
    DataType = Rest[0]
    Precision = Rest[2]   # sb1
    Rest = Rest[3:]
    (DataScale, Rest) = decode_ub4(Rest)
    (BufferSize, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)              # max_array_elems
    (_, Rest) = decode_ub4(Rest)              # cont_flags
    (OidLen, Rest) = decode_ub4(Rest)
    if OidLen > 0:
        Rest = _skip_chunked_bytes(Rest)
    (_, Rest) = decode_ub4(Rest)              # version
    (Charset, Rest) = decode_ub4(Rest)        # charset id
    Csfrm = Rest[0]                           # noqa: F841
    Rest = Rest[1:]
    (MaxSize, Rest) = decode_ub4(Rest)
    NullOk = Rest[0]
    Rest = Rest[2:]                           # skip nulls_allowed-byte AND v7 name length
    (ColName, Rest) = _read_str_with_length(Rest)
    (_, Rest) = _read_str_with_length(Rest)   # schema
    (_, Rest) = _read_str_with_length(Rest)   # type name
    (_, Rest) = decode_ub4(Rest)              # column position
    (_, Rest) = decode_ub4(Rest)              # uds flags
    Col = {
        'column_name': ColName,
        'data_type': DataType,
        'data_length': BufferSize,
        'data_scale': DataScale,
        'precision': Precision,
        'max_size': MaxSize,
        'charset': Charset,
        'null_ok': NullOk,
    }
    return (Col, Rest)

def decode_token_iov(Data: bytes, Acc: object) -> tuple:
    # I/O vector for PL/SQL OUT parameters (section 6.5)
    # Indicates direction of each bind variable
    (Cursor, RowFormat, Rows) = Acc
    Rest = Data[1:]  # skip token byte
    (NumBinds, Rest) = decode_ub4(Rest)
    Directions = []
    for _ in range(NumBinds):
        Direction = Rest[0]
        Rest = Rest[1:]
        Directions.append(Direction)
    return decode_packet(Rest, (Cursor, RowFormat, Rows))

def decode_token_lob(Data: bytes, Acc: object) -> tuple:
    # LOB data - FIXME: full LOB handling not yet implemented
    logger.debug("decode_token_lob: not fully implemented")
    return (True, Acc)

def decode_token_net(Data: bytes, Acc: object) -> None:
    pass
def decode_token_oer(Data: bytes, Acc: tuple) -> tuple:
    # OER ("Oracle Error" return-status TTC token; emitted at the end of every
    # server response — success or failure). Unified layout: every field is
    # always present and we walk through them sequentially rather than
    # branching on success-vs-error. The trailing length-prefixed bytes are
    # the human-readable message ("ORA-NNNNN: ...") which the server
    # populates when the error number is non-zero.
    #
    # Field order cross-referenced with python-oracledb's _process_error_info,
    # adjusted for Oracle 11g: the extended ub4 error number + ub8 rowcount
    # that 12c+ adds are not present, so the message DALC comes directly
    # after the batch-error-messages count.
    (Cursor, RowFormat, Rows) = Acc[:3]
    Rest = Data[1:]                                  # consume the OER token
    (CallStatus, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)                     # end-to-end seq#
    # In 11g the "current row number" field doubles as the DML affected-row
    # count: UPDATE/DELETE/INSERT set it to the number of rows touched by
    # the call. 12c+ moved the rowcount to a separate ub8 at the end of the
    # OER, but we don't have that here.
    (RowCount, Rest) = decode_ub4(Rest)
    (ErrCode, Rest) = decode_ub4(Rest)               # ORA-NNNN error number
    (_, Rest) = decode_ub4(Rest)                     # array elem error #1
    (_, Rest) = decode_ub4(Rest)                     # array elem error #2
    (CursorId, Rest) = decode_ub4(Rest)              # current cursor id
    (_, Rest) = decode_ub4(Rest)                     # error position
    Rest = Rest[6:]                                  # 6 single-byte fields:
                                                     #   sql_type, fatal,
                                                     #   flags, user_cursor_opts,
                                                     #   upi_param, warn_flags
    # rowid: ub4 rba, ub2 part_id, ub1 (reserved), ub4 block, ub2 slot
    (_, Rest) = decode_ub4(Rest)                     # rowid.rba
    (_, Rest) = decode_ub4(Rest)                     # rowid.partition_id
    Rest = Rest[1:]                                  # rowid reserved byte
    (_, Rest) = decode_ub4(Rest)                     # rowid.block_num
    (_, Rest) = decode_ub4(Rest)                     # rowid.slot_num
    (_, Rest) = decode_ub4(Rest)                     # os error
    Rest = Rest[2:]                                  # statement #, call #
    (_, Rest) = decode_ub4(Rest)                     # padding (ub2)
    (_, Rest) = decode_ub4(Rest)                     # successful iterations
                                                     #   (always 1 for a
                                                     #   single non-array
                                                     #   execute on 11g — the
                                                     #   real DML rowcount is
                                                     #   the "current row
                                                     #   number" field above)
    Rest = _skip_bytes_with_length(Rest)             # oerrdd (logical rowid)
    # Batch error codes / offsets / messages — three optional arrays. For
    # plain (non-batch) statements all three counts are zero, so the loops
    # never execute. Decoded for completeness.
    (NumBatchErrCodes, Rest) = decode_ub4(Rest)
    if NumBatchErrCodes > 0:
        Rest = Rest[1:]                              # first_byte indicator
        for _ in range(NumBatchErrCodes):
            (_, Rest) = decode_ub4(Rest)
    (NumBatchOffsets, Rest) = decode_ub4(Rest)
    if NumBatchOffsets > 0:
        Rest = Rest[1:]
        for _ in range(NumBatchOffsets):
            (_, Rest) = decode_ub4(Rest)
    (NumBatchMessages, Rest) = decode_ub4(Rest)
    if NumBatchMessages > 0:
        Rest = Rest[1:]
        for _ in range(NumBatchMessages):
            (_, Rest) = decode_ub4(Rest)             # chunk length
            Rest = _skip_bytes_with_length(Rest)     # message bytes
            Rest = Rest[2:]                          # end marker
    # On 11g the trailing message DALC comes right here. 12c+ has two more
    # extended-precision fields (ub4 error num + ub8 rowcount) ahead of it,
    # which would need a capability-version gate we don't surface yet.
    Message = None
    if ErrCode != 0 and Rest:
        try:
            (Bytes, _) = decode_dalc(Rest)
        except IndexError:
            Bytes = None
        if Bytes:
            try:
                Message = bytes(Bytes).decode('utf-8', errors='replace').rstrip()
            except (TypeError, AttributeError):
                Message = None
    RetFormat = (RowCount, RowFormat)
    return (CallStatus, ErrCode, CursorId, RetFormat, Rows, Message)

def decode_token_oac(Data: bytes, Acc: object) -> tuple[int, int, int, int, bytes]:
    (DataType, Flg, Pre) = struct.unpack(">BBB", Data[:3])
    (DataScale, R0) = decode_ub4(Data[3:])
    (MaxDataLength, R1) = decode_ub4(R0)
    (Mal, R2) = decode_ub4(R1)
    (Fl2, R3) = decode_ub4(R2)
    (ToId, R4) = decode_dalc(R3)
    (VSN, R5) = decode_ub4(R4)
    (Charset, R6) = decode_ub4(R5)
    FormOfUse = R6[0]
    (Mxlc, R7) = decode_ub4(R6[1:])
    return (DataType, MaxDataLength, DataScale, Charset, R7)

def decode_token_rpa(Data: bytes, Acc: object) -> tuple:
    (Num, Rest0) = decode_ub4(Data)
    (KVs, Rest1) = decode_kv(Rest0, Num, [])
    SessKey = dict(KVs).get(b'AUTH_SESSKEY')
    Salt = dict(KVs).get(b'AUTH_VFR_DATA')
    DerivedSalt = dict(KVs).get(b'AUTH_PBKDF2_CSK_SALT')
    Resp = dict(KVs).get(b'AUTH_SVR_RESPONSE')
    if Resp:
        Value = dict(KVs).get(b'AUTH_VERSION_NO')
        Ver =  0 if Value is None else int(Value) >> 24
        SessId = dict(KVs).get(b'AUTH_SESSION_ID')
        return (TTI_AUTH, Resp, Ver, SessId)
    else:
        return (TTI_SESS, SessKey, Salt, DerivedSalt)

_KNOWN_TTI_TOKENS = frozenset((TTI_OER, TTI_RXH, TTI_RXD, TTI_RPA, TTI_STA,
                               TTI_IOV, TTI_UDS, TTI_OAC, TTI_LOB, TTI_WRN,
                               TTI_DCB, TTI_FOB, TTI_BVC))

def decode_token_rpa_piggyback(Data: bytes, Acc: tuple) -> object:
    # Walks past a server-side session-state piggyback so the next decode_packet
    # call lands on the real status token (OER). The block layout is opaque
    # enough that empirically what works is: read Num, consume that many
    # ub4-encoded fields, skip trailing alignment zeros, then continue.
    Rest = Data[1:]
    try:
        (Num, Rest) = decode_ub4(Rest)
    except IndexError:
        return (True, Acc)
    for _ in range(max(Num, 0)):
        if not Rest or Rest[0] in _KNOWN_TTI_TOKENS:
            break
        try:
            (_, Rest) = decode_ub4(Rest)
        except IndexError:
            return (True, Acc)
    while Rest and Rest[0] == 0:
        Rest = Rest[1:]
    if Rest:
        return decode_packet(Rest, Acc)
    return (True, Acc)

def decode_token_uds(Data: bytes, Acc: object) -> tuple:
    # User describe information
    # Contains OAC descriptor for a single column
    (Cursor, RowFormat, Rows) = Acc
    (DataType, MaxDataLength, DataScale, Charset, Rest) = decode_token_oac(Data[1:], None)
    NullOk = Rest[0]
    (ColName, Rest) = decode_dalc(Rest[1:])
    (SchemaName, Rest) = decode_dalc(Rest)
    (TypeName, Rest) = decode_dalc(Rest)
    ColPos = Rest[0]
    Rest = Rest[1:]
    Col = {
        'column_name': ColName,
        'data_type': DataType,
        'data_length': MaxDataLength,
        'data_scale': DataScale,
        'charset': Charset,
        'null_ok': NullOk,
        'position': ColPos,
    }
    NewFormat = RowFormat + [Col] if isinstance(RowFormat, list) else [Col]
    return decode_packet(Rest, (Cursor, NewFormat, Rows))

def decode_token_rxd(Data: bytes, Acc: object) -> tuple:
    # Row data (section 6.2). Each column value is a DALC blob whose raw bytes
    # we hand to oracle.types.decode_value, which dispatches on the column's
    # TNS data type from the describe-info block.
    #
    # If a BVC token preceded this RXD, Acc carries a bit vector: a set bit
    # means "this column is in the RXD"; an unset bit means "reuse the
    # previous row's value". The bit vector applies to a single RXD and is
    # cleared from Acc on the way out.
    from oracle.types import decode_value
    (Cursor, RowFormat, Rows, *Extra) = Acc
    BitVec = Extra[0] if Extra else None
    Rest = Data[1:]
    Row = []
    if RowFormat:
        PrevRow = Rows[-1] if Rows else None
        for Idx, Col in enumerate(RowFormat):
            if BitVec is not None and not _bvc_bit_set(BitVec, Idx):
                Row.append(PrevRow[Idx] if PrevRow else None)
                continue
            (Val, Rest) = decode_dalc(Rest)
            Row.append(decode_value(Col, Val))
    return decode_packet(Rest, (Cursor, RowFormat, Rows + [Row]))

def _bvc_bit_set(BitVec: bytes, Idx: int) -> bool:
    Byte = Idx // 8
    Bit = Idx % 8
    if Byte >= len(BitVec):
        return False
    return bool(BitVec[Byte] & (1 << Bit))

def decode_token_rxh(Data: bytes, Acc: object) -> tuple:
    # Row Transfer Header. Fields use Oracle's variable ub1/ub2/ub4 encoding
    # (1-byte length prefix + value bytes), not the fixed 2-byte big-endian
    # layout the older version of this decoder assumed. See python-oracledb's
    # _process_row_header.
    (Cursor, RowFormat, Rows) = Acc
    Rest = Data[2:]                          # skip token + 1B flags
    (_, Rest) = decode_ub4(Rest)             # num requests
    (_, Rest) = decode_ub4(Rest)             # iteration number
    (_, Rest) = decode_ub4(Rest)             # num iters
    (_, Rest) = decode_ub4(Rest)             # buffer length
    (NumBytes, Rest) = decode_ub4(Rest)      # bit vector length
    if NumBytes > 0:
        Rest = Rest[1:]                      # skip repeated length
        Rest = Rest[NumBytes:]               # skip bit vector
    Rest = _skip_bytes_with_length(Rest)     # rxhrid
    return decode_packet(Rest, (Cursor, RowFormat, Rows))

def decode_token_wrn(Data: bytes, Acc: object) -> tuple:
    # Warning message (section 3.1)
    # Skip the warning and continue processing
    logger.debug("decode_token_wrn: warning received")
    Rest = Data[1:]  # skip token byte
    (ErrNum, Rest) = decode_ub4(Rest)
    (RowCount, Rest) = decode_ub4(Rest)
    (RetCode, Rest) = decode_ub4(Rest)
    (WarnFlag, Rest) = decode_ub4(Rest)
    logger.debug("decode_token_wrn: err=%s rows=%s ret=%s warn=%s", ErrNum, RowCount, RetCode, WarnFlag)
    return decode_packet(Rest, Acc)

def encode_packet(Type: int, Data: bytes, Length: int) -> tuple[bytes, bytes | None]:
    if Type == TNS_DATA:
        PacketSize = len(Data) + 10
        BodySize = Length - 10
        if (PacketSize > Length) and (BodySize < len(Data)):
            PacketBody = Data[:BodySize]
            Rest = Data[BodySize:]
            return (struct.pack(">hhBBhBI", PacketSize, 0, Type, 0, 0, 0, 32) + PacketBody, Rest)
        else:
            return (struct.pack(">hhBBhh", PacketSize, 0, Type, 0, 0, 0) + Data, None)
    else:
        PacketSize = len(Data) + 8
        return (struct.pack(">hhBBh", PacketSize, 0, Type, 0, 0) + Data, None)

def encode_dictionary(Dictionary: dict) -> bytes | tuple[bytes, bytes]:
    match Dictionary['type']:
        case DictionaryType.auth:
            return encode_dictionary_auth(Dictionary)
        case DictionaryType.close:
            return encode_dictionary_close(Dictionary)
        case DictionaryType.description:
            return encode_dictionary_description(Dictionary)
        case DictionaryType.dty:
            return encode_dictionary_dty(Dictionary)
        case DictionaryType.exec:
            return encode_dictionary_exec(Dictionary)
        case DictionaryType.fetch:
            return encode_dictionary_fetch(Dictionary)
        case DictionaryType.login:
            return encode_dictionary_login(Dictionary)
        case DictionaryType.pig:
            return encode_dictionary_pig(Dictionary)
        case DictionaryType.pro:
            return encode_dictionary_pro(Dictionary)
        case DictionaryType.sess:
            return encode_dictionary_sess(Dictionary)
        case DictionaryType.spfp:
            return encode_dictionary_spfp(Dictionary)
        case DictionaryType.start:
            return encode_dictionary_start(Dictionary)
        case DictionaryType.stop:
            return encode_dictionary_stop(Dictionary)
        case DictionaryType.tran:
            return encode_dictionary_tran(Dictionary)
        case _:
            raise Exception("unsupported dict type", Dictionary['type'])

##
## Supplementary functions
##

def encode_dictionary_auth(Dictionary: dict) -> tuple[bytes, bytes]:
    Tseq = Dictionary['seq']
    Sess = Dictionary['auth']['sess']
    Salt = Dictionary['auth']['salt']
    DerivedSalt = Dictionary['auth']['derived_salt']
    User = Dictionary['env']['user'].encode('utf-8')
    Pass = Dictionary['env']['password'].encode('utf-8')
    Role = Dictionary['env'].get('role', 0)
    Prelim = Dictionary['env'].get('prelim', 0)

    LogonMode = encode_sb4( (Role * 32) | (Prelim * 128) | 1 | 256 )
    (AuthPass, AuthSess, SpeedyKey, SpeedyKeyInd, ConnKey) = o5logon(Sess, Salt, DerivedSalt, User, Pass)

    AuthPass = encode_kv(b"AUTH_PASSWORD", AuthPass.hex().upper().encode('utf-8'))

    PBKDF2 = encode_kv(b"AUTH_PBKDF2_SPEEDY_KEY", SpeedyKey) if SpeedyKeyInd != 0 else b""

    AuthSess = encode_kv(b"AUTH_SESSKEY", AuthSess.hex().upper().encode('utf-8'), 1)

    Data = bytes([TTI_FUN, TTI_AUTH, Tseq, 1]) + encode_sb4(len(User)) + LogonMode + bytes([1]) + encode_sb4(2 + SpeedyKeyInd) + bytes([1, 1]) + User + AuthPass + PBKDF2 + AuthSess

    return (Data, ConnKey)

def encode_dictionary_close(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    return bytes([TTI_FUN, TTI_LOGOFF, Tseq])

def encode_dictionary_description(Dictionary: dict) -> bytes:
    logger.debug("encode_dictionary_description: %s", Dictionary)
    Hostname = socket.gethostname().encode('utf-8')
    User = Dictionary['env']['user'].encode('utf-8')
    Host = Dictionary['env'].get('host', DEFAULT_HOST).encode('utf-8')
    Port = str(Dictionary['env'].get('port', DEFAULT_PORT)).encode('utf-8')
    SID = Dictionary['env'].get('sid', DEFAULT_SID).encode('utf-8')
    ServiceName = Dictionary['env'].get('service_name', None)
    AppName = Dictionary['env'].get('app_name', "pyoracle").encode('utf-8')
    SslOpts = Dictionary['env'].get('ssl', None)
    Sn = b"SID=" + SID if ServiceName is None else b"SERVICE_NAME=" + ServiceName.encode('utf-8')
    Proto = b"TCP" if SslOpts is None else b"TCPS"
    return b"(DESCRIPTION=(CONNECT_DATA=(" + Sn + b")(CID=(PROGRAM=" + AppName + b")(HOST=" + Hostname + b")(USER=" + User + b")))(ADDRESS=(PROTOCOL=" + Proto + b")(HOST=" + Host + b")(PORT=" + Port + b")))"

def encode_dictionary_dty(Dictionary: dict) -> bytes:
    logger.debug("encode_dictionary_dty: %s", Dictionary)
    # FIXME put utf8 into charset KV
    Charset = struct.pack("<H", CharsetDict.get(Dictionary['req'], UTF8_CHARSET))
    Wtf0 = bytes([38,6,1,0,0,106,1,1,6,1,1,1,1,1,1,0,41,144,3,7,3,0,1,0,79,1,55,4,0,0,0,0,12,0,0,6,0,1,1])
    Wtf1 = bytes([7,2,0,0,0,0,0,0])
    Wtf2 = bytes(reduce(lambda y, z: y + z, [[]] + [ [x, x, 1, 0] for x in range(1,246)]))
    Wtf3 = bytes([
                2,2,10,0,3,2,10,0,4,2,10,0,5,1,1,0,6,2,10,0,7,2,10,0,9,1,1,0,12,12,10,0,13,0,14,0,15,
                23,1,0,16,0,17,0,18,0,19,0,20,0,21,0,22,0,39,120,1,0,58,0,68,2,10,0,69,0,70,0,74,0,
                6,0,91,2,10,0,94,1,1,0,95,23,1,0,96,96,1,0,97,96,1,0,104,11,1,0,105,0,108,109,1,0,
                110,111,1,0,116,102,1,0,118,0,119,0,121,0,122,0,123,0,136,0,146,146,1,0,147,0,
                152,2,10,0,153,2,10,0,154,2,10,0,155,1,1,0,156,12,10,0,172,2,10,0,209,0,3,0,0
    ])
    # We use the same charset for IN and OUT
    return  bytes([TTI_DTY]) + Charset + Charset + bytes([1]) + Wtf0 + Wtf1 + Wtf2 + Wtf3

def encode_dictionary_exec(Dictionary: dict) -> bytes:
    Type = Dictionary['query']['type']
    Auto = Dictionary['query']['auto']
    Fetch = Dictionary['query']['fetch']
    ServerVersion = b"" if Dictionary['query']['server_version'] == 10 else bytes([0,0,0,0,0])
    Cursor = Dictionary['query']['cursor']
    Query = Dictionary['query']['query'].encode('utf-8')
    QueryLen = len(Query)
    QueryFlag = 1 if QueryLen > 0 else 0
    Bind = Dictionary['query']['bind']
    BindLen = len(Bind)
    BindFlag = 1 if (Cursor == 0) and (BindLen > 0) else 0
    Batch = Dictionary['query']['batch']
    BatchLen = len(Batch)
    Def = Dictionary['query']['def']
    DefLen = len(Def)
    DefFlag = 1 if DefLen > 0 else 0
    Tseq = Dictionary['seq']

    if Cursor == 0:
        (Opt, LMax, Max, All8) = set_opts(Type, 1, BindFlag, BatchLen, Auto)
    elif Type == 'fetch':
        (Opt, LMax, Max, All8) = set_opts(Type, 0, DefInd, 0, Fetch)
    elif Type == 'select':
        (Opt, LMax, Max, All8) = set_opts(Type, 0, 0, 0, Fetch)
    else:
        (Opt, LMax, Max, All8) = set_opts(Type, 0, 0, BatchLen, Auto)

    All8Len = len(All8)
    All8Flag = 1 if All8Len > 0 else 0
    All8s = reduce( lambda x,y: x+y, [ encode_sb4(A) for A in All8])

    if BindLen == DefLen == 0:
        Tokens = b""
    elif DefLen == QueryLen == 0:
        Tokens = encode_tokens_rxd(Bind + Batch, b"")
    elif DefLen == 0:
        Tokens = encode_tokens_rxd(Bind + Batch, encode_tokens_oac(Bind, b""))
    elif BindLen == QueryLen == 0:
        Tokens = encode_tokens_oac(Def, b"")
    else:
        raise Exception("Unhandled tokens combination", Bind, Batch, Def, Query)

    return bytes([TTI_FUN, TTI_ALL8, Tseq]) + encode_sb4(Opt) + encode_sb4(Cursor) + bytes([QueryFlag]) + encode_sb4(QueryLen) + bytes([All8Flag]) + \
            encode_sb4(All8Len) + bytes([0,0]) + encode_sb4(LMax) + encode_sb4(Fetch) + encode_sb4(Max) + bytes([BindFlag]) + encode_sb4(BindLen) + \
            bytes([0,0,0,0,0]) + bytes([DefFlag]) + encode_sb4(DefLen) + bytes([0, 0, 1]) + ServerVersion + Query + All8s + Tokens

def encode_dictionary_fetch(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    Cursor = encode_sb4(Dictionary['cursor'])
    Fetch = encode_sb4(Dictionary['fetch'])
    return bytes([TTI_FUN, TTI_FETCH, Tseq]) + Cursor + Fetch

def encode_dictionary_login(Dictionary: dict) -> bytes:
    PacketVersion = bytes([1,57]) # Packet version number
    LowestCompatVersion = bytes([1,57]) # Lowest compatible version number
    GSO = bytes([0,0]) # Global service options supported
    SDU = struct.pack(">h", Dictionary['sdu']) # SDU
    TDU = bytes([255,255]) # TDU
    ProtocolCharacteristics = bytes([79,152]) # Protocol Characteristics
    MaxUnackPackets = bytes([0,0]) # Max packets before ACK
    Endiannes = struct.pack(">h", 1) # 1 in hardware byte order
    Data = encode_dictionary_description(Dictionary)
    DataLength = struct.pack(">h", len(Data)) # Connect Data length
    CDO = bytes([0,58]) # Connect Data offset
    MaxConnDataRecv = bytes(4) # Max connect data that can be received
    ANO = bytes([132,132]) # ANO disabled
    Padding = bytes(24)
    return PacketVersion + LowestCompatVersion + GSO + SDU + TDU + ProtocolCharacteristics + MaxUnackPackets + Endiannes + DataLength + CDO + MaxConnDataRecv + ANO + Padding + Data

def encode_dictionary_pig(Dictionary: dict) -> bytes:
    Request = Dictionary['req'] # FIXME should it be sb4-encoded?
    Tseq = Dictionary['seq']
    CursorsLen = encode_sb4(len(Dictionary['cursor']))
    Cursors = reduce( lambda x,y: x+y, [ encode_sb4(C) for C in Dictionary['cursor']])
    return bytes([TTI_PFN, Request, Tseq, 1]) + CursorsLen + Cursors

def encode_dictionary_pro(Dictionary: dict) -> bytes:
    return bytes([TTI_PRO, 6, 5, 4, 3, 2, 1, 0]) + b"python" + bytes([0])

def encode_dictionary_sess(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    Hostname = encode_kv(b"AUTH_MACHINE", socket.gethostname().encode('utf-8'))
    Pid = encode_kv(b"AUTH_PID", str(os.getpid()).encode('utf-8'))
    User = Dictionary['env']['user'].encode('utf-8')
    SID = encode_kv(b"AUTH_SID", Dictionary['env']['user'].encode('utf-8'))
    UserLen = encode_sb4(len(Dictionary['env']['user']))
    Role = Dictionary['env'].get('role', 0)
    Prelim = Dictionary['env'].get('prelim', 0)
    LogonMode = encode_sb4( (Role * 32) | (Prelim * 128) | 1 )
    AppName = encode_kv(b"AUTH_PROGRAM_NM", Dictionary['env'].get('app_name', "pyoracle").encode('utf-8'))

    return bytes([TTI_FUN, TTI_SESS, Tseq, 1]) + UserLen + LogonMode + bytes([1]) + encode_sb4(4) + bytes([1, 1]) + User + AppName + Hostname + Pid + SID

def encode_dictionary_spfp(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    return bytes([TTI_FUN, TTI_SPFP, Tseq, 1, 1, 100, 1, 1, 0, 0, 0, 0, 0])

def encode_dictionary_start(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    Request = encode_sb4(Dictionary['req'])
    return bytes([TTI_FUN, TTI_STRT, Tseq]) + Request + bytes([1])

def encode_dictionary_stop(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    Request = encode_sb4(Dictionary['req'])
    return bytes([TTI_FUN, TTI_STOP, Tseq]) + Request + bytes([1])

def encode_dictionary_tran(Dictionary: dict) -> bytes:
    Request = Dictionary['req']
    Tseq = Dictionary['seq']
    return bytes([TTI_FUN, Request, Tseq])

##
## Decoders/Encoders for base types
##

def set_opts(Type: str, Flag: int, Id: int, Len: int, Param: int) -> tuple[int, int, int, list[int]]:
    P0 = 32768
    P1 = (Id * 8) | (Param * 256)
    P2 = 0
    P3 = 2147483647 # 2^^31-1

    if Type == 'fetch':
        P1 = (Id * 16) | 64
        All8 = set_opts_all8(Flag, Param, 1)
    elif (Type == 'select') and (Flag == 0):
        P1 = (Id * 8) | 64
        All8 = set_opts_all8(Flag, Param, 1)
    elif (Type == 'select') and (Flag == 1):
        P1 = (Id * 8)
        P2 = 4294967295 # 2**32-1
        All8 = set_opts_all8(Flag, 0, 1)
    elif Type == 'change':
        All8 = set_opts_all8(Flag, 1 + Len, 0)
    elif Type == 'return':
        P0 = 1024
        All8 = set_opts_all8(Flag, 1, 0)
    elif Type == 'block':
        P0 = 1024
        P3 = 32760 # (2**15-1)^(2**3-1)
        All8 = set_opts_all8(Flag, 1, 0)
    else:
        raise Exception("Can't set opts", (Type, Flag, Id, Len, Param))

    # FIXME should it be Flag ^ 32 ^ P0 ^ P1 ?
    return (Flag ^ 32 ^ P0 | P1, P2, P3, All8)

def set_opts_all8(Opts: int, Fetch: int, Type: int) -> list[int]:
    return [Opts,Fetch,0,0,0,0,0,Type,0,0,0,0,0]

def decode_ub4(Bytes: bytes) -> tuple[int, bytes]:
    match Bytes[0]:
        case 0:
            return (0, Bytes[1:])
        case 1:
            return (Bytes[1], Bytes[2:])
        case 2:
            (Ret, ) = struct.Struct('>H').unpack(Bytes[1:3])
            return (Ret, Bytes[3:])
        case 3:
            (Ret, ) = struct.Struct('>I').unpack(bytes([0]) + Bytes[1:4])
            return (Ret, Bytes[4:])
        case 4:
            (Ret, ) = struct.Struct('>I').unpack(Bytes[1:5])
            return (Ret, Bytes[5:])
        case _:
            # FIXME so how we suppose to know that this is a signed negative num?
            return (-Bytes[1], Bytes[2:])
#       raise Exception("Can't decode ub4", Bytes)

def encode_sb4(Val: int) -> bytes:
    Bytes = struct.Struct('>I').pack(Val)
    match Val:
        case 0:
            return bytes([0])
        case v if v <= 0xFF:
            return bytes([1, Bytes[3]])
        case v if v <= 0xFFFF:
            return bytes([2, Bytes[2], Bytes[3]])
        case v if v <= 0xFFFFFF:
            return bytes([3, Bytes[1], Bytes[2], Bytes[3]])
        case v if v <= 0xFFFFFFFF:
            return bytes([4, Bytes[0], Bytes[1], Bytes[2], Bytes[3]])
        case _:
            raise Exception("Can't encode value", Val)

def decode_dalc(Bytes: bytes) -> tuple[bytes | list, bytes]:
    if Bytes[0] == 0:
        return ([], Bytes[1:])
    elif Bytes[0] == 254:
        return decode_chr(Bytes)
    # FIXME ub4-prefixed chr
    else:
        Length = Bytes[0]
        return (Bytes[1:Length+1], Bytes[Length+1:])

def decode_chr(Bytes: bytes) -> tuple[bytes, bytes]:
    if Bytes[0] == 254:
        j = 1
        i = Bytes[j]
        Out = b""
        while True:
            Out += Bytes[j+1:i+j+1]
            if Bytes[i+j+1] == 0:
                break
            j = i+j+1
            i = Bytes[j]
        return (Out, Bytes[i+j+1+1:])
    else:
        return (Bytes[1:Bytes[0]+1], Bytes[Bytes[0]+1:])

def encode_chr(String: str | bytes) -> bytes:
    Bytes = String.encode('utf-8') if isinstance(String, str) else String
    Length = len(Bytes)
    if Length > 64:
        Out = b""
        i = 0
        while i < Length - 64:
            Out += bytes([64]) + Bytes[i:i+64]
            i += 64
        return bytes([254]) + Out + bytes([Length - i]) + Bytes[i:] + bytes([0])

    return bytes([Length]) + Bytes

def decode_kv(Data: bytes, Num: int, Acc: list) -> tuple[list, bytes]:
    if Num <= 0 or not Data:
        return (sorted(Acc), Data)
    def decode_to_bin(D):
        if D[0] == 0:
            return (bytes([0]), D[1:])
        else:
            (Size, R) = decode_ub4(D)
            if R[0] == Size:
                return (R[1:1+Size], R[1+Size:])
            elif R[0] == 254:
                return decode_chr(R)
            else:
                # FIXME a there are any other options?
                return decode_chr(R)
    (Key, R0) = decode_to_bin(Data)
    (Val, R1) = decode_to_bin(R0)
    if Val == bytes([0]):
        Val = None
    NewAcc = Acc + [(Key, Val)]
    if not R1:
        return (sorted(NewAcc), R1)
    Skip = R1[0] + 1
    return decode_kv(R1[Skip:], Num - 1, NewAcc)

def encode_kv(Key: bytes, Val: bytes, Padding: int = 0) -> bytes:
    def encode_to_bin(Data):
        Size = len(Data)
        if Size == 0:
            return bytes([0])
        else:
            return encode_sb4(Size) +  bytes([Size]) + Data
    return encode_to_bin(Key) + encode_to_bin(Val) + encode_sb4(Padding)

def encode_tokens_rxd(Tokens: list, Binary: bytes) -> bytes:
    Out = bytes([TTI_RXD])
    for Token in Tokens:
        Out += encode_token_rxd(Token)
    return Binary + Out

def encode_tokens_oac(Tokens: list, Binary: bytes) -> bytes:
    # TODO do we really skip TTI_OAC here?
    #Out = bytes([TTI_OAC])
    Out = b""
    for Token in Tokens:
        Out += encode_token_oac(Token)
    return Binary + Out

def encode_token_rxd(Token: object) -> bytes:
    if Token is None:
        return bytes([0])
    if isinstance(Token, bool):
        # bool is an int subclass; reject explicitly so callers don't get a
        # surprise integer 0/1 when they meant something more specific.
        Bytes = encode_token_num(int(Token))
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, int):
        Bytes = encode_token_num(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, Decimal):
        Bytes = encode_token_decimal(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, (float, complex)):
        Bytes = encode_token_num(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, str):
        return encode_chr(Token)
    if isinstance(Token, (bytes, bytearray)):
        return encode_chr(Token.decode('utf-8').encode('utf-16be'))
    if isinstance(Token, cursor):
        return bytes([1, 0])
    if isinstance(Token, date):
        # Legacy oracle.date.date with has_timestamp / timestamptz flags;
        # keep it on its own path so callers who built one explicitly still
        # get the bytes they expected.
        Bytes = encode_token_date(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, datetime.datetime):
        Bytes = encode_token_datetime(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, datetime.date):
        Bytes = encode_token_datetime(
            datetime.datetime(Token.year, Token.month, Token.day)
        )
        return bytes([len(Bytes)]) + Bytes
    raise Exception("Unknown RXD token", Token)

def encode_token_oac(Token: object) -> bytes:
    if Token is None:
        return encode_token_raw(TNS_TYPE_VARCHAR, 4000, 16, UTF8_CHARSET, 0)
    if isinstance(Token, (int, float, complex, Decimal)):
        return encode_token_raw(TNS_TYPE_NUMBER, 22, 0, 0, 0)
    if isinstance(Token, str):
        return encode_token_raw(TNS_TYPE_VARCHAR, 4000, 16, UTF8_CHARSET, 0)
    if isinstance(Token, (bytes, bytearray)):
        return encode_token_raw(TNS_TYPE_VARCHAR, 4000, 16, AL16UTF16_CHARSET, 0)
    if isinstance(Token, cursor):
        return encode_token_raw(TNS_TYPE_REFCURSOR, 1, 0, UTF8_CHARSET, 0)
    if isinstance(Token, date):
        if Token.has_timestamp and Token.timestamptz:
            return encode_token_raw(TNS_TYPE_TIMESTAMPTZ, 13, 0, 0, 0)
        if Token.has_timestamp:
            return encode_token_raw(TNS_TYPE_TIMESTAMP, 11, 0, 0, 0)
        return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0)
    if isinstance(Token, datetime.datetime):
        if Token.tzinfo is not None:
            return encode_token_raw(TNS_TYPE_TIMESTAMPTZ, 13, 0, 0, 0)
        if Token.microsecond > 0:
            return encode_token_raw(TNS_TYPE_TIMESTAMP, 11, 0, 0, 0)
        return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0)
    if isinstance(Token, datetime.date):
        return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0)
    raise Exception("Unknown OAC token", Token)

def encode_token_decimal(Value: Decimal) -> bytes:
    # The base-100 NUMBER encoder works on int and float; route Decimal through
    # the right one based on whether it has a fractional component. This keeps
    # exact-integer Decimals exact and accepts the usual float lossy path for
    # the rest.
    if Value == Value.to_integral_value():
        return encode_token_num(int(Value))
    return encode_token_num(float(Value))

def encode_token_datetime(DT: datetime.datetime) -> bytes:
    # 7-byte DATE prefix is shared by all three temporal formats. TIMESTAMP
    # appends 4 BE bytes of nanoseconds. TIMESTAMP WITH TIME ZONE normalises
    # the wall clock to UTC, appends nanoseconds, then the offset bias bytes.
    if DT.tzinfo is not None:
        Utc = DT.astimezone(datetime.timezone.utc)
        Base = _encode_date_prefix(Utc)
        Nanos = (DT.microsecond * 1000).to_bytes(4, 'big')
        Offset = DT.utcoffset()
        Total = int(Offset.total_seconds() // 60)
        if Total < 0:
            HH, MM = divmod(-Total, 60)
            HH, MM = -HH, -MM
        else:
            HH, MM = divmod(Total, 60)
        return Base + Nanos + bytes([HH + 20, MM + 60])
    if DT.microsecond > 0:
        return _encode_date_prefix(DT) + (DT.microsecond * 1000).to_bytes(4, 'big')
    return _encode_date_prefix(DT)

def _encode_date_prefix(DT: datetime.datetime) -> bytes:
    return bytes([
        DT.year // 100 + 100, DT.year % 100 + 100,
        DT.month, DT.day,
        DT.hour + 1, DT.minute + 1, DT.second + 1,
    ])

def encode_token_date(Token: date) -> bytes:
    # Retained for any caller that still constructs the legacy oracle.date.date
    # subclass. New code should pass a stdlib datetime.datetime instead.
    if Token.has_timestamp and Token.timestamptz:
        T = Token.set_timestamptz(Token.timestamptz)
        return bytes([T.year // 100 + 100, T.year % 100 + 100, T.month, T.day, T.hour + 1, T.minute + 1, T.second + 1])+ (Token.microsecond * 1000).to_bytes(4, 'big') + bytes([Token.timestamptz // 3600 + 20, 60])
    elif Token.has_timestamp:
        return bytes([Token.year // 100 + 100, Token.year % 100 + 100, Token.month, Token.day, Token.hour + 1, Token.minute + 1, Token.second + 1]) + (Token.microsecond * 1000).to_bytes(4, 'big')
    else:
        return bytes([Token.year // 100 + 100, Token.year % 100 + 100, Token.month, Token.day, Token.hour + 1, Token.minute + 1, Token.second + 1])

def encode_token_num(Token: int | float) -> bytes:
    if Token == 0:
        return bytes([128])
    elif isinstance(Token, int):
        return bytes(lnxfmt(lnxmin(abs(Token),1,[]), Token))
    elif isinstance(Token, float):
        return bytes(lnxfmt(lnxren(abs(Token),0), Token))
    else:
        raise Exception("Unhandled number token", Token)

def encode_token_raw(DataType: int, Length: int, Flag: int, Charset: int, Max: int) -> bytes:
    FormOfUse = 2 if Charset == AL16UTF16_CHARSET else 1
    return bytes([DataType, 3, 0, 0]) + encode_sb4(Length) + bytes([0]) + encode_sb4(Flag) + bytes([0,0]) + encode_sb4(Charset) + bytes([FormOfUse]) + encode_sb4(Max)

##
## Some other specific transformation functions
##

def lnxmin(N: int, I: int, Acc: list[int]) -> list[int]:
    if N // 100 == 0:
        return lnxpak(([I-1] + [N % 100] + Acc)[::-1])
    elif I < 20:
        return lnxmin(N // 100, I+1, [N % 100] + Acc)
    else:
        raise Exception("LnxMin cannot handle this", N, I, Acc)

def lnxpak(List: list[int]) -> list[int]:
    i = 0
    while List[i] == 0:
        i += 1
    return List[: None if i == 0 else i - 1 : -1]

def lnxpak2(List: list[int], I: int) -> list[int]:
    if List == [100] and I == 8:
        return [100-1]
    elif len(List) > 1 and List[0] == 100 and I < 8:
        return lnxpak2([List[1] + 1] + List[2:], I+1)
    else:
        return List

def lnxren(N: float, I: int) -> list[int]:
    if N < 1.0:
        return lnxren(N * 100.0, I-1)
    elif 1.0 <= N and N < 10.0:
        return lnxpak(([I] + lnxren4(N,0,1,[]))[::-1])
    elif 10.0 <= N and N < 100.0:
        return lnxpak(([I] + lnxren4(N,0,0,[]))[::-1])
    else: # N >= 100.0
        return lnxren(N * 0.01, I+1)

def lnxren4(N: float, I: int, J: int, Acc: list[int]) -> list[int]:
    if J == 0 and I == 8 and len(Acc) > 1:
        return lnxpak2([(Acc[0]+5) // 10 * 10] + Acc[1:],1)[::-1]
    elif J == 1 and I == 8 and len(Acc) > 1:
        return lnxpak2([Acc[0] + (Acc[0] // 50)] + Acc[1:],1)[::-1]
    else:
        return lnxren4((N-int(N))*100.0, I+1, J, [int(N)] + Acc)

def lnxfmt(List: list[int], Data: int | float) -> list[int]:
    if Data > 0:
        return [List[0] + 192 + 1] + list(map(lambda x: x + 1, List[1:]))
    elif Data < 0:
        return [(List[0] + 192 + 1) ^ 255] + list(map(lambda x: 101 - x, List[1:])) + [102]
    else:
        raise Exception("LnxFmt cannot handle zeroes", List, Data)
