# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import datetime
from decimal import Decimal
from functools import reduce
from oracle.crypto import o5logon
from oracle.cursor import cursor
from oracle.datatypes import BinaryDouble, BinaryFloat, IntervalYM, Var
from oracle.date import date
from oracle.tns_consts import (
    AL16UTF16_CHARSET, CharsetDict, DEFAULT_HOST, DEFAULT_PORT, DEFAULT_SID,
    DictionaryType, TNS_DATA, TNS_REDIRECT, TTI_ALL8, TTI_AUTH, TTI_BVC,
    TTI_DCB, TTI_DTY, TTI_FETCH, TTI_FOB, TTI_FUN, TTI_IOV, TTI_LOB,
    TTI_LOGOFF, TTI_OAC, TTI_OER, TTI_PFN, TTI_PRO, TTI_RPA, TTI_RXD,
    TTI_RXH, TTI_SESS, TTI_SPFP, TTI_STA, TTI_STRT, TTI_STOP, TTI_UDS,
    TTI_WRN, TNS_BIND_DIR_INPUT, TNS_LOB_OP_READ, TNS_TYPE_BDOUBLE, TNS_TYPE_BFILE,
    TNS_TYPE_BFLOAT, TNS_TYPE_BLOB, TNS_TYPE_CLOB, TNS_TYPE_DATE,
    TNS_TYPE_INTERVALDS, TNS_TYPE_INTERVALYM, TNS_TYPE_LONG, TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER, TNS_TYPE_RAW, TNS_TYPE_REFCURSOR, TNS_TYPE_RID,
    TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPTZ, TNS_TYPE_UROWID, TNS_TYPE_VARCHAR,
    TTI_LOBOPS,
    UTF8_CHARSET,
)
import logging
import math
import os
import socket
import struct

logger = logging.getLogger(__name__)

def assemble_packet(Data: bytes, Length: int) -> tuple[bool, int | None, bytes | None, bytes | None]:
    (PacketSize, PacketFlags, Type, Flags, Zero) = struct.unpack(">HhBBh", Data[:8])
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
    (Cursor, _, Rows) = Acc[:3]
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
    # I/O vector for an anonymous PL/SQL block's binds (section 6.5). Layout
    # cross-referenced with python-oracledb's _process_io_vector and verified
    # against XE 11g captures.
    #
    #   1B   token (TTI_IOV)
    #   ub1  flag                                   (skip)
    #   ub2  num_requests  \  num_binds =
    #   ub4  num_iters     /    num_iters*256 + num_requests
    #   ub4  num iters this time                    (skip)
    #   ub2  uac buffer length                      (skip)
    #   ub2  fast-fetch bit vector length + bytes   (skip)
    #   ub2  rowid length + bytes                   (skip)
    #   per bind: ub1 direction (16=OUT, 32=IN, 48=IN OUT)
    #
    # When any bind is OUT / IN OUT the server then sends the returned values
    # as a TTI_RXD row: each value is a DALC blob followed by a 1-byte
    # indicator. We keep the raw value bytes here (decoding needs the bind's
    # type, which only the cursor knows) and surface them through the Rows
    # accumulator as an {'out_*': ...} record the cursor maps back onto its
    # bind variables.
    (Cursor, RowFormat, Rows) = Acc[:3]
    Binds = Acc[3] if len(Acc) > 3 else None
    (Directions, OutValues, Rest) = _read_iov(Data, Binds)
    OutPositions = [I for I, D in enumerate(Directions)
                    if D != TNS_BIND_DIR_INPUT]
    if OutPositions:
        Rows = Rows + [{'out_positions': OutPositions,
                        'out_values': OutValues,
                        'directions': Directions}]
    return decode_packet(Rest, (Cursor, RowFormat, Rows))

def _is_refcursor_bind(Bind: object) -> bool:
    if isinstance(Bind, Var):
        return Bind.dbtype.tns_type == TNS_TYPE_REFCURSOR
    return isinstance(Bind, cursor)

def _read_iov(Data: bytes, Binds: list | None = None
              ) -> tuple[list[int], list[object], bytes]:
    # Parse a TTI_IOV body starting at the token byte. Returns the per-bind
    # direction codes, the OUT/IN-OUT values (in OUT-bind order), and the
    # unconsumed tail (the RPA / OER that follow). See decode_token_iov.
    #
    # A scalar OUT value is raw DALC bytes (the cursor decodes it by the bind's
    # type). A REF CURSOR OUT value is instead an inline describe + cursor id;
    # it is returned as a {'_refcursor': True, 'cursor_id', 'row_format'} record
    # the cursor turns into a nested Cursor. Detecting which is which needs the
    # bind list, threaded in via the decode Acc.
    Rest = Data[1:]                              # consume IOV token
    Rest = Rest[1:]                              # skip flag (ub1)
    (NumRequests, Rest) = decode_ub4(Rest)
    (NumIters, Rest) = decode_ub4(Rest)
    NumBinds = NumIters * 256 + NumRequests
    (_, Rest) = decode_ub4(Rest)                 # num iters this time
    (_, Rest) = decode_ub4(Rest)                 # uac buffer length
    (BvLen, Rest) = decode_ub4(Rest)             # fast-fetch bit vector
    if BvLen > 0:
        Rest = Rest[BvLen:]
    (RidLen, Rest) = decode_ub4(Rest)            # rowid
    if RidLen > 0:
        Rest = Rest[RidLen:]
    Directions = [Rest[I] for I in range(NumBinds)]
    Rest = Rest[NumBinds:]
    HasOut = any(D != TNS_BIND_DIR_INPUT for D in Directions)
    OutValues = []
    if HasOut and Rest and Rest[0] == TTI_RXD:
        Rest = Rest[1:]                          # consume RXD token
        for Idx, D in enumerate(Directions):
            if D == TNS_BIND_DIR_INPUT:
                continue
            Bind = Binds[Idx] if Binds and Idx < len(Binds) else None
            if _is_refcursor_bind(Bind):
                (Value, Rest) = _read_refcursor_out(Rest)
                OutValues.append(Value)
            else:
                (Val, Rest) = decode_dalc(Rest)
                Rest = Rest[1:]                  # per-value indicator byte
                OutValues.append(b"" if Val == [] else bytes(Val))
    return (Directions, OutValues, Rest)

def _read_refcursor_out(Rest: bytes) -> tuple[dict, bytes]:
    # A REF CURSOR OUT value: a 1-byte length, then an inline describe (max row
    # size, num columns, the same per-column metadata as a DCB), then the
    # nested cursor id (ub2) and a 1-byte indicator. Mirrors oracledb's
    # _create_cursor_from_describe; byte layout verified against XE 11g.
    Rest = Rest[1:]                              # skip_ub1 (length)
    (_, Rest) = decode_ub4(Rest)                 # max row size
    (NumCols, Rest) = decode_ub4(Rest)
    if NumCols > 0:
        Rest = Rest[1:]                          # reserved byte
    Columns = []
    for _ in range(NumCols):
        (Col, Rest) = _decode_dcb_column(Rest)
        Columns.append(Col)
    Rest = _skip_bytes_with_length(Rest)         # current date
    for _ in range(4):                           # dcbflag / mdbz / mnpr / mxpr
        (_, Rest) = decode_ub4(Rest)
    Rest = _skip_bytes_with_length(Rest)         # dcbqcky
    (CursorId, Rest) = decode_ub4(Rest)
    Rest = Rest[1:]                              # per-value indicator byte
    return ({'_refcursor': True, 'cursor_id': CursorId,
             'row_format': Columns}, Rest)

def decode_token_lob(Data: bytes, Acc: object) -> tuple:
    # Defensive no-op for a TTI_LOB token seen in the general decode path. Real
    # LOB content is read by the dedicated _read_lob_response loop (see
    # lob_read), which walks TTI_LOB / RPA / OER itself — it doesn't route
    # through here.
    logger.debug("decode_token_lob: ignored (handled in _read_lob_response)")
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
    # rowid of the (last) row the statement touched — same physical-rowid
    # layout as a ROWID column (see _read_rowid_column): data object number,
    # relative file number, an unused byte, block number, slot number.
    (RowidObj, Rest) = decode_ub4(Rest)              # data object number
    (RowidFile, Rest) = decode_ub4(Rest)             # relative file number
    Rest = Rest[1:]                                  # rowid reserved byte
    (RowidBlock, Rest) = decode_ub4(Rest)            # block number
    (RowidSlot, Rest) = decode_ub4(Rest)             # slot number
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
    # Render the touched-row rowid (block 0 is the file header — never a data
    # row — so treat it as "no rowid", e.g. SELECT / DDL).
    Rowid = None
    if RowidBlock:
        from oracle.types import rowid_to_string
        Rowid = rowid_to_string(RowidObj, RowidFile, RowidBlock, RowidSlot)
    RetFormat = (RowCount, RowFormat)
    return (CallStatus, ErrCode, CursorId, RetFormat, Rows, Message, Rowid)

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
        # Keep the full packed version number; the connection decodes the major
        # release (>> 24) for its protocol gate and the full dotted string for
        # the `version` property.
        Ver = 0 if Value is None else int(Value)
        SessId = dict(KVs).get(b'AUTH_SESSION_ID')
        return (TTI_AUTH, Resp, Ver, SessId)
    else:
        return (TTI_SESS, SessKey, Salt, DerivedSalt)

def decode_token_pro(Data: bytes) -> dict:
    """Decode a TTI_PRO (protocol negotiation) server response.

    Returns the server's TTC protocol version byte, banner, and the two
    length-prefixed capability arrays (compile-time TNS_CCAP_* and runtime
    TNS_RCAP_*). `Data` starts at the message-type byte (== TTI_PRO). The
    field version the server advertises is `compile_caps[CCAP_FIELD_VERSION]`;
    the connection negotiates the effective version as min(client, server).
    Layout mirrors python-oracledb's protocol.pyx (docs/PROTOCOL.md §4.1)."""
    Off = 1                                    # skip the message-type byte
    ServerVersion = Data[Off]
    Off += 2                                   # version byte + a trailing zero
    End = Data.index(0, Off)                   # NUL-terminated banner
    Banner = Data[Off:End]
    Off = End + 1
    Off += 2                                   # charset_id (ub2 LE)
    Off += 1                                   # server flags
    NumElem = int.from_bytes(Data[Off:Off + 2], "little")
    Off += 2 + NumElem * 5                     # skip the charset-element array
    FdoLen = int.from_bytes(Data[Off:Off + 2], "big")
    Off += 2 + FdoLen                          # skip the FDO blob
    CcLen = Data[Off]; Off += 1
    CompileCaps = Data[Off:Off + CcLen]; Off += CcLen
    RcLen = Data[Off]; Off += 1
    RuntimeCaps = Data[Off:Off + RcLen]
    return {
        'server_version': ServerVersion,
        'banner': Banner,
        'compile_caps': CompileCaps,
        'runtime_caps': RuntimeCaps,
    }


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
    (Cursor, RowFormat, Rows) = Acc[:3]
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

_LOB_DATA_TYPES = frozenset((TNS_TYPE_CLOB, TNS_TYPE_BLOB, TNS_TYPE_BFILE))
_ROWID_DATA_TYPES = frozenset((TNS_TYPE_RID,))
_UROWID_DATA_TYPES = frozenset((TNS_TYPE_UROWID,))
_LONG_DATA_TYPES = frozenset((TNS_TYPE_LONG, TNS_TYPE_LONGRAW))

def decode_token_rxd(Data: bytes, Acc: object) -> tuple:
    # Row data (section 6.2). Each column value is normally a DALC blob whose
    # raw bytes we hand to oracle.types.decode_value, which dispatches on the
    # column's TNS data type from the describe-info block.
    #
    # LOB columns are special: instead of a single DALC they carry a small
    # length-prefixed locator block (`_read_lob_column`). The locator and
    # any inline content stay opaque for now — surfaced to the caller as an
    # oracle.lob.LOB object — until the LOB-content extraction work lands.
    #
    # If a BVC token preceded this RXD, Acc carries a bit vector: a set bit
    # means "this column is in the RXD"; an unset bit means "reuse the
    # previous row's value". The bit vector applies to a single RXD and is
    # cleared from Acc on the way out.
    from oracle.types import decode_value
    from oracle.lob import LOB
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
            DataType = Col.get('data_type')
            if DataType in _LOB_DATA_TYPES:
                (Locator, Rest) = _read_lob_column(Rest)
                Row.append(None if Locator is None else LOB(DataType, Locator))
                continue
            if DataType in _ROWID_DATA_TYPES:
                (Val, Rest) = _read_rowid_column(Rest)
                Row.append(Val)
                continue
            if DataType in _UROWID_DATA_TYPES:
                (Val, Rest) = _read_urowid_column(Rest)
                Row.append(Val)
                continue
            if DataType in _LONG_DATA_TYPES:
                (Val, Rest) = _read_long_column(Rest)
                Row.append(decode_value(Col, Val))
                continue
            (Val, Rest) = decode_dalc(Rest)
            Row.append(decode_value(Col, Val))
    return decode_packet(Rest, (Cursor, RowFormat, Rows + [Row]))

def _read_lob_column(Rest: bytes) -> tuple[bytes | None, bytes]:
    # LOB column layout in RXD (Oracle 11g):
    #
    #   ub1 0x00              → NULL LOB; total column size = 1 byte.
    #   ub4 num_bytes         → otherwise the leading variable-length integer
    #                           gives the size of the locator block that
    #                           follows.
    #   ub1 size_repeat       → echoes num_bytes as a single byte (skipped).
    #   num_bytes raw bytes   → the LOB locator + inline content section.
    #                           This is exactly what the server expects back
    #                           in TTI_LOBOPS — verified by diffing against
    #                           sqlplus's LOBOPS request locator bytes.
    #
    # Total LOB column size = num_bytes + 3. Confirmed against captured XE
    # 11g responses for NULL / EMPTY_CLOB / 'x' / 10-char and 23-char CLOBs.
    if not Rest:
        return (None, Rest)
    if Rest[0] == 0x00:
        return (None, Rest[1:])
    (NumBytes, Body) = decode_ub4(Rest)
    if NumBytes <= 0 or len(Body) < NumBytes + 1:
        # Defensive: malformed or unexpected layout. Surface what we have
        # rather than overrunning the buffer.
        return (bytes(Body), b"")
    # Skip the 1-byte size echo (Body[0]) and take the next num_bytes bytes.
    # That gives the locator format the server emitted *and* the format it
    # expects on input for TTI_LOBOPS round-trips.
    Locator = bytes(Body[1:1 + NumBytes])
    Tail = Body[1 + NumBytes:]
    return (Locator, Tail)

def _read_rowid_column(Rest: bytes) -> tuple[str | None, bytes]:
    # ROWID (TNS type 11) in RXD: a 1-byte present indicator (the size the
    # server reserved; 0 / 0xff means NULL) followed by a structured physical
    # rowid -- data object (ub4), relative file (ub2), an unused ub1, block
    # (ub4) and slot (ub2). Mirrors oracledb's read_rowid; the byte counts and
    # the base64 rendering were verified against ROWIDTOCHAR on a live XE row.
    from oracle.types import rowid_to_string
    if not Rest:
        return (None, Rest)
    Indicator = Rest[0]
    Rest = Rest[1:]
    if Indicator in (0, 0xFF):
        return (None, Rest)
    (Obj, Rest) = decode_ub4(Rest)
    (File, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)             # unused ub1
    (Block, Rest) = decode_ub4(Rest)
    (Slot, Rest) = decode_ub4(Rest)
    return (rowid_to_string(Obj, File, Block, Slot), Rest)

def _read_urowid_column(Rest: bytes) -> tuple[str | None, bytes]:
    # UROWID (universal/logical rowid, TNS type 208 -- e.g. an index-organized
    # table's rowid). Same RXD framing as a LOB column: ub4 num_bytes, a 1-byte
    # length echo, then num_bytes raw rowid bytes (a leading type tag + the
    # rowid body). Rendered as the "*"-prefixed base64 form. Verified against a
    # live XE IOT row vs the SELECT ROWID text.
    from oracle.types import urowid_to_string
    if not Rest:
        return (None, Rest)
    (NumBytes, Rest) = decode_ub4(Rest)
    if NumBytes <= 0:
        return (None, Rest)
    Rest = Rest[1:]                              # 1-byte length echo
    Value = bytes(Rest[:NumBytes])
    Rest = Rest[NumBytes:]
    return (urowid_to_string(Value), Rest)

def _read_long_column(Rest: bytes) -> tuple[bytes | None, bytes]:
    # LONG / LONG RAW in RXD: a value followed by two trailing ub4 indicators
    # (the actual/return lengths; 0 / 0 for an ordinary value). The value is
    #   0x00            -> NULL, no body
    #   0xfe            -> chunked: repeated [ub1 len][bytes] until a 0 length
    #   else            -> ub1 length + that many bytes
    # The two ub4 reads after the value keep the stream aligned regardless of
    # NULL. Structure cross-referenced with python-oracledb's column read;
    # verified against live XE captures (NULL, single-chunk, 700-byte multi-
    # chunk, and LONG-not-last rows).
    if not Rest:
        return (None, Rest)
    Marker = Rest[0]
    if Marker == 0x00:
        Val = None
        Rest = Rest[1:]
    elif Marker == 0xFE:
        Rest = Rest[1:]
        Chunks = b""
        while Rest:
            ChunkLen = Rest[0]
            Rest = Rest[1:]
            if ChunkLen == 0:
                break
            Chunks += bytes(Rest[:ChunkLen])
            Rest = Rest[ChunkLen:]
        Val = Chunks
    else:
        Val = bytes(Rest[1:1 + Marker])
        Rest = Rest[1 + Marker:]
    (_, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)
    return (Val, Rest)

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
    (Cursor, RowFormat, Rows) = Acc[:3]
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
            return (struct.pack(">HhBBhBI", PacketSize, 0, Type, 0, 0, 0, 32) + PacketBody, Rest)
        else:
            # PacketSize is a uint16 on the wire — use `>H` so requests
            # in the 32 KiB..64 KiB range (e.g. mid-size LOB inserts done
            # via a single PL/SQL block with multiple chunk binds) don't
            # overflow signed-short range and crash with `struct.error`.
            return (struct.pack(">HhBBhh", PacketSize, 0, Type, 0, 0, 0) + Data, None)
    else:
        PacketSize = len(Data) + 8
        return (struct.pack(">HhBBh", PacketSize, 0, Type, 0, 0) + Data, None)

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
        case DictionaryType.lobops:
            return encode_dictionary_lobops(Dictionary)
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

    # AUTH_PBKDF2_SPEEDY_KEY is hex-encoded like AUTH_PASSWORD / AUTH_SESSKEY
    # (the server expects the hex string, not the raw bytes — sending raw gives
    # ORA-03146 "invalid buffer length for TTC field"). 256-bit scheme only.
    PBKDF2 = encode_kv(b"AUTH_PBKDF2_SPEEDY_KEY", SpeedyKey.hex().upper().encode('utf-8')) if SpeedyKeyInd != 0 else b""

    AuthSess = encode_kv(b"AUTH_SESSKEY", AuthSess.hex().upper().encode('utf-8'), 1)

    # 12c+ length-prefixes the username (write_bytes_with_length), same as the
    # OSESSKEY phase; 11g sends it raw (read via the UserLen field). Sending the
    # raw form to 21c makes it read the first username byte as a length and
    # desync — surfaces as ORA-03120 (two-task conversion: integer overflow).
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    UserField = bytes([len(User)]) + User if FieldVersion >= FIELD_VERSION_12_1 else User

    Data = bytes([TTI_FUN, TTI_AUTH, Tseq, 1]) + encode_sb4(len(User)) + LogonMode + bytes([1]) + encode_sb4(2 + SpeedyKeyInd) + bytes([1, 1]) + UserField + AuthPass + PBKDF2 + AuthSess

    return (Data, ConnKey)

def encode_dictionary_close(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    return bytes([TTI_FUN, TTI_LOGOFF, Tseq])

def _redacted(Dictionary: dict) -> dict:
    # Return a copy safe to log: the password (carried in the env dict so the
    # encoders can use it) is masked so it never reaches a debug log in clear
    # text.
    Env = Dictionary.get('env')
    if not isinstance(Env, dict) or 'password' not in Env:
        return Dictionary
    Safe = dict(Dictionary)
    # Build the masked env without ever copying the secret values: replace
    # them with '***' in the comprehension rather than spreading Env (which
    # would route the real password through the dict and into the log).
    _SECRET = ('password', 'new_password')
    Safe['env'] = {k: ('***' if k in _SECRET else v) for k, v in Env.items()}
    return Safe

def encode_dictionary_description(Dictionary: dict) -> bytes:
    logger.debug("encode_dictionary_description: %s", _redacted(Dictionary))
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

# ---------------------------------------------------------------------------
# TTC capability vectors (carried in the TTI_DTY / DATA_TYPES message)
# ---------------------------------------------------------------------------
# The handshake advertises two length-prefixed capability arrays: compile-time
# (TNS_CCAP_*) and runtime (TNS_RCAP_*). Each is just a byte array where a
# given index is a named feature slot. Index meanings and the field-version
# values below were reverse-engineered from python-oracledb (constants.pxi /
# data_types.pyx) and verified against live 11g and 21c captures (issue #27,
# docs/PROTOCOL.md §4.2). We model them as {index: value} so the vector reads
# as a feature list instead of an opaque blob, and so a single field-version
# knob can switch pyoracle between the 11g-era and 12c+-era wire contracts.

# Compile-time capability indices (into the compile_caps array):
CCAP_SQL_VERSION = 0
CCAP_LOGON_TYPES = 4
CCAP_FEATURE_BACKPORT = 5
CCAP_FIELD_VERSION = 7          # gates the auth verifier + version-gated formats
CCAP_SERVER_DEFINE_CONV = 8
CCAP_DEQUEUE_WITH_SELECTOR = 9
CCAP_TTC1 = 15
CCAP_OCI1 = 16
CCAP_TDS_VERSION = 17
CCAP_RPC_VERSION = 18
CCAP_RPC_SIG = 19
CCAP_DBF_VERSION = 21
CCAP_LOB = 23
CCAP_TTC2 = 26
CCAP_UB2_DTY = 27              # 2-byte data-type ids (12c+)
CCAP_OCI2 = 31
CCAP_CLIENT_FN = 34
CCAP_OCI3 = 35
CCAP_TTC3 = 37
CCAP_SESS_SIGNATURE_VERSION = 39
CCAP_TTC4 = 40
CCAP_LOB2 = 42
CCAP_TTC5 = 44
CCAP_FEATURE_BACKPORT2 = 45
CCAP_VECTOR_FEATURES = 52

# TNS_CCAP_FIELD_VERSION_* values (the byte written at CCAP_FIELD_VERSION):
FIELD_VERSION_11_2 = 6
FIELD_VERSION_12_1 = 7
FIELD_VERSION_12_2 = 8
FIELD_VERSION_19_1 = 12
FIELD_VERSION_21_1 = 16
FIELD_VERSION_23_1 = 17

# Runtime capability indices + the flag bits we set:
RCAP_COMPAT = 0
RCAP_TTC = 6
RCAP_COMPAT_81 = 2
RCAP_TTC_ZERO_COPY = 0x01
RCAP_TTC_32K = 0x04

# Per-field-version capability vectors as {index: byte}; unset indices are 0.
# 11.2 reproduces pyoracle's historical 11g vector byte-for-byte (asserted by
# tests/test_tns_encode.py); 21.1 matches python-oracledb 4.0.1 against 21c.
_COMPILE_CAPS = {
    FIELD_VERSION_11_2: (38, {
        CCAP_SQL_VERSION: 6,            # TNS_CCAP_SQL_VERSION_MAX
        CCAP_LOGON_TYPES: 0x6a,         # O7LOGON | O5LOGON | O5LOGON_NP | 0x40
        CCAP_FEATURE_BACKPORT: 1,
        CCAP_FIELD_VERSION: FIELD_VERSION_11_2,
        CCAP_SERVER_DEFINE_CONV: 1,
        CCAP_DEQUEUE_WITH_SELECTOR: 1,
        CCAP_TTC1: 0x29,
        CCAP_OCI1: 0x90,
        CCAP_TDS_VERSION: 3,            # TNS_CCAP_TDS_VERSION_MAX
        CCAP_RPC_VERSION: 7,            # TNS_CCAP_RPC_VERSION_MAX
        CCAP_RPC_SIG: 3,               # TNS_CCAP_RPC_SIG_VALUE
        CCAP_DBF_VERSION: 1,           # TNS_CCAP_DBF_VERSION_MAX
        CCAP_LOB: 0x4f,
        CCAP_TTC2: 4,
        CCAP_OCI2: 12,
        CCAP_CLIENT_FN: 6,
        CCAP_TTC3: 1,
        # Slots oracledb leaves 0 but pyoracle's original 11g reference client
        # set; not in oracledb's named map. Kept verbatim for byte-parity.
        1: 1, 6: 1, 10: 1, 11: 1, 12: 1, 13: 1, 24: 1, 25: 0x37, 36: 1,
    }),
    FIELD_VERSION_21_1: (53, {
        CCAP_SQL_VERSION: 6,
        CCAP_LOGON_TYPES: 0xea,         # adds O8LOGON_LONG_IDENTIFIER (0x80)
        CCAP_FEATURE_BACKPORT: 0x18,
        CCAP_FIELD_VERSION: FIELD_VERSION_21_1,
        CCAP_SERVER_DEFINE_CONV: 1,
        CCAP_DEQUEUE_WITH_SELECTOR: 1,
        CCAP_TTC1: 0x29,
        CCAP_OCI1: 0x90,
        CCAP_TDS_VERSION: 3,
        CCAP_RPC_VERSION: 7,
        CCAP_RPC_SIG: 3,
        CCAP_DBF_VERSION: 1,
        CCAP_LOB: 0xcf,                 # adds LOB_12C (0x80)
        CCAP_TTC2: 4,
        CCAP_UB2_DTY: 1,
        CCAP_OCI2: 0x10,
        CCAP_CLIENT_FN: 12,             # TNS_CCAP_CLIENT_FN_MAX
        CCAP_OCI3: 0x20,               # OCI3_OCSSYNC
        CCAP_TTC3: 0xb8,
        CCAP_SESS_SIGNATURE_VERSION: 8,
        CCAP_TTC4: 0x44,
        CCAP_LOB2: 5,
        CCAP_TTC5: 0x3e,
        CCAP_FEATURE_BACKPORT2: 2,
        CCAP_VECTOR_FEATURES: 3,
    }),
}
_RUNTIME_CAPS = {
    FIELD_VERSION_11_2: (7, {
        RCAP_COMPAT: RCAP_COMPAT_81,
    }),
    FIELD_VERSION_21_1: (11, {
        RCAP_COMPAT: RCAP_COMPAT_81,
        RCAP_TTC: RCAP_TTC_ZERO_COPY | RCAP_TTC_32K,
    }),
}


def _render_caps(spec: tuple[int, dict]) -> bytes:
    """Render a (length, {index: value}) capability spec to its byte array."""
    length, values = spec
    caps = bytearray(length)
    for index, value in values.items():
        caps[index] = value
    return bytes(caps)


def capability_arrays(field_version: int = FIELD_VERSION_11_2) -> tuple[bytes, bytes]:
    """Return (compile_caps, runtime_caps) for a target TTC field version.

    Defaults to 11.2, which is byte-identical to what pyoracle has always sent.
    Higher versions are staged for 12c+ support (issue #27) and not wired into
    the handshake yet — advertising one also requires the matching version-gated
    DATA_TYPES table / OER / datatype decoding."""
    if field_version not in _COMPILE_CAPS:
        raise ValueError(f"unsupported TTC field version: {field_version}")
    return _render_caps(_COMPILE_CAPS[field_version]), _render_caps(_RUNTIME_CAPS[field_version])


# 12c+ datatype table. Where the 11g table (built inline in encode_dictionary_dty
# below) uses 1-byte-per-field entries with a short (type, 0) form for unknown
# types, the 12c+ table is a flat list of uniform 4-field entries, each field a
# UB2 (type, conv, repr, 0), terminated by a UB2 0. conv defaults to type and
# repr to 1 (universal) unless overridden in _DTY_12C_OVERRIDES (repr 10 =
# Oracle-native, e.g. NUMBER / DATE). The type list + overrides regenerate
# python-oracledb 4.0.1's DATA_TYPES table byte-for-byte (verified against a 21c
# capture); the gate is the UB2_DTY capability, i.e. field version >= 12.1.
_DTY_12C_TYPES = [
    1, 2, 8, 12, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 10, 11, 40,
    41, 117, 120, 290, 291, 292, 293, 294, 298, 299, 300, 301, 302, 303,
    304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 315, 316, 317,
    318, 319, 320, 321, 322, 323, 327, 328, 329, 331, 333, 334, 335,
    336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 348, 349,
    354, 355, 359, 363, 380, 381, 382, 383, 384, 385, 386, 387, 388,
    389, 390, 391, 393, 394, 395, 396, 397, 398, 399, 400, 401, 404,
    405, 406, 407, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422,
    423, 424, 425, 426, 427, 429, 430, 431, 432, 433, 449, 450, 454,
    455, 456, 457, 458, 459, 460, 461, 462, 463, 466, 467, 468, 469,
    470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482,
    483, 484, 485, 486, 490, 491, 492, 493, 494, 495, 496, 498, 499,
    500, 501, 502, 509, 510, 513, 514, 516, 517, 518, 519, 520, 521,
    522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534,
    535, 536, 537, 538, 539, 540, 541, 542, 543, 560, 565, 572, 573,
    574, 575, 576, 578, 563, 564, 579, 580, 581, 582, 583, 584, 585, 3,
    4, 5, 6, 7, 9, 15, 39, 68, 91, 94, 95, 96, 97, 100, 101, 102, 104,
    106, 108, 109, 110, 111, 112, 113, 114, 115, 116, 119, 198, 146,
    152, 153, 154, 155, 156, 172, 178, 179, 180, 181, 182, 183, 184,
    185, 186, 187, 188, 189, 190, 195, 196, 197, 208, 231, 232, 233,
    241, 252, 590, 591, 592, 613, 614, 615, 616, 611, 612, 593, 594,
    595, 596, 597, 598, 599, 600, 601, 602, 603, 604, 605, 622, 623,
    624, 625, 626, 627, 628, 629, 630, 631, 632, 637, 638, 636, 639,
    663, 640, 652, 646, 647, 127, 660, 661, 665, 669, 670,
]
_DTY_12C_OVERRIDES = {
    2: (2, 10), 12: (12, 10), 27: (27, 10), 3: (2, 10), 4: (2, 10),
    5: (1, 1), 6: (2, 10), 7: (2, 10), 9: (1, 1), 15: (1, 1), 68: (2, 10),
    91: (2, 10), 94: (1, 1), 95: (23, 1), 97: (96, 1), 104: (11, 1),
    108: (109, 1), 110: (111, 1), 116: (102, 1), 152: (2, 10),
    153: (2, 10), 154: (2, 10), 155: (1, 1), 156: (12, 10), 172: (2, 10),
    184: (12, 10), 195: (112, 1), 196: (113, 1), 197: (114, 1),
    232: (231, 1), 241: (109, 1),
}


def _datatype_table_12c() -> bytes:
    """Render the 12c+ datatype table: uniform UB2 (type, conv, repr, 0)
    entries terminated by a UB2 0."""
    Out = bytearray()
    for Type in _DTY_12C_TYPES:
        Conv, Rep = _DTY_12C_OVERRIDES.get(Type, (Type, 1))
        Out += struct.pack(">HHHH", Type, Conv, Rep, 0)
    Out += struct.pack(">H", 0)
    return bytes(Out)


def encode_dictionary_dty(Dictionary: dict) -> bytes:
    # TTI_DTY (Data Type Negotiation). Sent during the TTC handshake right
    # after TTI_PRO. Tells the server which native Oracle data types this
    # client understands and what wire representation it wants for each.
    #
    # On-wire structure (msgtype 2 = TNS_MSG_TYPE_DATA_TYPES):
    #
    #   TTI_DTY              1 byte   message token (== 2)
    #   charset_in           2 bytes  LE, NLS_LANGUAGE charset id (DB)
    #   charset_out          2 bytes  LE, NLS_NCHAR    charset id (client)
    #   flag                 1 byte   encoding flag (1 = standard)
    #   compile caps     1+N bytes  length byte + TNS_CCAP_* array
    #   runtime caps     1+M bytes  length byte + TNS_RCAP_* array
    #   identity table     980 bytes  `IdentityMap` — default "type N → repr N"
    #                                 for type ids 1..245 (245 × 4 bytes)
    #   override table     ~92 bytes  `TypeOverrides` — explicit non-identity
    #                                 mappings, terminated by `0 0`
    #
    # The capability arrays are built from named feature slots (see
    # `capability_arrays` above) and keyed on a target TTC field version; the
    # default (11.2) reproduces what pyoracle has always sent. The datatype
    # tables don't vary with the user's query workload — python-oracledb
    # hard-codes the equivalent, and the OCI thick client builds it from a
    # static C table at link time; we emit it as a constant for the same reason.
    # The table form is version-gated below: 11g 1-byte vs 12c+ 2-byte.
    logger.debug("encode_dictionary_dty: %s", _redacted(Dictionary))
    Charset = struct.pack("<H", CharsetDict.get(Dictionary['req'], UTF8_CHARSET))

    # Compile-time + runtime capability arrays, each emitted as a length byte
    # followed by the array (write_bytes_with_length in oracledb terms).
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    CompileCaps, RuntimeCaps = capability_arrays(FieldVersion)
    CapabilityHeader = bytes([len(CompileCaps)]) + CompileCaps
    TableHeader = bytes([len(RuntimeCaps)]) + RuntimeCaps

    # Identity map: for type id N in 1..245, emit (N, N, 1, 0) — "I know
    # type N and want it on the wire as type N with format flag 1". This
    # is the default assertion; `TypeOverrides` (below) overrides
    # specific entries.
    IdentityMap = bytes(reduce(lambda y, z: y + z,
                               [[]] + [[x, x, 1, 0] for x in range(1, 246)]))

    # Override table. Each entry is `(client_type, server_repr, format,
    # flags)` — when this client encounters data of type `client_type`,
    # negotiate `server_repr` as the wire representation with the given
    # format. Terminated by `0, 0`. Annotated against oracle.tns_consts:
    #
    #   (2,  2, 10)   NUMBER   → NUMBER (extended precision format 10)
    #   (3,  2, 10)   INTEGER  → NUMBER
    #   (4,  2, 10)   FLOAT    → NUMBER
    #   (5,  1,  1)   STRING   → VARCHAR
    #   (6,  2, 10)   VARNUM   → NUMBER
    #   (7,  2, 10)   DECIMAL  → NUMBER
    #   (9,  1,  1)   VCS      → VARCHAR
    #   (12,12, 10)   DATE     → DATE (format 10)
    #   (15,23,  1)   VBI      → RAW
    #   (39,120, 1)              named-type / collection variant
    #   (91, 2, 10)              NUMBER variant
    #   (94, 1,  1)   CHARZ    → VARCHAR
    #   (95,23,  1)              RAW variant
    #   (96,96,  1)   CHAR     → CHAR
    #   (97,96,  1)   CHAR_VAR → CHAR
    #   (104,11, 1)   ROWID    → RID (universal rowid → physical)
    #   (108,109,1)   NAMEDTYP → ADT
    #   (110,111,1)              → REF
    #   (116,102,1)   RSET     → REFCURSOR
    #   (146,146,1)              fixed-id self-map
    #   (152..154,2,10)          extended NUMBER subtypes → NUMBER
    #   (155, 1, 1)              → VARCHAR
    #   (156,12, 10)             → DATE
    #   (172, 2, 10)             → NUMBER
    #   (209, 0,  3)  UROWID
    #
    # Single-pair entries like `(13, 0)` are unknown types we don't have
    # a name for in tns_consts; they're left in for byte-level parity
    # with what every other Oracle client sends.
    TypeOverrides = bytes([
        2, 2, 10, 0, 3, 2, 10, 0, 4, 2, 10, 0, 5, 1, 1, 0,
        6, 2, 10, 0, 7, 2, 10, 0, 9, 1, 1, 0, 12, 12, 10, 0,
        13, 0, 14, 0,
        15, 23, 1, 0, 16, 0, 17, 0, 18, 0, 19, 0, 20, 0, 21, 0, 22, 0,
        39, 120, 1, 0,
        58, 0,
        68, 2, 10, 0, 69, 0, 70, 0, 74, 0,
        6, 0,
        91, 2, 10, 0, 94, 1, 1, 0, 95, 23, 1, 0,
        96, 96, 1, 0, 97, 96, 1, 0,
        104, 11, 1, 0, 105, 0,
        108, 109, 1, 0, 110, 111, 1, 0,
        116, 102, 1, 0,
        118, 0, 119, 0, 121, 0, 122, 0, 123, 0, 136, 0,
        146, 146, 1, 0, 147, 0,
        152, 2, 10, 0, 153, 2, 10, 0, 154, 2, 10, 0,
        155, 1, 1, 0, 156, 12, 10, 0,
        172, 2, 10, 0,
        209, 0, 3, 0,
        0,  # terminator
    ])
    # Datatype table: 12c+ (UB2_DTY) uses the uniform 2-byte-per-field table;
    # 11g uses the 1-byte form built above. The encoding flag follows suit
    # (oracledb sends 3 = MULTI_BYTE|CONV_LENGTH for 12c+, pyoracle 1 for 11g).
    if FieldVersion >= FIELD_VERSION_12_1:
        DataTypeTable = _datatype_table_12c()
        Flag = 3
    else:
        DataTypeTable = IdentityMap + TypeOverrides
        Flag = 1
    # Same charset for IN (server-side) and OUT (client-side) negotiation.
    return (bytes([TTI_DTY]) + Charset + Charset + bytes([Flag])
            + CapabilityHeader + TableHeader + DataTypeTable)

def _oac_rep_row(Rows: list) -> list:
    # For array DML, pick a representative value per column for the single OAC:
    # the one with the largest declared size (str/bytes byte length), so the
    # OAC's max-length covers every iteration. Fixed-size types (NUMBER, DATE,
    # ...) keep the first row's value.
    def _size(Value: object) -> int:
        if isinstance(Value, str):
            return len(Value.encode('utf-8'))
        if isinstance(Value, (bytes, bytearray)):
            return len(Value)
        return 0
    NumCols = len(Rows[0])
    Rep = []
    for J in range(NumCols):
        Best = Rows[0][J]
        BestSize = _size(Best)
        for R in Rows[1:]:
            S = _size(R[J])
            if S > BestSize:
                Best, BestSize = R[J], S
        Rep.append(Best)
    return Rep

def encode_dictionary_exec(Dictionary: dict) -> bytes:
    Type = Dictionary['query']['type']
    Auto = Dictionary['query']['auto']
    Fetch = Dictionary['query']['fetch']
    ServerVersion = b"" if (Dictionary['query']['server_version'] >> 24) == 10 else bytes([0,0,0,0,0])
    Cursor = Dictionary['query']['cursor']
    Query = Dictionary['query']['query'].encode('utf-8')
    QueryLen = len(Query)
    QueryFlag = 1 if QueryLen > 0 else 0
    Bind = Dictionary['query']['bind']
    BindLen = len(Bind)
    BindFlag = 1 if (Cursor == 0) and (BindLen > 0) else 0
    Batch = Dictionary['query']['batch']
    # Batch is a list of *additional* rows (each a list of column values) for
    # array DML: the OAC describes the columns once (from `Bind`, the first
    # row), the iteration count is 1 + len(Batch), and each row is sent as its
    # own RXD token after the OAC.
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
        if BatchLen > 0:
            Tokens = b"".join(encode_tokens_rxd(R, b"") for R in [Bind] + Batch)
        else:
            Tokens = encode_tokens_rxd(Bind, b"")
    elif DefLen == 0:
        if BatchLen > 0:
            # Array DML: OAC describes the columns once (sized to the widest
            # value in each column across all rows so a later row can't exceed
            # the declared buffer), then one RXD row per iteration.
            AllRows = [Bind] + Batch
            Oac = encode_tokens_oac(_oac_rep_row(AllRows), b"")
            Tokens = Oac + b"".join(
                encode_tokens_rxd(R, b"") for R in AllRows)
        else:
            Oac = encode_tokens_oac(Bind, b"")
            Tokens = encode_tokens_rxd(Bind, Oac)
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

def encode_dictionary_lobops(Dictionary: dict) -> bytes:
    # TTI_LOBOPS request. See docs/PROTOCOL.md §14 for the field layout.
    # This builds a READ request specifically (operation = 0x0002) since
    # that's all the driver currently issues; other opcodes plug into the
    # same shape by varying `operation` and the pointer flags.
    Tseq = Dictionary['seq']
    Locator = Dictionary['locator']
    # `amount` is in chars for CLOB / NCLOB and in bytes for BLOB / BFILE.
    # Don't pass the obvious-looking 0xFFFFFFFF "all" sentinel — XE 11g
    # quietly stops responding when given it (presumably Oracle tries to
    # allocate / range-check uint32-max and gets unhappy). 0x40000000
    # (= 1 GiB) is well over any real LOB we're likely to see while
    # staying inside signed-int32 territory, and the server returns just
    # the LOB's actual content rather than padding to the requested
    # ceiling.
    Amount = Dictionary.get('amount', 0x40000000)
    Operation = Dictionary.get('operation', TNS_LOB_OP_READ)
    SourceOffset = Dictionary.get('source_offset', 1)    # 1-based: start
    LocatorLen = len(Locator)

    Out = bytes([TTI_FUN, TTI_LOBOPS, Tseq])
    Out += bytes([1])                       # source pointer present
    Out += encode_sb4(LocatorLen)           # source locator length
    Out += bytes([0])                       # dest pointer absent
    Out += encode_sb4(0)                    # dest_length
    Out += encode_sb4(0)                    # short source offset
    Out += encode_sb4(0)                    # short dest offset
    Out += bytes([0])                       # charset pointer absent
    Out += bytes([0])                       # short amount absent
    Out += bytes([0])                       # null lob pointer absent
    Out += encode_sb4(Operation)            # operation code
    Out += bytes([0])                       # scn array pointer absent
    Out += bytes([0])                       # scn array length
    Out += encode_sb4(SourceOffset)         # source offset (ub8; small fits sb4)
    Out += encode_sb4(0)                    # dest offset (ub8)
    Out += bytes([1])                       # amount pointer present
    Out += struct.pack(">HHH", 0, 0, 0)     # three reserved ub16be slots
    Out += Locator                          # raw locator bytes (no DALC)
    Out += encode_sb4(Amount)               # amount to read
    return Out

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
    Request = Dictionary['req']        # single function-code byte (ping works)
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

    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    if FieldVersion >= FIELD_VERSION_12_1:
        # 12c+ OSESSKEY (python-oracledb auth.pyx _write_message phase one):
        # the username is length-prefixed (write_bytes_with_length) and the
        # pair count is 5, leading with AUTH_TERMINAL. 11g instead reads the
        # username by the earlier UserLen field and sends 4 pairs; sending the
        # 12c shape to 11g (or vice-versa) desyncs the server's parse.
        Terminal = encode_kv(b"AUTH_TERMINAL", b"unknown")
        UserField = bytes([len(User)]) + User
        return (bytes([TTI_FUN, TTI_SESS, Tseq, 1]) + UserLen + LogonMode
                + bytes([1]) + encode_sb4(5) + bytes([1, 1]) + UserField
                + Terminal + AppName + Hostname + Pid + SID)

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

    # Opt = (Flag ^ 32 ^ P0) | P1  (^ binds tighter than |); verified across
    # SELECT / DML / PL/SQL-block / array-DML execs.
    return (Flag ^ 32 ^ P0 | P1, P2, P3, All8)

def set_opts_all8(Opts: int, Fetch: int, Type: int) -> list[int]:
    return [Opts,Fetch,0,0,0,0,0,Type,0,0,0,0,0]

def decode_ub4(Bytes: bytes) -> tuple[int, bytes]:
    # Variable-length integer (PROTOCOL.md §12.1): a length byte, then that many
    # big-endian magnitude bytes (0..4). A length byte > 4 is not a real ub4 — it
    # arises because decode_token_oer reads some raw ub2 / counter fields through
    # here, whose leading byte can be anything. For those the historic behaviour
    # is to consume exactly two bytes (a raw ub2 width) and return the negated
    # second byte; the value is always discarded by those callers and consuming
    # two bytes keeps the OER stream aligned for ordinary multi-row fetches.
    # Making this strict (raising) desyncs that decode — e.g. a plain
    # "SELECT level FROM dual CONNECT BY level <= 50" crashes — so keep it
    # lenient. The single-byte negative form (NUMBER scale -127 = 0x81 0x7f)
    # falls out of the same branch.
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
            return (-Bytes[1], Bytes[2:])

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
    # Data with Attached Length Code (PROTOCOL.md §12.2). 0x00 = empty,
    # 0xFF = null marker (no data follows), 0xFE = chunked, otherwise the
    # length byte is followed by that many data bytes. Both empty and null
    # are reported as [] here; callers that need the distinction look at the
    # enclosing bytes_with_length count.
    if Bytes[0] == 0 or Bytes[0] == 255:
        return ([], Bytes[1:])
    elif Bytes[0] == 254:
        return decode_chr(Bytes)
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
    # OAC descriptors are emitted bare here (no leading TTI_OAC token byte) —
    # that's what the server expects inside the ALL8 bind section.
    Out = b""
    for Token in Tokens:
        Out += encode_token_oac(Token)
    return Binary + Out

def exec_oac_signature(Bind: list, Batch: list) -> bytes:
    # The exact OAC bytes a fresh parse would send for these binds. Used as
    # part of the DML cursor-cache key: a cached cursor re-execute skips
    # re-sending the OAC, so the server keeps the bind buffer sizes (and types)
    # from the original parse. Reusing it for binds whose OAC differs — most
    # commonly a longer string than the first call sized for — overflows that
    # frozen buffer and the server rejects the value as a streamed LONG
    # (ORA-01461). Keying the cache on this signature turns such a call into a
    # cache miss, forcing a re-parse with a correctly-sized OAC.
    if not Bind:
        return b""
    if Batch:
        return encode_tokens_oac(_oac_rep_row([Bind] + Batch), b"")
    return encode_tokens_oac(Bind, b"")

def encode_token_rxd(Token: object) -> bytes:
    if isinstance(Token, Var):
        # OUT / IN OUT bind: send the current value (NULL for an unseeded pure
        # OUT). The server writes the result back in the IOV response.
        if Token.dbtype.tns_type == TNS_TYPE_REFCURSOR:
            return bytes([1, 0])            # REF CURSOR slot placeholder
        if Token._value is None:
            return bytes([0])
        return encode_token_rxd(Token._value)
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
    if isinstance(Token, BinaryFloat):
        Bytes = encode_token_binary_float(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, BinaryDouble):
        Bytes = encode_token_binary_double(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, float):
        # NUMBER can't represent inf / nan; route the non-finite values to a
        # native BINARY_DOUBLE so they round-trip instead of blowing up the
        # base-100 encoder. Finite floats keep the historical NUMBER binding.
        if not math.isfinite(Token):
            Bytes = encode_token_binary_double(Token)
            return bytes([len(Bytes)]) + Bytes
        Bytes = encode_token_num(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, complex):
        Bytes = encode_token_num(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, datetime.timedelta):
        Bytes = encode_token_interval_ds(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, IntervalYM):
        Bytes = encode_token_interval_ym(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, str):
        return encode_chr(Token)
    if isinstance(Token, (bytes, bytearray)):
        # RAW binds: hand the bytes through verbatim. The old code path
        # round-tripped them through utf-8 → utf-16be which corrupted
        # anything that wasn't ASCII (and outright failed on 0x80+ bytes).
        return encode_chr(bytes(Token))
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
    # The OAC field tells the server the maximum size we *might* send for
    # this bind. Oracle rejects with ORA-01461 ("can bind a LONG value only
    # for insert into a LONG column") if the actual value exceeds it, even
    # when the target is a CLOB / BLOB that could comfortably hold more.
    # 32767 = PL/SQL VARCHAR2 / RAW max, the largest the regular bind path
    # accepts on 11g; larger payloads need TTI_LOBOPS WRITE.
    if isinstance(Token, Var):
        # OAC is driven by the Var's declared type + size, NOT its (maybe NULL)
        # value, so a pure-OUT bind still announces the right type and a buffer
        # large enough for the server to return into.
        DT = Token.dbtype.tns_type
        if DT == TNS_TYPE_NUMBER:
            return encode_token_raw(TNS_TYPE_NUMBER, 22, 0, 0, 0)
        if DT == TNS_TYPE_VARCHAR:
            return encode_token_raw(TNS_TYPE_VARCHAR, Token.size, 16,
                                    UTF8_CHARSET, 0)
        if DT == TNS_TYPE_RAW:
            return encode_token_raw(TNS_TYPE_RAW, Token.size, 16, 0, 0)
        if DT == TNS_TYPE_DATE:
            return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0)
        if DT == TNS_TYPE_TIMESTAMP:
            return encode_token_raw(TNS_TYPE_TIMESTAMP, 11, 0, 0, 0)
        if DT == TNS_TYPE_TIMESTAMPTZ:
            return encode_token_raw(TNS_TYPE_TIMESTAMPTZ, 13, 0, 0, 0)
        if DT == TNS_TYPE_BFLOAT:
            return encode_token_raw(TNS_TYPE_BFLOAT, 4, 0, 0, 0)
        if DT == TNS_TYPE_BDOUBLE:
            return encode_token_raw(TNS_TYPE_BDOUBLE, 8, 0, 0, 0)
        if DT == TNS_TYPE_INTERVALDS:
            return encode_token_raw(TNS_TYPE_INTERVALDS, 11, 0, 0, 0)
        if DT == TNS_TYPE_INTERVALYM:
            return encode_token_raw(TNS_TYPE_INTERVALYM, 5, 0, 0, 0)
        if DT == TNS_TYPE_REFCURSOR:
            return encode_token_raw(TNS_TYPE_REFCURSOR, 1, 0, UTF8_CHARSET, 0)
        raise Exception("Unsupported Var OAC type", DT)
    if Token is None:
        # NULL value (0 bytes): a minimal VARCHAR OAC, again avoiding the
        # 32767 LONG-reorder swap when a NULL bind precedes another bind.
        return encode_token_raw(TNS_TYPE_VARCHAR, 1, 16, UTF8_CHARSET, 0)
    if isinstance(Token, BinaryFloat):
        return encode_token_raw(TNS_TYPE_BFLOAT, 4, 0, 0, 0)
    if isinstance(Token, BinaryDouble):
        return encode_token_raw(TNS_TYPE_BDOUBLE, 8, 0, 0, 0)
    if isinstance(Token, float) and not math.isfinite(Token):
        # Non-finite floats (inf / nan) bind as native BINARY_DOUBLE — NUMBER
        # can't represent them (see encode_token_rxd).
        return encode_token_raw(TNS_TYPE_BDOUBLE, 8, 0, 0, 0)
    if isinstance(Token, (int, float, complex, Decimal)):
        return encode_token_raw(TNS_TYPE_NUMBER, 22, 0, 0, 0)
    if isinstance(Token, datetime.timedelta):
        return encode_token_raw(TNS_TYPE_INTERVALDS, 11, 0, 0, 0)
    if isinstance(Token, IntervalYM):
        return encode_token_raw(TNS_TYPE_INTERVALYM, 5, 0, 0, 0)
    if isinstance(Token, str):
        # Size the OAC to the actual value, not a flat 32767: a VARCHAR bind
        # declared larger than the 4000-byte VARCHAR2 limit is treated by the
        # server as a streamed LONG and reordered after the following bind,
        # which silently swaps a string bind with the next one. A value over
        # 4000 bytes still gets the larger size (and the LONG handling) it
        # needs for the ~7 KiB regular-path CLOB case.
        return encode_token_raw(
            TNS_TYPE_VARCHAR, max(len(Token.encode('utf-8')), 1), 16,
            UTF8_CHARSET, 0)
    if isinstance(Token, (bytes, bytearray)):
        # Bind as RAW so arbitrary byte sequences (non-UTF8, control bytes,
        # 0x80+) round-trip verbatim into RAW / BLOB columns. Size to the
        # actual value (see the str case) to avoid the LONG-reorder swap.
        return encode_token_raw(TNS_TYPE_RAW, max(len(Token), 1), 16, 0, 0)
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

def encode_token_binary_float(Value: float) -> bytes:
    # BINARY_FLOAT is a 32-bit IEEE-754 value stored in Oracle's order-
    # preserving form: for a positive number the sign bit is set, for a
    # negative number every bit is flipped. Decoding reverses this.
    Raw = struct.pack(">f", Value)
    if Raw[0] & 0x80:
        return bytes(B ^ 0xFF for B in Raw)
    return bytes([Raw[0] ^ 0x80]) + Raw[1:]

def encode_token_binary_double(Value: float) -> bytes:
    # BINARY_DOUBLE: same order-preserving transform as BINARY_FLOAT over the
    # 64-bit IEEE-754 representation.
    Raw = struct.pack(">d", Value)
    if Raw[0] & 0x80:
        return bytes(B ^ 0xFF for B in Raw)
    return bytes([Raw[0] ^ 0x80]) + Raw[1:]

def encode_token_interval_ds(TD: datetime.timedelta) -> bytes:
    # INTERVAL DAY TO SECOND: 4-byte days biased by 2**31, then hours / minutes
    # / seconds each biased by 60, then 4-byte nanoseconds biased by 2**31. All
    # fields share the interval's sign, so collapse the timedelta (which keeps
    # days negative but seconds/microseconds positive) to a single signed total
    # before splitting it back out.
    TotalUs = (TD.days * 86400 + TD.seconds) * 1_000_000 + TD.microseconds
    Negative = TotalUs < 0
    TotalUs = abs(TotalUs)
    Days, Rest = divmod(TotalUs, 86_400_000_000)
    Hours, Rest = divmod(Rest, 3_600_000_000)
    Minutes, Rest = divmod(Rest, 60_000_000)
    Seconds, Micros = divmod(Rest, 1_000_000)
    Nanos = Micros * 1000
    if Negative:
        Days, Hours, Minutes, Seconds, Nanos = (
            -Days, -Hours, -Minutes, -Seconds, -Nanos)
    return (
        (Days + 2**31).to_bytes(4, "big")
        + bytes([Hours + 60, Minutes + 60, Seconds + 60])
        + (Nanos + 2**31).to_bytes(4, "big")
    )

def encode_token_interval_ym(IV: IntervalYM) -> bytes:
    # INTERVAL YEAR TO MONTH: 4-byte years biased by 2**31, then 1-byte months
    # biased by 60. IntervalYM has already normalised the two fields to share a
    # sign with abs(months) < 12.
    return (IV.years + 2**31).to_bytes(4, "big") + bytes([IV.months + 60])

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
