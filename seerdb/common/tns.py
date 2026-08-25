# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import datetime
import platform
from decimal import Decimal
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from seerdb.common.dbobject import DbObject, DbRef
from functools import reduce

from seerdb.client.cursor import cursor
from seerdb.common.crypto import encrypt_password, o5logon
from seerdb.common.datatypes import (
    JSON,
    BinaryDouble,
    BinaryFloat,
    IntervalYM,
    TempLob,
    Var,
)
from seerdb.common.date import date
from seerdb.common.exceptions import DataError
from seerdb.common.vector import (
    VECTOR_BIND_DESCRIPTOR,
    VECTOR_BIND_OAC,
    encode_vector,
    is_vector_bind,
)


def _json_bind_text(Token: object) -> str:
    # A dict (auto-detected) or a JSON() wrapper binds into a native JSON column
    # (#50): serialise to JSON text and bind it as a string; the server casts
    # VARCHAR -> JSON. Lazy import keeps oson off the tns import chain.
    from seerdb.common.oson import json_to_text

    return json_to_text(Token.value if isinstance(Token, JSON) else Token)


def _native_lob_bind_value(image: bytes) -> bytes:
    # Native inline bind value for a LOB-backed type (VECTOR #62, JSON #70): a
    # fixed descriptor, the image length (ub2), 22 zero bytes, then the image
    # framed like RAW (encode_chr).
    return (
        VECTOR_BIND_DESCRIPTOR
        + len(image).to_bytes(2, 'big')
        + b'\x00' * 22
        + encode_chr(image)
    )


def _json_oson_image(Token: object):
    # The OSON image for a dict / JSON() bind (#70), or None when the value is
    # too large/complex for the native encoder so the caller falls back to the
    # text cast (#50/#64) — which the server parses just as well.
    from seerdb.common.oson import OsonError, encode_oson

    value = Token.value if isinstance(Token, JSON) else Token
    try:
        return encode_oson(value)
    except OsonError:
        return None


import contextvars
import logging
import math
import os
import re
import socket
import struct

from seerdb.common.tns_consts import (
    AL16UTF16_CHARSET,
    AL32UTF8_CHARSET,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_SID,
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_12_2,
    FIELD_VERSION_12_2_EXT1,
    FIELD_VERSION_19_1_EXT1,
    FIELD_VERSION_20_1,
    FIELD_VERSION_21_1,
    FIELD_VERSION_23_1,
    TNS_AL8I4_ARRAY_DML_ROWCOUNTS,
    TNS_AQ_ARRAY_ENQ,
    TNS_AQ_ARRAY_FLAGS_RETURN_MESSAGE_ID,
    TNS_AQ_EXT_KEYWORD_AGENT_ADDRESS,
    TNS_AQ_EXT_KEYWORD_AGENT_NAME,
    TNS_AQ_EXT_KEYWORD_AGENT_PROTOCOL,
    TNS_AQ_EXT_KEYWORD_ORIGINAL_MSGID,
    TNS_AQ_MESSAGE_ID_LENGTH,
    TNS_AQ_MESSAGE_VERSION,
    TNS_AQ_MSG_BUFFERED,
    TNS_AQ_MSG_PERSISTENT_OR_BUFFERED,
    TNS_BIND_DIR_INPUT,
    TNS_CCAP_END_OF_RESPONSE,
    TNS_DATA,
    TNS_END_TO_END_ACTION,
    TNS_END_TO_END_CLIENT_IDENTIFIER,
    TNS_END_TO_END_CLIENT_INFO,
    TNS_END_TO_END_DBOP,
    TNS_END_TO_END_MODULE,
    TNS_EXEC_FLAGS_NO_CANCEL_ON_EOF,
    TNS_EXEC_FLAGS_SCROLLABLE,
    TNS_EXEC_OPTION_BATCH_ERRORS,
    TNS_EXEC_OPTION_EXECUTE,
    TNS_FUNC_AQ_DEQ,
    TNS_FUNC_AQ_ENQ,
    TNS_FUNC_ARRAY_AQ,
    TNS_FUNC_PIPELINE_BEGIN,
    TNS_FUNC_PIPELINE_END,
    TNS_FUNC_SET_END_TO_END_ATTR,
    TNS_FUNC_TPC_TXN_CHANGE_STATE,
    TNS_FUNC_TPC_TXN_SWITCH,
    TNS_KPD_AQ_BUFMSG,
    TNS_KPD_AQ_EITHER,
    TNS_LOB_OP_FILE_CLOSE,
    TNS_LOB_OP_FILE_OPEN,
    TNS_LOB_OP_READ,
    TNS_LOB_OP_WRITE,
    TNS_MSG_TYPE_FAST_AUTH,
    TNS_REDIRECT,
    TNS_SERVER_CONVERTS_CHARS,
    TNS_SERVER_PIGGYBACK_LTXID,
    TNS_SERVER_PIGGYBACK_OS_PID_MTS,
    TNS_SERVER_PIGGYBACK_QUERY_CACHE_INVALIDATION,
    TNS_SERVER_PIGGYBACK_SESS_RET,
    TNS_SERVER_PIGGYBACK_SYNC,
    TNS_SERVER_PIGGYBACK_TRACE_EVENT,
    TNS_TYPE_ADT,
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFILE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_BLOB,
    TNS_TYPE_BOOLEAN,
    TNS_TYPE_CHAR,
    TNS_TYPE_CLOB,
    TNS_TYPE_DATE,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_INTERVALYM,
    TNS_TYPE_JSON,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_REF,
    TNS_TYPE_REFCURSOR,
    TNS_TYPE_RID,
    TNS_TYPE_ROWID,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_UROWID,
    TNS_TYPE_VARCHAR,
    TNS_TYPE_VECTOR,
    TTI_3LOGA,
    TTI_3LOGON,
    TTI_ALL7,
    TTI_ALL8,
    TTI_AUTH,
    TTI_BVC,
    TTI_DCB,
    TTI_DTY,
    TTI_END_OF_RESPONSE,
    TTI_FETCH,
    TTI_FOB,
    TTI_FUN,
    TTI_IOV,
    TTI_IRD,
    TTI_LOB,
    TTI_LOBOPS,
    TTI_LOGOFF,
    TTI_MSG_TYPE_PIGGYBACK,
    TTI_OAC,
    TTI_OCCA,
    TTI_OER,
    TTI_PFN,
    TTI_PRO,
    TTI_RPA,
    TTI_RXD,
    TTI_RXH,
    TTI_SESS,
    TTI_SPFP,
    TTI_STA,
    TTI_STOP,
    TTI_STRT,
    TTI_SVR_PIGGYBACK,
    TTI_TOKEN,
    TTI_UDS,
    TTI_WRN,
    UTF8_CHARSET,
    CharsetDict,
    DictionaryType,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_9_2 as FIELD_VERSION_9_2,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_19_1 as FIELD_VERSION_19_1,
)

logger = logging.getLogger(__name__)

# The TTC field version negotiated for the connection whose response we are
# currently decoding. Set by `decode_packet` at the top of each response and
# read by the version-gated token decoders (e.g. the 12c+ DCB column format).
# A ContextVar (not a parameter threaded through every decoder, nor a plain
# global) so concurrent async connections / sync threads each see their own
# value. Default 6 == FIELD_VERSION_11_2 (defined later); decoders only diverge
# from the 11g layout when this is >= a 12c+ field version.
_DECODE_FIELD_VERSION = contextvars.ContextVar('decode_field_version', default=6)

# Same idea for the *encode* side: the field version of the message currently
# being built, set by encode_dictionary_exec and read by encode_token_raw to
# pick the 11g vs 12c+ bind-OAC layout. Separate from the decode var so the two
# phases never interfere. Default 6 == FIELD_VERSION_11_2.
_ENCODE_FIELD_VERSION = contextvars.ContextVar('encode_field_version', default=6)

# Set True for the duration of an execute that requested array-DML row counts
# (oracledb arraydmlrowcounts, #18). It tells decode_token_rpa_piggyback to
# expect the `ub4 count | count×ub4` row-count block the server appends to the
# RPA region ahead of the trailing OER — absent the flag the RPA is just walked
# and discarded as before. The connection sets it per execute.
_DECODE_DML_ROWCOUNTS = contextvars.ContextVar('decode_dml_rowcounts', default=False)


def set_decode_dml_rowcounts(Flag: bool) -> None:
    """Arm/disarm row-count extraction for the next response decode (#18).

    The connection calls this before reading an execute's response so
    decode_token_rpa_piggyback knows whether to expect the array-DML row-count
    block. Reset every execute so a stale flag never leaks into another call."""
    _DECODE_DML_ROWCOUNTS.set(bool(Flag))


# DML RETURNING ... INTO (#120): the sorted return-bind positions for the next
# response, so the TTI_RXD decoder reads the out-bind return data (per bind:
# ub4 num_rows + per row a value + sb4 truncation length) instead of treating
# the RXD as query rows. Reset every execute.
_DECODE_RETURN_BINDS = contextvars.ContextVar('decode_return_binds', default=())


def set_decode_return_binds(Positions) -> None:
    """Arm return-bind decoding for the next response (#120). `Positions` is the
    set/list of 0-based OUT-bind positions, or empty/None to disarm."""
    _DECODE_RETURN_BINDS.set(tuple(sorted(Positions)) if Positions else ())


# The last row of the previous fetch, seeded for a scroll re-execute (#181). When
# a scroll repositions onto a row whose column values equal the last row already
# returned, the server omits those values and flags them in the row-header bit
# vector as "reuse previous". Duplicate detection is per-response in the decoder
# (Rows starts empty each call), so the cursor seeds this with the prior batch's
# last row; decode_token_rxd falls back to it for a reused column when no
# in-response previous row exists. Empty/None disarms (the default).
_DECODE_PREV_ROW: contextvars.ContextVar[list | None] = contextvars.ContextVar(
    'decode_prev_row', default=None
)


def set_decode_prev_row(Row) -> None:
    """Seed the previous-fetch row for the next scroll re-execute decode (#181),
    or pass None to disarm."""
    _DECODE_PREV_ROW.set(list(Row) if Row else None)


def assemble_packet(
    Data: bytes, Length: int, Large: bool = False
) -> tuple[bool, int | None, bytes | None, bytes | None]:
    # Two on-wire packet-header layouts share an 8-byte size and put the type at
    # byte 4. Legacy: len(ub2) + checksum(ub2) + type + flags + hdr-cksum(ub2).
    # Large-SDU (#155, negotiated at protocol version >= 315): len(ub4) + type +
    # flags + hdr-cksum(ub2) — the 4-byte length replaces the legacy len+cksum.
    # `Zero` (the hdr-cksum at bytes 6-7) is read the same way in both.
    if Large:
        (PacketSize, Type, Flags, Zero) = struct.unpack('>IBBh', Data[:8])
    else:
        (PacketSize, _, Type, Flags, Zero) = struct.unpack('>HhBBh', Data[:8])
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
        # The server is handing us a new address to reconnect to (shared
        # server / RAC / some listener configs). The body is the connect
        # descriptor — ASCII, carrying an (ADDRESS=...(HOST=..)(PORT=..)).
        # Return it raw (everything after the 8-byte header); handle_login
        # parses the address out. A leading 2-byte data-length some servers
        # insert is simply skipped over by the descriptor regex.
        if PacketSize <= len(Data):
            return (True, TNS_REDIRECT, Data[8:PacketSize], Data[PacketSize:])
        return (False, None, None, None)
    elif Zero == 0:
        BodySize = PacketSize - 8
        Rest = Data[8:]
        if BodySize <= len(Rest):
            return (True, Type, Rest[:BodySize], Rest[BodySize:])
        else:
            return (False, None, None, None)
    else:
        raise Exception('Cannot decode packet', Data, Length)


_REDIRECT_HOST_RE = re.compile(rb'\(HOST\s*=\s*([^)\s]+)\s*\)', re.IGNORECASE)
_REDIRECT_PORT_RE = re.compile(rb'\(PORT\s*=\s*(\d+)\s*\)', re.IGNORECASE)


def parse_redirect_address(Body: bytes) -> tuple[str | None, int | None]:
    # Pull the (HOST=..)(PORT=..) out of a TNS_REDIRECT body's connect
    # descriptor. The descriptor carries the server ADDRESS to reconnect to,
    # and may also carry the original CONNECT_DATA (whose CID has the *client*
    # HOST) after a NUL — so scope the search to the ADDRESS block, where the
    # real target lives, and only fall back to a bare first match if there is
    # no ADDRESS keyword.
    Region = Body
    Marker = re.search(rb'\(ADDRESS\b', Body, re.IGNORECASE)
    if Marker:
        Region = Body[Marker.start() :]
    Host = _REDIRECT_HOST_RE.search(Region)
    Port = _REDIRECT_PORT_RE.search(Region)
    if Host and Port:
        return (Host.group(1).decode('ascii', 'replace'), int(Port.group(1)))
    return (None, None)


def decode_packet(Data: bytes, Acc: tuple, FieldVersion: int | None = None) -> tuple:
    # FieldVersion is passed only by the top-level caller (the connection's
    # response handler); recursive token decoders omit it and inherit the value
    # via the ContextVar set here.
    if FieldVersion is not None:
        _DECODE_FIELD_VERSION.set(FieldVersion)
    Token = Data[0]
    logger.debug('Token %s', Token)
    match Token:
        case t if t == TTI_BVC:
            return decode_token_bvc(Data, Acc)
        case t if t == TTI_DCB:
            return decode_token_dcb(Data, Acc)
        case t if t == TTI_FOB:  # return
            return (False, 'fob')
        case t if t == TTI_IOV:
            return decode_token_iov(Data, Acc)
        case t if t == TTI_IRD:
            return decode_token_implicit(Data, Acc)
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
        case t if t == TTI_SVR_PIGGYBACK:
            return decode_token_server_piggyback(Data, Acc)
        case t if t == TTI_STA:  # tran
            return (True, Acc)
        case t if t == TTI_END_OF_RESPONSE:
            # End-of-response marker (#155/#132): on an EOR-negotiated 23ai
            # connection the server terminates each response with this token.
            # A single (non-pipelined) call already ends on its STATUS/OER
            # terminal, so this is normally the trailing byte in the same
            # packet; handle it explicitly so it is never an "unknown type".
            return (True, Acc)
        case t if t == TTI_TOKEN:
            # Pipeline response-correlation marker (#158): a ub8 token number
            # tagging which pipelined op this response belongs to. The pipelined
            # responses arrive in op order, so consume the token and continue
            # decoding the op's response body (which ends on its own EOR).
            (_, Rest) = decode_ub4(Data[1:])
            return decode_packet(Rest, Acc)
        case t if t == TTI_UDS:
            return decode_token_uds(Data, Acc)
        case t if t == TTI_WRN:
            return decode_token_wrn(Data, Acc)
    # No case matched — raise here rather than via `case _` so every branch is a
    # value-return, matching encode_dictionary below and keeping CodeQL's flow
    # analysis happy (the `case _` wildcard reads as an implicit fall-through).
    raise Exception("Can't decode unknown type", Token, Data, Acc)


def decode_token_bvc(Data: bytes, Acc: tuple) -> tuple:
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
        return Data[1 + Length :]


def _read_chunked_bytes(Data: bytes) -> tuple[bytes, bytes]:
    # The value form _skip_chunked_bytes skips, but returning the bytes: a
    # 1-byte length then that many raw bytes (length < 254), nothing (255 NULL),
    # or a chunked ub4-prefixed sequence terminated by a zero-length chunk (254).
    Length = Data[0]
    if Length == 254:
        Rest = Data[1:]
        Out = b''
        while True:
            (ChunkLen, Rest) = decode_ub4(Rest)
            if ChunkLen == 0:
                return (Out, Rest)
            Out += bytes(Rest[:ChunkLen])
            Rest = Rest[ChunkLen:]
    elif Length == 255:
        return (b'', Data[1:])
    else:
        return (bytes(Data[1 : 1 + Length]), Data[1 + Length :])


def _skip_bytes_with_length(Data: bytes) -> bytes:
    (NumBytes, Rest) = decode_ub4(Data)
    if NumBytes > 0:
        Rest = _skip_chunked_bytes(Rest)
    return Rest


def _bytes_with_length(Data: bytes) -> bytes:
    # Inverse of `_skip_chunked_bytes` (oracledb write_bytes_with_length): a
    # 1-byte length + data for short values (< 254), or the 254 LONG marker
    # followed by ub4-prefixed chunks terminated by a zero-length chunk.
    if len(Data) < 254:
        return bytes([len(Data)]) + Data
    Out = bytearray([254])
    for I in range(0, len(Data), 0x40):
        Chunk = Data[I : I + 0x40]
        Out += encode_sb4(len(Chunk)) + Chunk
    Out += encode_sb4(0)
    return bytes(Out)


def _read_str_with_length(Data: bytes) -> tuple[bytes, bytes]:
    (NumBytes, Rest) = decode_ub4(Data)
    if NumBytes > 0:
        # A length-prefixed string is never chunked, so the DALC value is bytes
        # (never the list form).
        return cast('tuple[bytes, bytes]', decode_dalc(Rest))
    return (b'', Rest)


def decode_token_dcb(Data: bytes, Acc: tuple) -> tuple:
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
    (Columns, Rest) = _decode_describe_body(Rest)
    return decode_packet(Rest, (Cursor, Columns, Rows))


def decode_token_implicit(Data: bytes, Acc: tuple) -> tuple:
    # Implicit result sets (#121, DBMS_SQL.RETURN_RESULT). Layout (oracledb
    # base.pyx _process_implicit_result):
    #   ub4  num_results
    #   per result:  ub1 len + that many bytes (skip)
    #                describe body (column metadata, _decode_describe_body)
    #                ub2 cursor id
    # Each result is a server cursor (id + row format), fetched on demand like a
    # REF CURSOR. We surface them as a record the cursor turns into nextset()
    # result sets, then continue decoding the block's trailing RPA/OER.
    (Cursor, RowFormat, Rows, *_) = Acc
    Rest = Data[1:]
    (NumResults, Rest) = decode_ub4(Rest)
    Results = []
    for _ in range(NumResults):
        PreLen = Rest[0]
        Rest = Rest[1 + PreLen :]
        (Columns, Rest) = _decode_describe_body(Rest)
        (CursorId, Rest) = decode_ub4(Rest)  # ub2 cursor id
        Results.append({'cursor_id': CursorId, 'row_format': Columns})
    Record = {'implicit_results': Results}
    return decode_packet(Rest, (Cursor, RowFormat, Rows + [Record]))


def _decode_describe_body(Rest: bytes) -> tuple[list, bytes]:
    # The describe-info body shared by the TTI_DCB token and the implicit-result
    # describe (#121): max row size, column count, a reserved byte, the
    # per-column metadata, then the describe trailer. The token-specific
    # preamble (DCB's chunked uuid/timestamp, or the implicit-result ub1 block)
    # is consumed by the caller before this point.
    (_, Rest) = decode_ub4(Rest)  # max row size
    (NumCols, Rest) = decode_ub4(Rest)
    if NumCols > 0:
        Rest = Rest[1:]  # reserved
    Columns = []
    for _ in range(NumCols):
        (Col, Rest) = _decode_dcb_column(Rest)
        Columns.append(Col)
    Rest = _skip_bytes_with_length(Rest)  # current date
    for _ in range(4):
        (_, Rest) = decode_ub4(Rest)  # dcbflag/dcbmdbz/dcbmnpr/dcbmxpr
    if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_11_2:
        # dcbqcky (query-cache key) is an 11g addition (the result cache landed
        # in 11g); 10g's describe ends after the four ub4 flags, so skipping a
        # phantom bytes-with-length here would consume the first row token (#84).
        Rest = _skip_bytes_with_length(Rest)
    return (Columns, Rest)


def _decode_dcb_column(Rest: bytes) -> tuple[dict, bytes]:
    # Per-column metadata. 12c+ (field version >= 12.2) differs from 11g in two
    # ways (oracledb base.pyx _process_metadata): scale is a raw signed byte
    # (sb1), and an extra ub4 `oaccolid` follows max_size. 11g keeps an
    # sb4-style variable scale (so NUMBER's -127 default arrives as 0x81 0x7f)
    # and has no oaccolid. precision is sb1 in both.
    Is12c = _DECODE_FIELD_VERSION.get() >= 8  # FIELD_VERSION_12_2
    DataType = Rest[0]
    Precision = Rest[2]  # sb1
    Rest = Rest[3:]
    if Is12c:
        DataScale = Rest[0] - 256 if Rest[0] > 127 else Rest[0]  # sb1
        Rest = Rest[1:]
    else:
        (DataScale, Rest) = decode_ub4(Rest)
    (BufferSize, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)  # max_array_elems
    (_, Rest) = decode_ub4(Rest)  # cont_flags (ub8 on 12c; small)
    (OidLen, Rest) = decode_ub4(Rest)
    TypeOid = b''
    if OidLen > 0:
        # For an object (ADT, type 109) / collection column this is the type's
        # 16-byte OID; capturing it (rather than skipping) lets the row decoder
        # tie the value back to its type for the attribute-layout lookup (#115).
        (TypeOid, Rest) = _read_chunked_bytes(Rest)
    (_, Rest) = decode_ub4(Rest)  # version
    (Charset, Rest) = decode_ub4(Rest)  # charset id
    Csfrm = Rest[0]  # charset form (1 DB / 2 national)
    Rest = Rest[1:]
    (MaxSize, Rest) = decode_ub4(Rest)
    if Is12c:
        (_, Rest) = decode_ub4(Rest)  # oaccolid (12.2+)
    NullOk = Rest[0]
    Rest = Rest[2:]  # skip nulls_allowed-byte AND v7 name length
    (ColName, Rest) = _read_str_with_length(Rest)
    (TypeSchema, Rest) = _read_str_with_length(Rest)  # owner of the type (ADT)
    (TypeName, Rest) = _read_str_with_length(Rest)  # the type's name (ADT)
    (_, Rest) = decode_ub4(Rest)  # column position
    if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_11_2:
        # `uds flags` is an 11g addition; a 10g (field version 4) describe ends
        # the per-column metadata at column position. Reading a phantom ub4 here
        # eats the next column's first bytes (or the DCB trailer's date length),
        # desyncing the whole row decode (#84). Verified against a live 10.2.0.5
        # server across 1/2/6-column, mixed-type and 0-row describes.
        (_, Rest) = decode_ub4(Rest)  # uds flags
    DomainSchema = DomainName = b''
    if _DECODE_FIELD_VERSION.get() >= 17:  # FIELD_VERSION_23_1
        # 23c (field version 17) appends the column's SQL-domain schema and
        # name, each a ub4-counted DALC string (the same codec as the column
        # name above) — empty (a single 0x00) for a column with no domain.
        # Earlier code read them as plain ub4s, which only survives the empty
        # case; a real domain (e.g. `01 03 03 'PYO' 01 07 07 'PYO_DOM'`) then
        # desynced the row (#53). Reverse-engineered by diffing a domain column
        # vs a plain one on 23ai, cross-checked against python-oracledb's
        # domain_schema/domain_name. Column annotations are carried elsewhere in
        # the describe (a plain column and an annotated one have identical
        # trailing fields here), so they neither appear nor desync here.
        (DomainSchema, Rest) = _read_str_with_length(Rest)
        (DomainName, Rest) = _read_str_with_length(Rest)
    Annotations = {}
    if _DECODE_FIELD_VERSION.get() > FIELD_VERSION_23_1:  # 23ai fv >= 18 (#89)
        # Each column carries its annotation map and the vector descriptor after
        # the domain fields (oracledb base.pyx _process_metadata). Both must be
        # consumed or the row stream desyncs; the annotations are the #89 payload.
        # The count is sent twice around a 1-byte pointer, and each key/value pair
        # is followed by a ub4 flags word, with a trailing ub4 flags after the loop.
        (NumAnno, Rest) = decode_ub4(Rest)
        if NumAnno > 0:
            Rest = Rest[1:]  # pointer
            (NumAnno, Rest) = decode_ub4(Rest)  # count, repeated
            Rest = Rest[1:]  # pointer
            for _ in range(NumAnno):
                (Key, Rest) = _read_str_with_length(Rest)
                (Val, Rest) = _read_str_with_length(Rest)
                Annotations[Key] = Val or b''
                (_, Rest) = decode_ub4(Rest)  # per-pair flags
            (_, Rest) = decode_ub4(Rest)  # trailing flags
        # Vector descriptor (23.4+): dimensions (ub4) + format + flags (ub1 each).
        (_, Rest) = decode_ub4(Rest)
        Rest = Rest[2:]
    Col = {
        'column_name': ColName,
        'data_type': DataType,
        'data_length': BufferSize,
        'data_scale': DataScale,
        'precision': Precision,
        'max_size': MaxSize,
        'charset': Charset,
        'csfrm': Csfrm,
        'null_ok': NullOk,
        'domain_schema': DomainSchema or None,
        'domain_name': DomainName or None,
        'annotations': Annotations or None,
    }
    if DataType in (TNS_TYPE_ADT, TNS_TYPE_REF):
        # Object (ADT, #115) and REF (#119) columns carry the (referenced) type
        # identity here; keep it so the row decoder can look up the attribute
        # layout / label the REF. Names are plain ASCII identifiers.
        Col['type_oid'] = TypeOid
        Col['type_schema'] = (
            TypeSchema.decode('ascii', 'replace') or None if TypeSchema else None
        )
        Col['type_name'] = (
            TypeName.decode('ascii', 'replace') or None if TypeName else None
        )
    return (Col, Rest)


def decode_token_iov(Data: bytes, Acc: tuple) -> tuple:
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
    OutPositions = [I for I, D in enumerate(Directions) if D != TNS_BIND_DIR_INPUT]
    if OutPositions:
        Rows = Rows + [
            {
                'out_positions': OutPositions,
                'out_values': OutValues,
                'directions': Directions,
            }
        ]
    return decode_packet(Rest, (Cursor, RowFormat, Rows))


def _is_refcursor_bind(Bind: object) -> bool:
    if isinstance(Bind, Var):
        return Bind.dbtype.tns_type == TNS_TYPE_REFCURSOR
    return isinstance(Bind, cursor)


def _read_iov(
    Data: bytes, Binds: list | None = None
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
    Rest = Data[1:]  # consume IOV token
    Rest = Rest[1:]  # skip flag (ub1)
    (NumRequests, Rest) = decode_ub4(Rest)
    (NumIters, Rest) = decode_ub4(Rest)
    NumBinds = NumIters * 256 + NumRequests
    (_, Rest) = decode_ub4(Rest)  # num iters this time
    (_, Rest) = decode_ub4(Rest)  # uac buffer length
    (BvLen, Rest) = decode_ub4(Rest)  # fast-fetch bit vector
    if BvLen > 0:
        Rest = Rest[BvLen:]
    (RidLen, Rest) = decode_ub4(Rest)  # rowid
    if RidLen > 0:
        Rest = Rest[RidLen:]
    Directions = [Rest[I] for I in range(NumBinds)]
    Rest = Rest[NumBinds:]
    HasOut = any(D != TNS_BIND_DIR_INPUT for D in Directions)
    OutValues: list = []
    if HasOut and Rest and Rest[0] == TTI_RXD:
        Rest = Rest[1:]  # consume RXD token
        for Idx, D in enumerate(Directions):
            if D == TNS_BIND_DIR_INPUT:
                continue
            Bind = Binds[Idx] if Binds and Idx < len(Binds) else None
            if _is_refcursor_bind(Bind):
                (Value, Rest) = _read_refcursor_out(Rest)
                OutValues.append(Value)
            elif Bind is not None and getattr(Bind, 'is_array', False):
                # Associative-array OUT (#122): a ub4 element count, then each
                # element as a DALC value + indicator. Kept as a list of raw
                # element bytes; the cursor decodes them by the Var's type.
                (Count, Rest) = decode_ub4(Rest)
                Elements = []
                for _ in range(Count):
                    (Val, Rest) = decode_dalc(Rest)
                    (_, Rest) = decode_ub4(Rest)  # per-element return code
                    Elements.append(b'' if Val == [] else bytes(Val))
                OutValues.append({'_array': True, 'values': Elements})
            else:
                (Val, Rest) = decode_dalc(Rest)
                # The per-value return code is a variable-length integer, not a
                # fixed byte: a non-NULL value's code is ub4(0) = one 0x00 byte,
                # but a NULL value's is ub4(-1) = 0x81 0x01 (two bytes). Skipping
                # a fixed byte desynced the decoder on a NULL OUT bind.
                (_, Rest) = decode_ub4(Rest)
                OutValues.append(b'' if Val == [] else bytes(Val))
    return (Directions, OutValues, Rest)


def _read_refcursor_out(Rest: bytes) -> tuple[dict, bytes]:
    # A REF CURSOR OUT value: a 1-byte length, then an inline describe (max row
    # size, num columns, the same per-column metadata as a DCB), then the
    # nested cursor id (ub2) and a 1-byte indicator. Mirrors oracledb's
    # _create_cursor_from_describe; byte layout verified against XE 11g.
    Rest = Rest[1:]  # skip_ub1 (length)
    (_, Rest) = decode_ub4(Rest)  # max row size
    (NumCols, Rest) = decode_ub4(Rest)
    if NumCols > 0:
        Rest = Rest[1:]  # reserved byte
    Columns = []
    for _ in range(NumCols):
        (Col, Rest) = _decode_dcb_column(Rest)
        Columns.append(Col)
    Rest = _skip_bytes_with_length(Rest)  # current date
    for _ in range(4):  # dcbflag / mdbz / mnpr / mxpr
        (_, Rest) = decode_ub4(Rest)
    if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_11_2:
        # dcbqcky (query-cache key) is an 11g addition; a 10g (field version 4)
        # nested-cursor describe ends after the four ub4 flags. Skipping a
        # phantom one here consumes the cursor id and desyncs the IOV decode of
        # a REF CURSOR OUT bind (#84) — same pre-11g gap as decode_token_dcb.
        Rest = _skip_bytes_with_length(Rest)  # dcbqcky
    (CursorId, Rest) = decode_ub4(Rest)
    Rest = Rest[1:]  # per-value indicator byte
    return ({'_refcursor': True, 'cursor_id': CursorId, 'row_format': Columns}, Rest)


def decode_token_lob(Data: bytes, Acc: tuple) -> tuple:
    # Defensive no-op for a TTI_LOB token seen in the general decode path. Real
    # LOB content is read by the dedicated _read_lob_response loop (see
    # lob_read), which walks TTI_LOB / RPA / OER itself — it doesn't route
    # through here.
    logger.debug('decode_token_lob: ignored (handled in _read_lob_response)')
    return (True, Acc)


def decode_token_net(Data: bytes, Acc: tuple) -> None:
    pass


def _read_batch_ub4_array(Rest: bytes) -> tuple[list, bytes]:
    # An array-DML batch field (#18): a ub4 count, then a DALC blob packing
    # that many ub4 values back-to-back. Returns the values and the remaining
    # bytes. Used for the batch-error code and row-offset arrays.
    (Count, Rest) = decode_ub4(Rest)
    if Count <= 0:
        return ([], Rest)
    (Blob, Rest) = decode_dalc(Rest)
    Buf = bytes(Blob) if not isinstance(Blob, list) else b''
    Values = []
    for _ in range(Count):
        (Value, Buf) = decode_ub4(Buf)
        Values.append(Value)
    return (Values, Rest)


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
    # Array-DML row counts threaded in by decode_token_rpa_piggyback (the RPA
    # carrying them precedes this OER); None for a normal execute (#18).
    RowCounts = Acc[4] if len(Acc) > 4 else None
    Rest = Data[1:]  # consume the OER token
    (CallStatus, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)  # end-to-end seq#
    # In 11g the "current row number" field doubles as the DML affected-row
    # count: UPDATE/DELETE/INSERT set it to the number of rows touched by
    # the call. 12c+ moved the rowcount to a separate ub8 at the end of the
    # OER, but we don't have that here.
    (RowCount, Rest) = decode_ub4(Rest)
    (ErrCode, Rest) = decode_ub4(Rest)  # ORA-NNNN error number
    (_, Rest) = decode_ub4(Rest)  # array elem error #1
    (_, Rest) = decode_ub4(Rest)  # array elem error #2
    (CursorId, Rest) = decode_ub4(Rest)  # current cursor id
    (_, Rest) = decode_ub4(Rest)  # error position
    Rest = Rest[6:]  # 6 single-byte fields:
    #   sql_type, fatal,
    #   flags, user_cursor_opts,
    #   upi_param, warn_flags
    # rowid of the (last) row the statement touched — same physical-rowid
    # layout as a ROWID column (see _read_rowid_column): data object number,
    # relative file number, an unused byte, block number, slot number.
    (RowidObj, Rest) = decode_ub4(Rest)  # data object number
    (RowidFile, Rest) = decode_ub4(Rest)  # relative file number
    Rest = Rest[1:]  # rowid reserved byte
    (RowidBlock, Rest) = decode_ub4(Rest)  # block number
    (RowidSlot, Rest) = decode_ub4(Rest)  # slot number
    (_, Rest) = decode_ub4(Rest)  # os error
    Rest = Rest[2:]  # statement #, call #
    (_, Rest) = decode_ub4(Rest)  # padding (ub2)
    (_, Rest) = decode_ub4(Rest)  # successful iterations
    #   (always 1 for a
    #   single non-array
    #   execute on 11g — the
    #   real DML rowcount is
    #   the "current row
    #   number" field above)
    Rest = _skip_bytes_with_length(Rest)  # oerrdd (logical rowid)
    # Batch error code / offset / message arrays (array-DML `batcherrors`
    # mode, #18). For plain statements all three counts are zero and the loops
    # never run. When set, the three arrays line up by position: error i hit
    # row `BatchOffsets[i]` with ORA-`BatchCodes[i]` and text `BatchMessages[i]`.
    # Batch error code / offset / message arrays (array-DML `batcherrors`
    # mode, #18). For plain statements all three counts are zero and the loops
    # never run. Layout (reverse-engineered against a 21c capture): each of the
    # code and offset arrays is `ub4 count | DALC blob`, where the blob packs
    # the count ub4 values (the DALC is the 0xFE chunked form once it grows).
    # The message array is `ub4 count | ub1 indicator | count × (ub4-prefixed
    # string + 2-byte trailer)`. Error i hit row BatchOffsets[i] with
    # ORA-BatchCodes[i] and text BatchMessages[i].
    (BatchCodes, Rest) = _read_batch_ub4_array(Rest)
    (BatchOffsets, Rest) = _read_batch_ub4_array(Rest)
    BatchMessages: list = []
    (NumBatchMessages, Rest) = decode_ub4(Rest)
    if NumBatchMessages > 0:
        Rest = Rest[1:]  # indicator byte
        for _ in range(NumBatchMessages):
            (MsgBytes, Rest) = _read_str_with_length(Rest)
            Rest = Rest[2:]  # 2-byte trailer
            BatchMessages.append(
                bytes(MsgBytes).decode('utf-8', errors='replace').rstrip()
            )
    BatchErrors = [
        {
            'offset': BatchOffsets[I] if I < len(BatchOffsets) else None,
            'code': BatchCodes[I] if I < len(BatchCodes) else None,
            'message': BatchMessages[I] if I < len(BatchMessages) else None,
        }
        for I in range(max(len(BatchOffsets), len(BatchCodes), len(BatchMessages)))
    ]
    # On 11g the trailing message DALC comes right here. 12c+ inserts the
    # extended-precision error number (ub4) and rowcount (ub8) ahead of it, and
    # 20.1+ adds a ub4 sql type + ub4 server checksum (oracledb
    # _process_error_info). Skip them so the message DALC stays aligned.
    FieldVersion = _DECODE_FIELD_VERSION.get()
    if FieldVersion >= 7:  # FIELD_VERSION_12_1
        (_, Rest) = decode_ub4(Rest)  # extended error number
        (_, Rest) = decode_ub4(Rest)  # extended rowcount (ub8)
        if FieldVersion >= 14:  # FIELD_VERSION_20_1
            (_, Rest) = decode_ub4(Rest)  # sql type
            (_, Rest) = decode_ub4(Rest)  # server checksum
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
        from seerdb.common.types import rowid_to_string

        Rowid = rowid_to_string(RowidObj, RowidFile, RowidBlock, RowidSlot)
    RetFormat = (RowCount, RowFormat)
    return (
        CallStatus,
        ErrCode,
        CursorId,
        RetFormat,
        Rows,
        Message,
        Rowid,
        BatchErrors,
        RowCounts,
    )


def decode_lobops_oer(Packet: bytes, FieldVersion: int) -> tuple[int, str | None]:
    # Pull the (error code, message) out of a content-free TTI_LOBOPS response
    # (WRITE / temp ops): TTI_RPA (updated locator + amount) optionally followed
    # by a trailing charset, then TTI_OER. The RPA's locator is binary and may
    # contain a 0x04 byte, so skip past it (using its ub2 length) before
    # scanning for the OER token — otherwise the scan can false-match inside the
    # locator. The OER call status is NOT fixed (1 for a standalone op, 5 right
    # after a PL/SQL call), so match the token + a valid ub4 length only, never
    # a specific status value.
    _DECODE_FIELD_VERSION.set(FieldVersion)
    Pos = 0
    if Packet and Packet[0] == TTI_RPA and len(Packet) >= 3:
        Pos = 3 + ((Packet[1] << 8) | Packet[2])  # skip ub2-prefixed locator
    while Pos < len(Packet) - 1:
        if Packet[Pos] == TTI_OER and 1 <= Packet[Pos + 1] <= 4:
            Result = decode_token_oer(Packet[Pos:], (None, None, []))
            return (Result[1], Result[5] if len(Result) > 5 else None)
        Pos += 1
    return (0, None)


def decode_token_oac(Data: bytes, Acc: tuple) -> tuple[int, int, int, int, bytes]:
    (DataType, Flg, Pre) = struct.unpack('>BBB', Data[:3])
    (DataScale, R0) = decode_ub4(Data[3:])
    (MaxDataLength, R1) = decode_ub4(R0)
    (Mal, R2) = decode_ub4(R1)
    (Fl2, R3) = decode_ub4(R2)
    (ToId, R4) = decode_dalc(R3)
    (VSN, R5) = decode_ub4(R4)
    (Charset, R6) = decode_ub4(R5)
    (Mxlc, R7) = decode_ub4(R6[1:])  # R6[0] is the csfrm byte — skipped
    return (DataType, MaxDataLength, DataScale, Charset, R7)


def decode_token_rpa(Data: bytes, Acc: tuple) -> tuple:
    (Num, Rest0) = decode_ub4(Data)
    Flags: dict = {}
    (KVs, Rest1) = decode_kv(Rest0, Num, [], Flags)
    SessKey = dict(KVs).get(b'AUTH_SESSKEY')
    Salt = dict(KVs).get(b'AUTH_VFR_DATA')
    DerivedSalt = dict(KVs).get(b'AUTH_PBKDF2_CSK_SALT')
    Resp = dict(KVs).get(b'AUTH_SVR_RESPONSE')
    Value = dict(KVs).get(b'AUTH_VERSION_NO')
    # An auth *result* carries either the server proof (O5LOGON) or — for token
    # auth (#125), which has no ConnKey and no proof — just the version + session
    # id with no session-key challenge. A *challenge* always carries AUTH_SESSKEY.
    if Resp or (SessKey is None and Value is not None):
        # Keep the full packed version number; the connection decodes the major
        # release (>> 24) for its protocol gate and the full dotted string for
        # the `version` property.
        Ver = 0 if Value is None else int(Value)
        SessId = dict(KVs).get(b'AUTH_SESSION_ID')
        return (TTI_AUTH, Resp, Ver, SessId)
    else:
        # The 256-bit scheme carries the server's PBKDF2 iteration counts; the
        # client must derive the key with these, not hardcoded defaults (#309).
        # Absent (10g/11g) → None, and the crypto falls back to the defaults.
        VgenRaw = dict(KVs).get(b'AUTH_PBKDF2_VGEN_COUNT')
        SderRaw = dict(KVs).get(b'AUTH_PBKDF2_SDER_COUNT')
        VgenCount = int(VgenRaw) if VgenRaw else None
        SderCount = int(SderRaw) if SderRaw else None
        # The AUTH_VFR_DATA flag names the verifier type (SHA-1 vs SHA-2 vs
        # legacy) — needed to pick the right key schedule on a modern server for
        # a pre-SHA-2 account (#311).
        VerifierType = Flags.get(b'AUTH_VFR_DATA')
        return (
            TTI_SESS,
            SessKey,
            Salt,
            DerivedSalt,
            VgenCount,
            SderCount,
            VerifierType,
        )


def decode_token_pro(Data: bytes) -> dict:
    """Decode a TTI_PRO (protocol negotiation) server response.

    Returns the server's TTC protocol version byte, banner, and the two
    length-prefixed capability arrays (compile-time TNS_CCAP_* and runtime
    TNS_RCAP_*). `Data` starts at the message-type byte (== TTI_PRO). The
    field version the server advertises is `compile_caps[CCAP_FIELD_VERSION]`;
    the connection negotiates the effective version as min(client, server).
    Layout mirrors python-oracledb's protocol.pyx (docs/PROTOCOL.md §4.1)."""
    Off = 1  # skip the message-type byte
    ServerVersion = Data[Off]
    Off += 2  # version byte + a trailing zero
    End = Data.index(0, Off)  # NUL-terminated banner
    Banner = Data[Off:End]
    Off = End + 1
    Off += 2  # charset_id (ub2 LE)
    Off += 1  # server flags
    NumElem = int.from_bytes(Data[Off : Off + 2], 'little')
    Off += 2 + NumElem * 5  # skip the charset-element array
    FdoLen = int.from_bytes(Data[Off : Off + 2], 'big')
    Off += 2 + FdoLen  # skip the FDO blob
    CcLen = Data[Off]
    Off += 1
    CompileCaps = Data[Off : Off + CcLen]
    Off += CcLen
    RcLen = Data[Off]
    Off += 1
    RuntimeCaps = Data[Off : Off + RcLen]
    return {
        'server_version': ServerVersion,
        'banner': Banner,
        'compile_caps': CompileCaps,
        'runtime_caps': RuntimeCaps,
    }


_KNOWN_TTI_TOKENS = frozenset(
    (
        TTI_OER,
        TTI_RXH,
        TTI_RXD,
        TTI_RPA,
        TTI_STA,
        TTI_IOV,
        TTI_UDS,
        TTI_OAC,
        TTI_LOB,
        TTI_WRN,
        TTI_DCB,
        TTI_FOB,
        TTI_BVC,
    )
)


def decode_token_server_piggyback(Data: bytes, Acc: tuple) -> tuple:
    # Server-side piggyback (#130): a session-state block the server prepends to
    # a response. DRCP-pooled sessions carry SESS_RET (the assigned session id /
    # serial + any session-state key/value pairs) and OS_PID_MTS; consume it
    # byte-for-byte (the values are not needed) and continue with the rest of the
    # response. Mirrors python-oracledb _process_server_side_piggyback. ub2/ub4
    # are the variable-length form (decode_ub4); skip_ub1 is one raw byte;
    # skip_bytes is a single-byte/0xFE-chunked value (decode_dalc).
    Rest = Data[1:]
    Opcode = Rest[0]
    Rest = Rest[1:]
    if Opcode == TNS_SERVER_PIGGYBACK_SESS_RET:
        (_, Rest) = decode_ub4(Rest)  # number of DTYs (ub2)
        Rest = Rest[1:]  # length of DTYs (ub1)
        (NumElements, Rest) = decode_ub4(Rest)  # number of pairs (ub2)
        if NumElements > 0:
            Rest = Rest[1:]  # skip_ub1
            for _ in range(NumElements):
                (KeyLen, Rest) = decode_ub4(Rest)
                if KeyLen > 0:
                    (_, Rest) = decode_dalc(Rest)
                (ValLen, Rest) = decode_ub4(Rest)
                if ValLen > 0:
                    (_, Rest) = decode_dalc(Rest)
                (_, Rest) = decode_ub4(Rest)  # pair flags (ub2)
        (_, Rest) = decode_ub4(Rest)  # session flags (ub4)
        (_, Rest) = decode_ub4(Rest)  # session id (ub4)
        (_, Rest) = decode_ub4(Rest)  # serial number (ub2)
    elif Opcode == TNS_SERVER_PIGGYBACK_OS_PID_MTS:
        (_, Rest) = decode_ub4(Rest)  # ub2
        (_, Rest) = decode_dalc(Rest)  # pid bytes
    elif Opcode == TNS_SERVER_PIGGYBACK_SYNC:
        # Sessionless transactions (#133): the server reports txn-id sync state
        # as keyword-value pairs (keyword 201 = transaction id) piggybacked on
        # the next call response while a sessionless txn is active. seerdb
        # tracks the active flag client-side, so the pairs are only consumed
        # byte-for-byte here. Each pair = ub2 text-len + dalc / ub2 binary-len +
        # dalc / ub2 keyword-num, framed like the SESS_RET pair loop.
        (_, Rest) = decode_ub4(Rest)  # number of DTYs (ub2)
        Rest = Rest[1:]  # length of DTYs (ub1)
        (NumElements, Rest) = decode_ub4(Rest)  # number of pairs (ub2)
        Rest = Rest[1:]  # length (ub1)
        for _ in range(NumElements):
            (TextLen, Rest) = decode_ub4(Rest)  # text value len (ub2)
            if TextLen > 0:
                (_, Rest) = decode_dalc(Rest)
            (BinLen, Rest) = decode_ub4(Rest)  # binary value len (ub2)
            if BinLen > 0:
                (_, Rest) = decode_dalc(Rest)
            (_, Rest) = decode_ub4(Rest)  # keyword num (ub2)
        (_, Rest) = decode_ub4(Rest)  # overall flags (ub4)
    elif Opcode == TNS_SERVER_PIGGYBACK_LTXID:
        (_, Rest) = decode_dalc(Rest)  # logical transaction id
    elif Opcode in (
        TNS_SERVER_PIGGYBACK_QUERY_CACHE_INVALIDATION,
        TNS_SERVER_PIGGYBACK_TRACE_EVENT,
    ):
        pass  # no body
    else:
        raise Exception('Unhandled server-side piggyback opcode', Opcode, Data)
    return decode_packet(Rest, Acc)


def decode_token_rpa_piggyback(Data: bytes, Acc: tuple) -> tuple:
    # Walks past a server-side session-state piggyback so the next decode_packet
    # call lands on the real status token (OER). The block layout is opaque
    # enough that empirically what works is: read Num, consume that many
    # ub4-encoded fields, skip trailing alignment zeros, then continue.
    Rest = Data[1:]
    try:
        (Num, Rest) = decode_ub4(Rest)
    except IndexError:
        return (True, Acc)
    # On fv2 (9i) Num over-counts and the params end at the real status token, so
    # stop early on a known token byte. From fv4 up Num is exact, and a scrollable
    # cursor's position parameter has a value whose length byte (0x04) collides
    # with the OER token — so there we must consume exactly Num and not break on a
    # token-valued param byte, or the OER decodes off by those bytes (#181).
    BreakOnToken = _DECODE_FIELD_VERSION.get() < FIELD_VERSION_10_2
    for _ in range(max(Num, 0)):
        if not Rest or (BreakOnToken and Rest[0] in _KNOWN_TTI_TOKENS):
            break
        try:
            (_, Rest) = decode_ub4(Rest)
        except IndexError:
            return (True, Acc)
    while Rest and Rest[0] == 0:
        Rest = Rest[1:]
    # Array-DML row counts (#18): when the execute requested arraydmlrowcounts
    # the server appends a `ub4 count | count×ub4` block here, between the RPA
    # body and the trailing OER — the per-iteration affected-row counts. Without
    # it the RPA always ends on a known TTI token (the OER), so a non-token byte
    # at this point is the row-count block. Pull it out and stash it on Acc so
    # decode_token_oer can fold it into the result; the surrounding RPA fields
    # stay opaque as before.
    if _DECODE_DML_ROWCOUNTS.get() and Rest and Rest[0] not in _KNOWN_TTI_TOKENS:
        try:
            (Count, R2) = decode_ub4(Rest)
            Counts = []
            for _ in range(Count):
                (C, R2) = decode_ub4(R2)
                Counts.append(C)
        except IndexError:
            # Speculative decode: if reading the count/values runs off the end of
            # the buffer this wasn't a row-count block after all — leave Rest/Acc
            # untouched (the `else` only commits R2 on a clean parse).
            pass
        else:
            Rest = R2
            Acc = tuple(Acc) + (Counts,)
    if Rest:
        return decode_packet(Rest, Acc)
    return (True, Acc)


def decode_token_uds(Data: bytes, Acc: tuple) -> tuple:
    # User describe information
    # Contains OAC descriptor for a single column
    (Cursor, RowFormat, Rows) = Acc[:3]
    (DataType, MaxDataLength, DataScale, Charset, Rest) = decode_token_oac(Data[1:], ())
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


# A native JSON column (21c+, #30) is delivered exactly like a BLOB: the RXD
# carries a LOB locator and the OSON image comes back over TTI_LOBOPS. We read
# it through the same locator path and decode the OSON in `LOB.read()`. A native
# VECTOR column (23ai+, #55) works the same way — locator + binary image.
_LOB_DATA_TYPES = frozenset(
    (TNS_TYPE_CLOB, TNS_TYPE_BLOB, TNS_TYPE_BFILE, TNS_TYPE_JSON, TNS_TYPE_VECTOR)
)
_ROWID_DATA_TYPES = frozenset((TNS_TYPE_RID,))
_UROWID_DATA_TYPES = frozenset((TNS_TYPE_UROWID,))
_LONG_DATA_TYPES = frozenset((TNS_TYPE_LONG, TNS_TYPE_LONGRAW))


def decode_token_rxd(Data: bytes, Acc: tuple) -> tuple:
    Val: Any  # reused per column, heterogeneous
    # Row data (section 6.2). Each column value is normally a DALC blob whose
    # raw bytes we hand to seerdb.common.types.decode_value, which dispatches on the
    # column's TNS data type from the describe-info block.
    #
    # LOB columns are special: instead of a single DALC they carry a small
    # length-prefixed locator block (`_read_lob_column`). The locator and
    # any inline content stay opaque for now — surfaced to the caller as an
    # seerdb.common.lob.LOB object — until the LOB-content extraction work lands.
    #
    # If a BVC token preceded this RXD, Acc carries a bit vector: a set bit
    # means "this column is in the RXD"; an unset bit means "reuse the
    # previous row's value". The bit vector applies to a single RXD and is
    # cleared from Acc on the way out.
    from seerdb.common.lob import LOB
    from seerdb.common.types import decode_value

    (Cursor, RowFormat, Rows, *Extra) = Acc
    BitVec = Extra[0] if Extra else None
    Rest = Data[1:]
    ReturnPositions = _DECODE_RETURN_BINDS.get()
    if ReturnPositions:
        # DML RETURNING ... INTO (#120): this RXD is out-bind return data, not
        # query rows. Per return bind: ub4 num_rows, then per affected row a
        # length-prefixed value + an sb4 truncation length (discarded). Keep the
        # raw value bytes; the cursor decodes them by each Var's type. Surfaced
        # as a record the cursor maps onto its return Vars (one list per bind).
        ReturnValues = []
        for _ in ReturnPositions:
            (NumRows, Rest) = decode_ub4(Rest)
            Vals = []
            for _Row in range(NumRows):
                (Val, Rest) = decode_dalc(Rest)
                (_, Rest) = decode_ub4(Rest)  # sb4 actual length (trunc)
                Vals.append(Val)
            ReturnValues.append(Vals)
        Record = {
            'return_positions': list(ReturnPositions),
            'return_values': ReturnValues,
        }
        return decode_packet(Rest, (Cursor, RowFormat, Rows + [Record]))
    Row = []
    if RowFormat:
        # Reused (bit-unset) columns copy the previous row. Within a response
        # that's the last accumulated row; for the first row of a scroll
        # re-execute it's the prior batch's last row, seeded via _DECODE_PREV_ROW
        # (#181) since duplicate detection is otherwise per-response.
        PrevRow = Rows[-1] if Rows else _DECODE_PREV_ROW.get()
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
            if DataType == TNS_TYPE_ADT:
                (Val, Rest) = _read_object_column(Rest, Col)
                Row.append(Val)
                continue
            (Val, Rest) = decode_dalc(Rest)
            Row.append(decode_value(Col, Val))
    return decode_packet(Rest, (Cursor, RowFormat, Rows + [Row]))


def _read_lob_column(Rest: bytes) -> tuple[bytes | None, bytes]:
    # LOB column layout in RXD (Oracle 11g):
    #
    #   ub1 0x00              → NULL LOB; total column size = 1 byte.
    #   ub4 num_bytes         → otherwise the size of the locator block.
    #   DALC locator block    → the LOB locator + any inline content section.
    #                           This is exactly what the server expects back in
    #                           TTI_LOBOPS — verified by diffing against
    #                           sqlplus's LOBOPS request locator bytes.
    #
    # The locator block is a DALC (§12.2): a single length-prefixed chunk while
    # the block stays under 254 bytes, or the 0xFE chunked form (length-prefixed
    # sub-chunks terminated by a zero length) at 254 bytes and up. A block grows
    # past 254 bytes once the LOB's content is woven inline into the locator —
    # which happens for medium CLOBs, and for NCLOBs sooner because their inline
    # content is UTF-16BE (two bytes per character). The old code assumed a
    # 1-byte size echo followed by num_bytes raw bytes; that only matched the
    # single-chunk case, so the chunked form was mis-read and the leftover
    # content bytes were then fed to decode_packet as bogus tokens (#37).
    if not Rest:
        return (None, Rest)
    if Rest[0] == 0x00:
        return (None, Rest[1:])
    (NumBytes, Body) = decode_ub4(Rest)
    if NumBytes <= 0 or not Body:
        # Defensive: malformed or unexpected layout. Surface what we have
        # rather than overrunning the buffer.
        return (bytes(Body), b'')
    (Locator, Tail) = decode_dalc(Body)
    if isinstance(Locator, list):  # 0x00 / 0xFF DALC → empty / null
        return (None, Tail)
    return (bytes(Locator), Tail)


def _read_rowid_column(Rest: bytes) -> tuple[str | None, bytes]:
    # ROWID (TNS type 11) in RXD: a 1-byte present indicator (the size the
    # server reserved; 0 / 0xff means NULL) followed by a structured physical
    # rowid -- data object (ub4), relative file (ub2), an unused ub1, block
    # (ub4) and slot (ub2). Mirrors oracledb's read_rowid; the byte counts and
    # the base64 rendering were verified against ROWIDTOCHAR on a live XE row.
    from seerdb.common.types import rowid_to_string

    if not Rest:
        return (None, Rest)
    Indicator = Rest[0]
    Rest = Rest[1:]
    if Indicator in (0, 0xFF):
        return (None, Rest)
    (Obj, Rest) = decode_ub4(Rest)
    (File, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)  # unused ub1
    (Block, Rest) = decode_ub4(Rest)
    (Slot, Rest) = decode_ub4(Rest)
    return (rowid_to_string(Obj, File, Block, Slot), Rest)


def _read_urowid_column(Rest: bytes) -> tuple[str | None, bytes]:
    # UROWID (universal/logical rowid, TNS type 208 -- e.g. an index-organized
    # table's rowid). Same RXD framing as a LOB column: ub4 num_bytes, a 1-byte
    # length echo, then num_bytes raw rowid bytes (a leading type tag + the
    # rowid body). Rendered as the "*"-prefixed base64 form. Verified against a
    # live XE IOT row vs the SELECT ROWID text.
    from seerdb.common.types import urowid_to_string

    if not Rest:
        return (None, Rest)
    (NumBytes, Rest) = decode_ub4(Rest)
    if NumBytes <= 0:
        return (None, Rest)
    Rest = Rest[1:]  # 1-byte length echo
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
        Chunks = b''
        if _DECODE_FIELD_VERSION.get() >= 8:  # FIELD_VERSION_12_2
            # 12c+ prefixes each chunk with a ub4 length (zero-length terminator)
            # rather than 11g's single length byte.
            while Rest:
                (ChunkLen, Rest) = decode_ub4(Rest)
                if ChunkLen == 0:
                    break
                Chunks += bytes(Rest[:ChunkLen])
                Rest = Rest[ChunkLen:]
        else:
            while Rest:
                ChunkLen = Rest[0]
                Rest = Rest[1:]
                if ChunkLen == 0:
                    break
                Chunks += bytes(Rest[:ChunkLen])
                Rest = Rest[ChunkLen:]
        Val = Chunks
    else:
        Val = bytes(Rest[1 : 1 + Marker])
        Rest = Rest[1 + Marker :]
    (_, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)
    return (Val, Rest)


def _read_object_column(Rest: bytes, Col: dict) -> tuple[object, bytes]:
    # SQL OBJECT (ADT, TNS type 109) value in RXD. The wire framing mirrors
    # python-oracledb's packet.pyx read_dbobject:
    #
    #   bytes_with_length   type OID (the type's 16-byte identity)
    #   bytes_with_length   object OID
    #   bytes_with_length   snapshot                         (skip)
    #   ub2                 version                          (skip)
    #   ub4                 image length (gate: 0 => NULL)
    #   ub2                 flags                            (skip)
    #   bytes               packed image (own length prefix)
    #
    # The image is a self-delimiting blob (its own 1-byte length, or the 0xFE
    # chunked form) -- NOT raw `num_bytes` bytes; num_bytes only gates whether
    # an image is present (read_dbobject skips read_bytes when it is 0). This
    # framing needs no attribute layout, so it keeps the row stream in sync
    # regardless of whether the type has been described yet. We hand back an
    # ObjectImage placeholder; the cursor decodes the image into a DbObject
    # once it has fetched the layout (#115). XMLType (type 109 with no object
    # type) is a separate path (#124).
    from seerdb.common.dbobject import ObjectImage

    (TypeOid, Rest) = _read_str_with_length(Rest)  # type OID
    (_, Rest) = _read_str_with_length(Rest)  # object OID
    Rest = _skip_bytes_with_length(Rest)  # snapshot
    (_, Rest) = decode_ub4(Rest)  # version (ub2)
    (NumBytes, Rest) = decode_ub4(Rest)  # image-present gate
    (_, Rest) = decode_ub4(Rest)  # flags (ub2)
    if NumBytes == 0:
        return (None, Rest)
    (Image, Rest) = _read_chunked_bytes(Rest)
    Oid = bytes(TypeOid) if not isinstance(TypeOid, list) else b''
    Placeholder = ObjectImage(
        Oid or Col.get('type_oid', b''),
        Col.get('type_schema'),
        Col.get('type_name'),
        Col.get('charset'),
        Image,
    )
    return (Placeholder, Rest)


def _bvc_bit_set(BitVec: bytes, Idx: int) -> bool:
    Byte = Idx // 8
    Bit = Idx % 8
    if Byte >= len(BitVec):
        return False
    return bool(BitVec[Byte] & (1 << Bit))


def decode_token_rxh(Data: bytes, Acc: tuple) -> tuple:
    # Row Transfer Header. Fields use Oracle's variable ub1/ub2/ub4 encoding
    # (1-byte length prefix + value bytes), not the fixed 2-byte big-endian
    # layout the older version of this decoder assumed. See python-oracledb's
    # _process_row_header.
    (Cursor, RowFormat, Rows) = Acc[:3]
    Rest = Data[2:]  # skip token + 1B flags
    (_, Rest) = decode_ub4(Rest)  # num requests
    (_, Rest) = decode_ub4(Rest)  # iteration number
    (_, Rest) = decode_ub4(Rest)  # num iters
    (_, Rest) = decode_ub4(Rest)  # buffer length
    (NumBytes, Rest) = decode_ub4(Rest)  # bit vector length
    BitVec = None
    if NumBytes > 0:
        # The row header can carry a column bit vector (oracledb's
        # _get_bit_vector): an unset bit means the column repeats the previous
        # row's value and carries no bytes in the following RXD. It must be
        # passed to the RXD decoder, not skipped — skipping it makes the RXD read
        # the next token as a column value and desync (a scroll re-execute that
        # repositions onto a row whose value equals the last one returned uses
        # this compression, e.g. LAST after fetching to EOF). #181.
        Rest = Rest[1:]  # skip repeated length
        BitVec = bytes(Rest[:NumBytes])
        Rest = Rest[NumBytes:]
    Rest = _skip_bytes_with_length(Rest)  # rxhrid
    Acc = (
        (Cursor, RowFormat, Rows)
        if BitVec is None
        else (Cursor, RowFormat, Rows, BitVec)
    )
    return decode_packet(Rest, Acc)


def decode_token_wrn(Data: bytes, Acc: tuple) -> tuple:
    # Warning message (section 3.1)
    # Skip the warning and continue processing
    logger.debug('decode_token_wrn: warning received')
    Rest = Data[1:]  # skip token byte
    (ErrNum, Rest) = decode_ub4(Rest)
    (RowCount, Rest) = decode_ub4(Rest)
    (RetCode, Rest) = decode_ub4(Rest)
    (WarnFlag, Rest) = decode_ub4(Rest)
    logger.debug(
        'decode_token_wrn: err=%s rows=%s ret=%s warn=%s',
        ErrNum,
        RowCount,
        RetCode,
        WarnFlag,
    )
    return decode_packet(Rest, Acc)


def _packet_header(Size: int, Type: int, Large: bool) -> bytes:
    # The 8-byte TNS packet header in the legacy (ub2 length + ub2 checksum) or
    # large-SDU (ub4 length, #155) layout. Type sits at byte 4 in both.
    if Large:
        return struct.pack('>IBBh', Size, Type, 0, 0)
    return struct.pack('>HhBBh', Size, 0, Type, 0, 0)


def encode_data_packet(Body: bytes, DataFlags: int, Large: bool = False) -> bytes:
    # A single TNS_DATA packet carrying explicit data flags. Request pipelining
    # (#158) sets BEGIN_PIPELINE (0x1000) on the first packet of a burst and
    # END_OF_REQUEST (0x0800) on each op packet — the ordinary encode_packet
    # path always writes 0 (or 0x0020 on an oversized fragment), so the
    # pipelined sender builds its packets here instead.
    return (
        _packet_header(len(Body) + 10, TNS_DATA, Large)
        + struct.pack('>H', DataFlags)
        + Body
    )


def encode_packet(
    Type: int, Data: bytes, Length: int, Large: bool = False
) -> tuple[bytes, bytes | None]:
    if Type == TNS_DATA:
        PacketSize = len(Data) + 10
        if PacketSize > Length:
            # Oversized request: split into SDU-sized DATA packets. Each
            # fragment is an ordinary DATA packet — 8-byte header + 2-byte data
            # flags + a (SDU - 10)-byte payload chunk — and the chunks
            # concatenate back into the message on the server. Non-final
            # fragments carry data flags 0x0020 (PROTOCOL.md §1.3); the final
            # one (built by the branch below) uses 0x0000. `send()` loops until
            # the rest is empty. (The old `>HhBBhBI` + trailing `0, 32` header
            # mis-encoded that 0x20 flag as a 5-byte tail and drew ORA-12592 /
            # ORA-01013 from the server — issue #8.)
            BodySize = Length - 10
            return (
                _packet_header(BodySize + 10, Type, Large)
                + struct.pack('>h', 0x0020)
                + Data[:BodySize],
                Data[BodySize:],
            )
        # The non-final fragment branch above carries data-flags 0x0020; the
        # final/whole packet uses 0x0000. The 2-byte data flags follow the
        # 8-byte header in both framing layouts.
        return (
            _packet_header(PacketSize, Type, Large) + struct.pack('>h', 0) + Data,
            None,
        )
    else:
        PacketSize = len(Data) + 8
        return (_packet_header(PacketSize, Type, Large) + Data, None)


def encode_dictionary(Dictionary: dict) -> bytes:
    # Auth dictionaries yield two values (data, conn_key); callers use
    # encode_dictionary_auth() directly for that, so this stays single-bytes.
    match Dictionary['type']:
        case DictionaryType.chgpwd:
            return encode_dictionary_chgpwd(Dictionary)
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
    # No case matched (the match has no value-less path); raising here rather
    # than via `case _` keeps every branch a value-return for flow analysis.
    raise Exception('unsupported dict type', Dictionary['type'])


##
## Supplementary functions
##


def encode_dictionary_auth(Dictionary: dict) -> tuple[bytes, bytes]:
    Tseq = Dictionary['seq']
    Sess = Dictionary['auth']['sess']
    Salt = Dictionary['auth']['salt']
    DerivedSalt = Dictionary['auth']['derived_salt']
    VgenCount = Dictionary['auth'].get('vgen_count')
    SderCount = Dictionary['auth'].get('sder_count')
    VerifierType = Dictionary['auth'].get('verifier_type')
    User = Dictionary['env']['user'].encode('utf-8')
    Pass = Dictionary['env']['password'].encode('utf-8')
    Role = Dictionary['env'].get('role', 0)
    Prelim = Dictionary['env'].get('prelim', 0)

    LogonMode = encode_sb4((Role * 32) | (Prelim * 128) | 1 | 256)
    (AuthPass, AuthSess, SpeedyKey, SpeedyKeyInd, ConnKey) = o5logon(
        Sess, Salt, DerivedSalt, User, Pass, VgenCount, SderCount, VerifierType
    )

    AuthPass = encode_kv(b'AUTH_PASSWORD', AuthPass.hex().upper().encode('utf-8'))

    # AUTH_PBKDF2_SPEEDY_KEY is hex-encoded like AUTH_PASSWORD / AUTH_SESSKEY
    # (the server expects the hex string, not the raw bytes — sending raw gives
    # ORA-03146 "invalid buffer length for TTC field"). 256-bit scheme only.
    PBKDF2 = (
        encode_kv(b'AUTH_PBKDF2_SPEEDY_KEY', SpeedyKey.hex().upper().encode('utf-8'))
        if SpeedyKeyInd != 0
        else b''
    )

    AuthSess = encode_kv(b'AUTH_SESSKEY', AuthSess.hex().upper().encode('utf-8'), 1)

    # Proxy authentication (#126): a `proxy_user[schema]` connect adds one auth
    # pair naming the target schema; the proxy user authenticates normally and
    # the server switches the session into the schema's context.
    ProxyUser = Dictionary['env'].get('proxy_user')
    ProxyKv = (
        encode_kv(b'PROXY_CLIENT_NAME', ProxyUser.encode('utf-8')) if ProxyUser else b''
    )
    ProxyInd = 1 if ProxyUser else 0

    # DRCP (#130): a connection class and/or session purity. When DRCP is used
    # but no purity was given, a standalone connection defaults to NEW (matching
    # python-oracledb). cclass -> AUTH_KPPL_CONN_CLASS, purity -> AUTH_KPPL_PURITY.
    CClass = Dictionary['env'].get('cclass')
    Purity = Dictionary['env'].get('purity', 0) or 0
    if (CClass or Purity) and Purity == 0:
        Purity = 1  # PURITY_NEW
    CClassKv = (
        encode_kv(b'AUTH_KPPL_CONN_CLASS', CClass.encode('utf-8')) if CClass else b''
    )
    PurityKv = (
        encode_kv(b'AUTH_KPPL_PURITY', str(Purity).encode('utf-8'), 1)
        if Purity
        else b''
    )
    DrcpInd = (1 if CClass else 0) + (1 if Purity else 0)
    DrcpKv = CClassKv + PurityKv

    # 12c+ length-prefixes the username (write_bytes_with_length), same as the
    # OSESSKEY phase; 11g sends it raw (read via the UserLen field). Sending the
    # raw form to 21c makes it read the first username byte as a length and
    # desync — surfaces as ORA-03120 (two-task conversion: integer overflow).
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)

    # At fv >= 18 (fast-auth / 23ai, #89) phase two follows python-oracledb
    # exactly: the username is NOT re-sent (has_user = 0, user length 0 — the
    # session is already established by OSESSKEY), and the OAUTH carries the
    # session-context pairs the server now requires. The legacy fv <= 17 path
    # re-sends the username and the minimal AUTH_PASSWORD/SESSKEY/SPEEDY_KEY set;
    # using either shape against the other desyncs the server's parse, surfacing
    # as ORA-03120 (two-task conversion: integer overflow). RE'd from an
    # oracledb-thin fv24 capture (docs/PROTOCOL.md §20).
    if FieldVersion > FIELD_VERSION_23_1:
        # Header replicates python-oracledb's fv24 phase two byte-for-byte: the
        # has-user pointer byte is 0 followed by an extra 0x01, the logon mode
        # gains 0x20000, and the username is still sent length-prefixed. RE'd from
        # an oracledb-thin fv24 capture (docs/PROTOCOL.md §20).
        Header = bytes([TTI_FUN, TTI_AUTH, Tseq, 0, 1])
        Mode = encode_sb4((Role * 32) | (Prelim * 128) | 1 | 256 | 0x20000)
        UserField = bytes([len(User)]) + User
        SessionKvs = _auth_session_kvs(Dictionary)
        NumPairs = 2 + SpeedyKeyInd + 5 + ProxyInd + DrcpInd
    else:
        # 12c+ length-prefixes the username (write_bytes_with_length); 11g sends
        # it raw (read via the UserLen field). Sending the raw form to 21c makes
        # it read the first username byte as a length and desync (ORA-03120).
        Header = bytes([TTI_FUN, TTI_AUTH, Tseq, 1])
        Mode = LogonMode
        UserField = (
            bytes([len(User)]) + User if FieldVersion >= FIELD_VERSION_12_1 else User
        )
        # Sync the session time zone to the client's UTC offset, the way oracledb
        # / OCI / sqlplus do (AUTH_ALTER_SESSION). Without it the session runs at
        # the server default, so CURRENT_TIMESTAMP / LOCALTIMESTAMP /
        # SESSIONTIMEZONE and TIMESTAMP WITH LOCAL TIME ZONE reflect the server's
        # zone, not the client's — a porting surprise (#307). Gated to 12c+: that
        # is where oracledb (thin, 12.1+) operates and the phase-two AUTH accepts
        # the extra pair; 10g / 11g have a stricter parse that desyncs on it, and
        # no oracledb reference to match. The fv > 17 fast-auth path already
        # carries this via _auth_session_kvs.
        if FieldVersion >= FIELD_VERSION_12_1:
            SessionKvs = encode_kv(b'AUTH_ALTER_SESSION', _local_tz_clause(), 1)
            NumPairs = 2 + SpeedyKeyInd + 1 + ProxyInd + DrcpInd
        else:
            SessionKvs = b''
            NumPairs = 2 + SpeedyKeyInd + ProxyInd + DrcpInd

    Data = (
        Header
        + encode_sb4(len(User))
        + Mode
        + bytes([1])
        + encode_sb4(NumPairs)
        + bytes([1, 1])
        + UserField
        + AuthPass
        + PBKDF2
        + AuthSess
        + SessionKvs
        + ProxyKv
        + DrcpKv
    )

    return (Data, ConnKey)


def encode_dictionary_token_auth(Dictionary: dict) -> bytes:
    """Build the token-auth AUTH message (#125).

    Token auth replaces the O5LOGON challenge/response entirely: there is no
    OSESSKEY, no session key, and no server proof. This is a single TTI_AUTH
    (func 0x73) message with no username, logon mode ``NoNewPass`` (0x1), and the
    key/value pairs carrying the token — ``AUTH_TOKEN`` always, plus
    ``AUTH_HEADER`` + ``AUTH_SIGNATURE`` for the OCI IAM (signed) variant — after
    the standard session-context pairs. RE'd from go-ora (MIT); the wire shape
    matches the ordinary AUTH header with the user fields zeroed.
    """
    Tseq = Dictionary['seq']
    Role = Dictionary['env'].get('role', 0)
    Prelim = Dictionary['env'].get('prelim', 0)
    # NoNewPass (0x1) only — no UserAndPass (0x100), since there is no password.
    Mode = encode_sb4((Role * 32) | (Prelim * 128) | 1)

    Pairs = [encode_kv(b'AUTH_TOKEN', Dictionary['token'].encode('utf-8'))]
    Header = Dictionary.get('token_header')
    Signature = Dictionary.get('token_signature')
    if Header is not None and Signature is not None:
        Pairs.append(encode_kv(b'AUTH_HEADER', Header.encode('utf-8')))
        Pairs.append(encode_kv(b'AUTH_SIGNATURE', Signature.encode('utf-8')))
    SessionKvs = _auth_session_kvs(Dictionary)  # 5 pairs (charset..connect-string)
    NumPairs = len(Pairs) + 5

    # No user: the has-user pointer byte is 0 and the user length is 0.
    HeaderBytes = bytes([TTI_FUN, TTI_AUTH, Tseq, 0]) + encode_sb4(0)
    return (
        HeaderBytes
        + Mode
        + bytes([1])
        + encode_sb4(NumPairs)
        + bytes([1, 1])
        + b''.join(Pairs)
        + SessionKvs
    )


# seerdb's advertised client version, packed the way python-oracledb encodes
# SESSION_CLIENT_VERSION: (major << 24) | (minor << 20) | (patch << 12). Keep the
# string in sync with pyproject.toml. (4.0.1 -> 67112960 in the reference capture.)
_CLIENT_VERSION = '2.2.0'


def _packed_client_version(Version: str) -> int:
    Parts = [int(p) for p in Version.split('.')[:3]] + [0, 0, 0]
    return (Parts[0] << 24) | (Parts[1] << 20) | (Parts[2] << 12)


def _local_tz_clause() -> bytes:
    # "ALTER SESSION SET TIME_ZONE='±hh:mm'" + NUL, matching the reference client:
    # the client pins the session time zone to its own UTC offset.
    Offset = datetime.datetime.now().astimezone().utcoffset() or datetime.timedelta(0)
    Total = int(Offset.total_seconds())
    Sign = '+' if Total >= 0 else '-'
    Hh, Mm = divmod(abs(Total) // 60, 60)
    return f"ALTER SESSION SET TIME_ZONE='{Sign}{Hh:02d}:{Mm:02d}'\x00".encode('utf-8')


def _auth_session_kvs(Dictionary: dict) -> bytes:
    """The session-context key/value pairs the OAUTH phase two must carry at
    fv >= 18 (#89): client charset, driver banner, packed version, the time-zone
    ALTER SESSION, and the connect descriptor."""
    Charset = struct.pack('<H', CharsetDict.get(Dictionary['req'], AL32UTF8_CHARSET))
    return (
        encode_kv(
            b'SESSION_CLIENT_CHARSET',
            str(int.from_bytes(Charset, 'little')).encode('utf-8'),
        )
        + encode_kv(
            b'SESSION_CLIENT_DRIVER_NAME',
            f'seerdb thn : {_CLIENT_VERSION}'.encode('utf-8'),
        )
        + encode_kv(
            b'SESSION_CLIENT_VERSION',
            str(_packed_client_version(_CLIENT_VERSION)).encode('utf-8'),
        )
        + encode_kv(b'AUTH_ALTER_SESSION', _local_tz_clause(), 1)
        + encode_kv(b'AUTH_CONNECT_STRING', encode_dictionary_description(Dictionary))
    )


def encode_dictionary_chgpwd(Dictionary: dict) -> bytes:
    # Password change (#21). Sent on an already-authenticated session: a single
    # TTI_AUTH call that reuses the session key from login (no fresh
    # AUTH_SESSKEY), carrying the current and new passwords. Reverse-engineered
    # from an oracledb-thin capture against 21c. Same shape as the login OAUTH
    # (encode_dictionary_auth) but:
    #   - logon mode 0x102 = WITH_PASSWORD(0x100) | CHANGE_PASSWORD(0x02), and
    #     crucially WITHOUT the LOGON(0x01) bit the login carries;
    #   - exactly two key/value pairs: AUTH_PASSWORD (current) and
    #     AUTH_NEWPASSWORD (new), both AES-CBC-encrypted with the login ConnKey;
    #   - no AUTH_SESSKEY / AUTH_PBKDF2_SPEEDY_KEY (the session already exists).
    Tseq = Dictionary['seq']
    User = Dictionary['env']['user'].encode('utf-8')
    ConnKey = Dictionary['auth']['conn_key']
    CurPass = Dictionary['auth']['old_password'].encode('utf-8')
    NewPass = Dictionary['auth']['new_password'].encode('utf-8')

    AuthPass = encode_kv(
        b'AUTH_PASSWORD',
        encrypt_password(ConnKey, CurPass).hex().upper().encode('utf-8'),
    )
    AuthNewPass = encode_kv(
        b'AUTH_NEWPASSWORD',
        encrypt_password(ConnKey, NewPass).hex().upper().encode('utf-8'),
    )

    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    # fv >= 18 (23ai, #89) needs the same header shape as the login phase two:
    # the extra leading pointer byte and the 0x20000 logon-mode bit (else the
    # server rejects the change with ORA-03120). See encode_dictionary_auth.
    if FieldVersion > FIELD_VERSION_23_1:
        Header = bytes([TTI_FUN, TTI_AUTH, Tseq, 0, 1])
        LogonMode = encode_sb4(0x102 | 0x20000)
    else:
        Header = bytes([TTI_FUN, TTI_AUTH, Tseq, 1])
        LogonMode = encode_sb4(0x102)
    UserField = (
        bytes([len(User)]) + User if FieldVersion >= FIELD_VERSION_12_1 else User
    )

    return (
        Header
        + encode_sb4(len(User))
        + LogonMode
        + bytes([1])
        + encode_sb4(2)
        + bytes([1, 1])
        + UserField
        + AuthPass
        + AuthNewPass
    )


def _fun_header(Token: int, Seq: int, FieldVersion: int, TokenNum: int = 0) -> bytes:
    # Header for a TTI function-call message. 23ai (fv > 17, #89) appends a
    # ub8 "token number" after the sequence number (oracledb's
    # _write_function_code at fv24) — present on every function message
    # (execute, fetch, commit/rollback, LOB ops, logoff, ...). Omitting it
    # desyncs the call: the server either rejects it (ORA-03146 / ORA-03120) or
    # never replies (read timeout). For an ordinary call the token is 0
    # (encode_sb4(0) == b"\x00", the historical single zero byte); request
    # pipelining (#132) numbers each piggybacked call 1..N so the server can tag
    # each response with a matching TOKEN (33) marker.
    if FieldVersion > FIELD_VERSION_23_1:
        return bytes([TTI_FUN, Token, Seq]) + encode_sb4(TokenNum)
    return bytes([TTI_FUN, Token, Seq])


def encode_pipeline_begin(
    Seq: int, FieldVersion: int, TokenNum: int, Mode: int
) -> bytes:
    # The begin-pipeline piggyback (#132): tells the server a pipelined burst is
    # starting and which error mode applies. It rides on the first pipelined
    # message (the caller sets the BEGIN_PIPELINE data flag on that packet) and
    # shares that message's token. Mirrors oracledb
    # _write_begin_pipeline_piggyback; byte-validated against a 23ai capture.
    Out = bytes([TTI_MSG_TYPE_PIGGYBACK, TNS_FUNC_PIPELINE_BEGIN, Seq])
    if FieldVersion > FIELD_VERSION_23_1:
        Out += encode_sb4(TokenNum)
    return Out + encode_sb4(0) + bytes([0]) + bytes([Mode])


def encode_pipeline_end(Seq: int, FieldVersion: int) -> bytes:
    # The PIPELINE_END (func 200) message closing a pipelined burst (#132).
    return _fun_header(TNS_FUNC_PIPELINE_END, Seq, FieldVersion) + encode_sb4(0)


def _e2e_header(Modified: bool, Value: bytes | None) -> bytes:
    # One end-to-end attribute's header: a pointer byte (1 if the attribute is
    # being set this flush, else 0) + a ub4 length of its value (0 when unset or
    # cleared). The value bytes themselves are appended later, in field order.
    if Modified:
        return bytes([1]) + encode_sb4(len(Value) if Value else 0)
    return bytes([0]) + encode_sb4(0)


def encode_close_cursors_piggyback(Seq: int, FieldVersion: int, Cursors: list) -> bytes:
    """Build the CLOSE_CURSORS (OCCA, func 105) piggyback that frees a batch of
    server cursors (#191). Rides in front of the next call's message; the server
    closes the listed cursors before processing that call. Mirrors oracledb's
    _write_close_cursors_piggyback — note the ub8 token at fv24, which the older
    encode_dictionary_pig path omitted (it was never exercised on 12c+)."""
    Out = bytes([TTI_MSG_TYPE_PIGGYBACK, TTI_OCCA, Seq])
    if FieldVersion > FIELD_VERSION_23_1:
        Out += encode_sb4(0)  # ub8 token (0)
    Out += bytes([1]) + encode_sb4(len(Cursors))  # pointer + count
    for C in Cursors:
        Out += encode_sb4(C)
    return Out


def encode_end_to_end_piggyback(Seq: int, FieldVersion: int, Attrs: dict) -> bytes:
    """Build the SET_END_TO_END_ATTR piggyback (#183, func 135) that updates the
    session's end-to-end application-tracing attributes. `Attrs` maps each name
    (client_identifier / module / action / client_info / dbop) to either its new
    str value or None (clear); only the keys present are flushed. The piggyback
    rides in front of the next call's message. Byte layout + field order mirror
    oracledb's _write_end_to_end_piggyback (validated against a 23ai capture)."""

    def enc(Name):
        return Attrs[Name].encode('utf-8') if Attrs.get(Name) is not None else None

    Mod = {
        Name: Name in Attrs
        for Name in ('client_identifier', 'module', 'action', 'client_info', 'dbop')
    }
    Val = {Name: enc(Name) for Name in Mod}
    Flags = 0
    if Mod['action']:
        Flags |= TNS_END_TO_END_ACTION
    if Mod['client_identifier']:
        Flags |= TNS_END_TO_END_CLIENT_IDENTIFIER
    if Mod['client_info']:
        Flags |= TNS_END_TO_END_CLIENT_INFO
    if Mod['module']:
        Flags |= TNS_END_TO_END_MODULE
    if Mod['dbop']:
        Flags |= TNS_END_TO_END_DBOP

    Out = bytes([TTI_MSG_TYPE_PIGGYBACK, TNS_FUNC_SET_END_TO_END_ATTR, Seq])
    if FieldVersion > FIELD_VERSION_23_1:
        Out += encode_sb4(0)  # ub8 token (0)
    Out += bytes([0, 0]) + encode_sb4(Flags)  # cidnam, cidser pointers; flags
    Out += _e2e_header(Mod['client_identifier'], Val['client_identifier'])
    Out += _e2e_header(Mod['module'], Val['module'])
    Out += _e2e_header(Mod['action'], Val['action'])
    Out += bytes([0]) + encode_sb4(0)  # cideci (unsupported)
    Out += bytes([0]) + encode_sb4(0)  # cidcct / cidecs (unsupported)
    Out += _e2e_header(Mod['client_info'], Val['client_info'])
    Out += bytes([0]) + encode_sb4(0)  # cidkstk (unsupported)
    Out += bytes([0]) + encode_sb4(0)  # cidktgt (unsupported)
    Out += _e2e_header(Mod['dbop'], Val['dbop'])
    # values, in field order, only those set to a non-None value
    for Name in ('client_identifier', 'module', 'action', 'client_info', 'dbop'):
        if Mod[Name] and Val[Name] is not None:
            Out += _bytes_with_length(Val[Name])
    return Out


def encode_dictionary_close(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    return _fun_header(TTI_LOGOFF, Tseq, FieldVersion)


# Env keys safe to include in a debug log. Deliberately an allow-list, NOT a
# deny-list: the connection `password` (and the changepassword `new_password`)
# is simply never read, so no secret value can flow into the logged copy. The
# whole `auth` sub-dict is dropped wholesale — it only ever holds secrets (the
# session key, salts, and the changepassword old/new passwords, #21).
_REDACT_ENV_SAFE = (
    'host',
    'port',
    'user',
    'sid',
    'service_name',
    'conn_state',
    'timeout',
    'autocommit',
    'fetch',
    'role',
    'charset',
    'prelim',
    'app_name',
)


def _redacted(Dictionary: dict) -> dict:
    # Return a copy safe to log. Secrets live in the env dict (connection
    # password) and the auth dict (changepassword passwords + session key);
    # neither secret value is ever read here, so they cannot reach a log.
    Safe = {k: v for k, v in Dictionary.items() if k not in ('env', 'auth')}
    Env = Dictionary.get('env')
    if isinstance(Env, dict):
        Safe['env'] = {k: Env[k] for k in _REDACT_ENV_SAFE if k in Env}
    if 'auth' in Dictionary:
        Safe['auth'] = '<redacted>'
    return Safe


def _tpc_xid_bytes(Xid) -> tuple | None:
    # (format_id, gtrid, bqual, xid_bytes) for a TPC Xid, or None. The wire xid
    # is gtrid + bqual zero-padded to a fixed 128 bytes (oracledb _write_message).
    if Xid is None:
        return None
    FormatId = Xid[0]
    Gtrid = Xid[1] if isinstance(Xid[1], (bytes, bytearray)) else Xid[1].encode()
    Bqual = Xid[2] if isinstance(Xid[2], (bytes, bytearray)) else Xid[2].encode()
    XidBytes = bytes(Gtrid) + bytes(Bqual) + bytes(128 - len(Gtrid) - len(Bqual))
    return (FormatId, bytes(Gtrid), bytes(Bqual), XidBytes)


def _tpc_xid_descriptor(Parts) -> bytes:
    # The format-id / gtrid-len / bqual-len / xid-pointer block shared by both
    # TPC messages (after the operation + context-pointer block).
    if Parts is not None:
        (FormatId, Gtrid, Bqual, XidBytes) = Parts
        return (
            encode_sb4(FormatId)
            + encode_sb4(len(Gtrid))
            + encode_sb4(len(Bqual))
            + bytes([1])
            + encode_sb4(len(XidBytes))
        )
    return encode_sb4(0) + encode_sb4(0) + encode_sb4(0) + bytes([0]) + encode_sb4(0)


def encode_tpc_switch(
    Seq: int,
    FieldVersion: int,
    Operation: int,
    Xid,
    Flags: int,
    Timeout: int,
    Context: bytes | None,
    AppValue: int = 0,
    InternalName: bytes | None = None,
    ExternalName: bytes | None = None,
) -> bytes:
    # TPC start (tpc_begin) / detach (tpc_end). Mirrors oracledb
    # TransactionSwitchMessage._write_message (#131).
    Parts = _tpc_xid_bytes(Xid)
    Out = _fun_header(TNS_FUNC_TPC_TXN_SWITCH, Seq, FieldVersion)
    Out += encode_sb4(Operation)
    if Context is not None:
        Out += bytes([1]) + encode_sb4(len(Context))
    else:
        Out += bytes([0]) + encode_sb4(0)
    Out += _tpc_xid_descriptor(Parts)
    Out += encode_sb4(Flags) + encode_sb4(Timeout)
    Out += bytes([1, 1, 1])  # ptrs: app value, return context, len
    Out += (
        bytes([1]) + encode_sb4(len(InternalName))
        if InternalName
        else bytes([0]) + encode_sb4(0)
    )
    Out += (
        bytes([1]) + encode_sb4(len(ExternalName))
        if ExternalName
        else bytes([0]) + encode_sb4(0)
    )
    if Context is not None:
        Out += Context
    if Parts is not None:
        Out += Parts[3]
    Out += encode_sb4(AppValue)
    if InternalName:
        Out += InternalName
    if ExternalName:
        Out += ExternalName
    return Out


def encode_tpc_change_state(
    Seq: int,
    FieldVersion: int,
    Operation: int,
    State: int,
    Xid,
    Flags: int,
    Context: bytes | None,
) -> bytes:
    # TPC prepare / commit / rollback / forget. Mirrors oracledb
    # TransactionChangeStateMessage._write_message (#131).
    Parts = _tpc_xid_bytes(Xid)
    Out = _fun_header(TNS_FUNC_TPC_TXN_CHANGE_STATE, Seq, FieldVersion)
    Out += encode_sb4(Operation)
    if Context is not None:
        Out += bytes([1]) + encode_sb4(len(Context))
    else:
        Out += bytes([0]) + encode_sb4(0)
    Out += _tpc_xid_descriptor(Parts)
    Out += encode_sb4(0)  # timeout
    Out += encode_sb4(State)
    Out += bytes([1])  # ptr (out state)
    Out += encode_sb4(Flags)
    if Context is not None:
        Out += Context
    if Parts is not None:
        Out += Parts[3]
    return Out


def encode_dictionary_description(Dictionary: dict) -> bytes:
    logger.debug('encode_dictionary_description: %s', _redacted(Dictionary))
    Hostname = socket.gethostname().encode('utf-8')
    User = Dictionary['env']['user'].encode('utf-8')
    Host = Dictionary['env'].get('host', DEFAULT_HOST).encode('utf-8')
    Port = str(Dictionary['env'].get('port', DEFAULT_PORT)).encode('utf-8')
    SID = Dictionary['env'].get('sid', DEFAULT_SID).encode('utf-8')
    ServiceName = Dictionary['env'].get('service_name', None)
    AppName = Dictionary['env'].get('app_name', 'seerdb').encode('utf-8')
    SslOpts = Dictionary['env'].get('ssl', None)
    Sn = (
        b'SID=' + SID
        if ServiceName is None
        else b'SERVICE_NAME=' + ServiceName.encode('utf-8')
    )
    Proto = b'TCP' if SslOpts is None else b'TCPS'
    # DRCP (#130): a connection class or non-default purity requests a pooled
    # server from the connection broker via (SERVER=POOLED) in the CONNECT_DATA.
    Drcp = (
        b'(SERVER=POOLED)'
        if (Dictionary['env'].get('cclass') or Dictionary['env'].get('purity'))
        else b''
    )
    return (
        b'(DESCRIPTION=(CONNECT_DATA=('
        + Sn
        + b')'
        + Drcp
        + b'(CID=(PROGRAM='
        + AppName
        + b')(HOST='
        + Hostname
        + b')(USER='
        + User
        + b')))(ADDRESS=(PROTOCOL='
        + Proto
        + b')(HOST='
        + Host
        + b')(PORT='
        + Port
        + b')))'
    )


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
# knob can switch seerdb between the 11g-era and 12c+-era wire contracts.

# Compile-time capability indices (into the compile_caps array):
CCAP_SQL_VERSION = 0
CCAP_LOGON_TYPES = 4
CCAP_FEATURE_BACKPORT = 5
CCAP_FIELD_VERSION = 7  # gates the auth verifier + version-gated formats
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
CCAP_UB2_DTY = 27  # 2-byte data-type ids (12c+)
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

# TNS_CCAP_FIELD_VERSION_* values (the byte written at CCAP_FIELD_VERSION) now
# live in seerdb.common.tns_consts and are imported at the top of this module — kept
# importable as `from seerdb.common.tns import FIELD_VERSION_*` for existing callers.
# They moved to the leaf constants module so seerdb.client.cursor can import the 12.1
# threshold without an import cycle (seerdb.common.tns imports seerdb.client.cursor).

# Runtime capability indices + the flag bits we set:
RCAP_COMPAT = 0
RCAP_TTC = 6
RCAP_COMPAT_81 = 2
RCAP_TTC_ZERO_COPY = 0x01
RCAP_TTC_32K = 0x04

# Per-field-version capability vectors as {index: byte}; unset indices are 0.
# 11.2 reproduces seerdb's historical 11g vector byte-for-byte (asserted by
# tests/test_tns_encode.py); 21.1 matches python-oracledb 4.0.1 against 21c.
_COMPILE_CAPS = {
    FIELD_VERSION_11_2: (
        38,
        {
            CCAP_SQL_VERSION: 6,  # TNS_CCAP_SQL_VERSION_MAX
            CCAP_LOGON_TYPES: 0x6A,  # O7LOGON | O5LOGON | O5LOGON_NP | 0x40
            CCAP_FEATURE_BACKPORT: 1,
            CCAP_FIELD_VERSION: FIELD_VERSION_11_2,
            CCAP_SERVER_DEFINE_CONV: 1,
            CCAP_DEQUEUE_WITH_SELECTOR: 1,
            CCAP_TTC1: 0x29,
            CCAP_OCI1: 0x90,
            CCAP_TDS_VERSION: 3,  # TNS_CCAP_TDS_VERSION_MAX
            CCAP_RPC_VERSION: 7,  # TNS_CCAP_RPC_VERSION_MAX
            CCAP_RPC_SIG: 3,  # TNS_CCAP_RPC_SIG_VALUE
            CCAP_DBF_VERSION: 1,  # TNS_CCAP_DBF_VERSION_MAX
            CCAP_LOB: 0x4F,
            CCAP_TTC2: 4,
            CCAP_OCI2: 12,
            CCAP_CLIENT_FN: 6,
            CCAP_TTC3: 1,
            # Slots oracledb leaves 0 but seerdb's original 11g reference client
            # set; not in oracledb's named map. Kept verbatim for byte-parity.
            1: 1,
            6: 1,
            10: 1,
            11: 1,
            12: 1,
            13: 1,
            24: 1,
            25: 0x37,
            36: 1,
        },
    ),
    FIELD_VERSION_21_1: (
        53,
        {
            CCAP_SQL_VERSION: 6,
            CCAP_LOGON_TYPES: 0xEA,  # adds O8LOGON_LONG_IDENTIFIER (0x80)
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
            CCAP_LOB: 0xCF,  # adds LOB_12C (0x80)
            CCAP_TTC2: 4,
            CCAP_UB2_DTY: 1,
            CCAP_OCI2: 0x10,
            CCAP_CLIENT_FN: 12,  # TNS_CCAP_CLIENT_FN_MAX
            CCAP_OCI3: 0x20,  # OCI3_OCSSYNC
            CCAP_TTC3: 0xB8,
            CCAP_SESS_SIGNATURE_VERSION: 8,
            CCAP_TTC4: 0x44,
            CCAP_LOB2: 5,
            CCAP_TTC5: 0x3E,
            CCAP_FEATURE_BACKPORT2: 2,
            CCAP_VECTOR_FEATURES: 3,
        },
    ),
}
_RUNTIME_CAPS = {
    FIELD_VERSION_11_2: (
        7,
        {
            RCAP_COMPAT: RCAP_COMPAT_81,
        },
    ),
    FIELD_VERSION_21_1: (
        11,
        {
            RCAP_COMPAT: RCAP_COMPAT_81,
            RCAP_TTC: RCAP_TTC_ZERO_COPY | RCAP_TTC_32K,
        },
    ),
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

    Two base vectors are modelled: the 11.2 vector for pre-12c field versions
    (byte-identical to what seerdb has always sent) and the 21.1 vector for
    12c+. The capability *contents* are stable across 12c+ releases — only the
    field-version byte differs — so for any negotiated 12c+ version we render
    the 21.1 base and patch in that version. This lets the client advertise the
    highest version and operate against any server it negotiates down to
    (12.1 / 12.2 / 18c / 19c / 21c …)."""
    if not 0 <= field_version <= 0xFF:
        raise ValueError(f'field version out of range: {field_version}')
    if field_version < FIELD_VERSION_10_2:
        # Pre-10g (9i, #90): the minimal capability vector the Oracle JDBC thin
        # driver sends — crucially LOGON_TYPES = 0 (does NOT advertise O5LOGON).
        # The 11.2 vector advertises O5LOGON (0x6a), which makes 9i attempt a
        # verifier the account lacks and reject the login (ORA-01017); with the
        # minimal caps 9i falls back to the O3LOGON path. CCAP_FIELD_VERSION
        # stays 0 (9i negotiates the field version via TTI_PRO, not the caps).
        return _O3_COMPILE_CAPS, _O3_RUNTIME_CAPS
    Base = (
        FIELD_VERSION_21_1
        if field_version >= FIELD_VERSION_12_1
        else FIELD_VERSION_11_2
    )
    Compile = bytearray(_render_caps(_COMPILE_CAPS[Base]))
    Compile[CCAP_FIELD_VERSION] = field_version
    return bytes(Compile), _render_caps(_RUNTIME_CAPS[Base])


# Oracle 9i (pre-10g) capability vectors, captured from the JDBC thin driver
# (#90). Minimal by design: compile-cap index 17 = 0x03, everything else 0
# (no O5LOGON), runtime caps = a single 0x02 byte.
_O3_COMPILE_CAPS = bytes(17) + bytes([3]) + bytes(3)
_O3_RUNTIME_CAPS = bytes([2])


# 12c+ datatype table. Where the 11g table (built inline in encode_dictionary_dty
# below) uses 1-byte-per-field entries with a short (type, 0) form for unknown
# types, the 12c+ table is a flat list of uniform 4-field entries, each field a
# UB2 (type, conv, repr, 0), terminated by a UB2 0. conv defaults to type and
# repr to 1 (universal) unless overridden in _DTY_12C_OVERRIDES (repr 10 =
# Oracle-native, e.g. NUMBER / DATE). The type list + overrides regenerate
# python-oracledb 4.0.1's DATA_TYPES table byte-for-byte (verified against a 21c
# capture); the gate is the UB2_DTY capability, i.e. field version >= 12.1.
_DTY_12C_TYPES = [
    1,
    2,
    8,
    12,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    10,
    11,
    40,
    41,
    117,
    120,
    290,
    291,
    292,
    293,
    294,
    298,
    299,
    300,
    301,
    302,
    303,
    304,
    305,
    306,
    307,
    308,
    309,
    310,
    311,
    312,
    313,
    315,
    316,
    317,
    318,
    319,
    320,
    321,
    322,
    323,
    327,
    328,
    329,
    331,
    333,
    334,
    335,
    336,
    337,
    338,
    339,
    340,
    341,
    342,
    343,
    344,
    345,
    346,
    348,
    349,
    354,
    355,
    359,
    363,
    380,
    381,
    382,
    383,
    384,
    385,
    386,
    387,
    388,
    389,
    390,
    391,
    393,
    394,
    395,
    396,
    397,
    398,
    399,
    400,
    401,
    404,
    405,
    406,
    407,
    413,
    414,
    415,
    416,
    417,
    418,
    419,
    420,
    421,
    422,
    423,
    424,
    425,
    426,
    427,
    429,
    430,
    431,
    432,
    433,
    449,
    450,
    454,
    455,
    456,
    457,
    458,
    459,
    460,
    461,
    462,
    463,
    466,
    467,
    468,
    469,
    470,
    471,
    472,
    473,
    474,
    475,
    476,
    477,
    478,
    479,
    480,
    481,
    482,
    483,
    484,
    485,
    486,
    490,
    491,
    492,
    493,
    494,
    495,
    496,
    498,
    499,
    500,
    501,
    502,
    509,
    510,
    513,
    514,
    516,
    517,
    518,
    519,
    520,
    521,
    522,
    523,
    524,
    525,
    526,
    527,
    528,
    529,
    530,
    531,
    532,
    533,
    534,
    535,
    536,
    537,
    538,
    539,
    540,
    541,
    542,
    543,
    560,
    565,
    572,
    573,
    574,
    575,
    576,
    578,
    563,
    564,
    579,
    580,
    581,
    582,
    583,
    584,
    585,
    3,
    4,
    5,
    6,
    7,
    9,
    15,
    39,
    68,
    91,
    94,
    95,
    96,
    97,
    100,
    101,
    102,
    104,
    106,
    108,
    109,
    110,
    111,
    112,
    113,
    114,
    115,
    116,
    119,
    198,
    146,
    152,
    153,
    154,
    155,
    156,
    172,
    178,
    179,
    180,
    181,
    182,
    183,
    184,
    185,
    186,
    187,
    188,
    189,
    190,
    195,
    196,
    197,
    208,
    231,
    232,
    233,
    241,
    252,
    590,
    591,
    592,
    613,
    614,
    615,
    616,
    611,
    612,
    593,
    594,
    595,
    596,
    597,
    598,
    599,
    600,
    601,
    602,
    603,
    604,
    605,
    622,
    623,
    624,
    625,
    626,
    627,
    628,
    629,
    630,
    631,
    632,
    637,
    638,
    636,
    639,
    663,
    640,
    652,
    646,
    647,
    127,
    660,
    661,
    665,
    669,
    670,
]
_DTY_12C_OVERRIDES = {
    2: (2, 10),
    12: (12, 10),
    27: (27, 10),
    3: (2, 10),
    4: (2, 10),
    5: (1, 1),
    6: (2, 10),
    7: (2, 10),
    9: (1, 1),
    15: (1, 1),
    68: (2, 10),
    91: (2, 10),
    94: (1, 1),
    95: (23, 1),
    97: (96, 1),
    104: (11, 1),
    108: (109, 1),
    110: (111, 1),
    116: (102, 1),
    152: (2, 10),
    153: (2, 10),
    154: (2, 10),
    155: (1, 1),
    156: (12, 10),
    172: (2, 10),
    184: (12, 10),
    195: (112, 1),
    196: (113, 1),
    197: (114, 1),
    232: (231, 1),
    241: (109, 1),
}


def _datatype_table_12c() -> bytes:
    """Render the 12c+ datatype table: uniform UB2 (type, conv, repr, 0)
    entries terminated by a UB2 0."""
    Out = bytearray()
    for Type in _DTY_12C_TYPES:
        Conv, Rep = _DTY_12C_OVERRIDES.get(Type, (Type, 1))
        Out += struct.pack('>HHHH', Type, Conv, Rep, 0)
    Out += struct.pack('>H', 0)
    return bytes(Out)


# Oracle 8i (8.1.7) DTY (data-type negotiation), captured from a live
# 9.2-client -> 8.1.7 handshake. 8i predates ~37 later data types, so its
# identity map is shorter than the modern table (1019 B vs 1167 B), and it
# negotiates a single-byte charset (WE8ISO8859P1 = 31) — 8i has no Unicode
# charset, so the modern AL32UTF8 (873) DTY draws ORA-03120. Emitted as a
# constant the same way encode_dictionary_dty emits the modern table (the
# negotiation does not vary with the workload); sent when the server is 8i.
_DTY_8I = bytes.fromhex(
    '021f001f0002150601010105010102010101010101017f0f03060300020201800000003c3c3c80'
    '0000000101010002020a00080801000c0c0a0017170100181801001919181901001a1a191a0100'
    '1b1b0a1b01001c1c161c01001d1d171d01001e1e171e01001f1f191f010020200c20010021210c'
    '2101000a0a01000b0b010022220100232301230100242401002525010026260100282801002929'
    '01002a2a01002b2b01002c2c01002d2d01002e2e01002f2f010030300100313101003232010033'
    '3301003434010035350100363601003737010038380100393901003b3b01003c3c01003d3d0100'
    '3e3e01003f3f0100404001004141010042420100434301004747010048480100494901004b4b01'
    '004d4d01004e4e01004f4f01005050010051510100525201005353010054540100555501005656'
    '0100575701570100595901005a5a01005c5c01005d5d01006262010063630100676701006b6b01'
    '0075750100787801007c7c014201007d7d01007e7e01007f7f0100808001008181010082820100'
    '8383010084840100858501008686010087870100898901008a8a01008b8b01008c8c01008d8d01'
    '008e8e01008f8f010090900100919101009494012501009595010096960100979701009d9d0100'
    '9e9e01009f9f0100a0a00100a1a10100a2a20100a3a30100a4a40100a5a50100a6a60100a7a701'
    '00a8a80100a9a90100aaaa0100abab0100adad0100aeae0100afaf0100b0b00100b1b10100c1c1'
    '0100c2c201250100c6c60100c7c70100c8c80100c9c90100caca019f0100cbcb01a00100cccc01'
    'a20100cdcd01a30100cece01b10100cfcf01220100d2d20100d3d301ab0100d4d40100d5d50100'
    'd6d60100d7d70100d8d80100d9d90100dada0100dbdb0100dcdc0100dddd0100dede0100dfdf01'
    '00e0e00100e1e10100e2e20100e3e3016b0100e4e40100e5e50100e6e60100eaea0100ebeb0100'
    'ecec0100eded0100eeee0100efef0100f2f20100f4f40100f5f5010003020a0004020a00050101'
    '0006020a0007020a00090101000d000e000f17010010001100120013001400150016002778015d'
    '012601003a6d010044020a00450046004a6d01004c0058005b020a005e0101005f170100606001'
    '00616001006400650066660100680069006a6a01006c6d01006d6d01006e6f01006f6f01007070'
    '01007171010072720100737301007466010076007700796d01007a6d01007b6d01008800929201'
    '009393010098020a0099020a009a020a009b0101009c0c0a00ac020a00b2b20100b3b30100b4b4'
    '0100b5b50100b6b60100b7b70100b80c0a00b9b20100bab30100bbb40100bcb50100bdb60100be'
    'b70100bf00c000c3700100c4710100c5720100d0d00100d100e7e70100e8e70100e900f000f16d'
    '0100f30000'
)


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
    # default (11.2) reproduces what seerdb has always sent. The datatype
    # tables don't vary with the user's query workload — python-oracledb
    # hard-codes the equivalent, and the OCI thick client builds it from a
    # static C table at link time; we emit it as a constant for the same reason.
    # The table form is version-gated below: 11g 1-byte vs 12c+ 2-byte.
    logger.debug('encode_dictionary_dty: %s', _redacted(Dictionary))
    Charset = struct.pack('<H', CharsetDict.get(Dictionary['req'], AL32UTF8_CHARSET))

    # Compile-time + runtime capability arrays, each emitted as a length byte
    # followed by the array (write_bytes_with_length in oracledb terms).
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    CompileCaps, RuntimeCaps = capability_arrays(FieldVersion)
    # End-of-response opt-in (#155/#132): when the server advertised EOR support
    # in its accept, set CCAP_TTC4's 0x20 bit so the server delimits every
    # response with the EOR (29) marker — the prerequisite for pipelining. Only
    # reached on a >= 318 server (older tiers never set supports_eor), and
    # guarded on the cap array being long enough.
    if Dictionary.get('supports_eor') and len(CompileCaps) > CCAP_TTC4:
        Caps = bytearray(CompileCaps)
        Caps[CCAP_TTC4] |= TNS_CCAP_END_OF_RESPONSE
        CompileCaps = bytes(Caps)
    CapabilityHeader = bytes([len(CompileCaps)]) + CompileCaps
    TableHeader = bytes([len(RuntimeCaps)]) + RuntimeCaps

    # Identity map: for type id N in 1..245, emit (N, N, 1, 0) — "I know
    # type N and want it on the wire as type N with format flag 1". This
    # is the default assertion; `TypeOverrides` (below) overrides
    # specific entries.
    IdentityMap = bytes(
        reduce(lambda y, z: y + z, [[]] + [[x, x, 1, 0] for x in range(1, 246)])
    )

    # Override table. Each entry is `(client_type, server_repr, format,
    # flags)` — when this client encounters data of type `client_type`,
    # negotiate `server_repr` as the wire representation with the given
    # format. Terminated by `0, 0`. Annotated against seerdb.common.tns_consts:
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
    TypeOverrides = bytes(
        [
            2,
            2,
            10,
            0,
            3,
            2,
            10,
            0,
            4,
            2,
            10,
            0,
            5,
            1,
            1,
            0,
            6,
            2,
            10,
            0,
            7,
            2,
            10,
            0,
            9,
            1,
            1,
            0,
            12,
            12,
            10,
            0,
            13,
            0,
            14,
            0,
            15,
            23,
            1,
            0,
            16,
            0,
            17,
            0,
            18,
            0,
            19,
            0,
            20,
            0,
            21,
            0,
            22,
            0,
            39,
            120,
            1,
            0,
            58,
            0,
            68,
            2,
            10,
            0,
            69,
            0,
            70,
            0,
            74,
            0,
            6,
            0,
            91,
            2,
            10,
            0,
            94,
            1,
            1,
            0,
            95,
            23,
            1,
            0,
            96,
            96,
            1,
            0,
            97,
            96,
            1,
            0,
            104,
            11,
            1,
            0,
            105,
            0,
            108,
            109,
            1,
            0,
            110,
            111,
            1,
            0,
            116,
            102,
            1,
            0,
            118,
            0,
            119,
            0,
            121,
            0,
            122,
            0,
            123,
            0,
            136,
            0,
            146,
            146,
            1,
            0,
            147,
            0,
            152,
            2,
            10,
            0,
            153,
            2,
            10,
            0,
            154,
            2,
            10,
            0,
            155,
            1,
            1,
            0,
            156,
            12,
            10,
            0,
            172,
            2,
            10,
            0,
            209,
            0,
            3,
            0,
            0,  # terminator
        ]
    )
    # Datatype table: 12c+ (UB2_DTY) uses the uniform 2-byte-per-field table;
    # 11g uses the 1-byte form built above. The encoding flag follows suit
    # (oracledb sends 3 = MULTI_BYTE|CONV_LENGTH for 12c+, seerdb 1 for 11g).
    if FieldVersion >= FIELD_VERSION_12_1:
        DataTypeTable = _datatype_table_12c()
        Flag = 3
    else:
        DataTypeTable = IdentityMap + TypeOverrides
        Flag = 1
    # Same charset for IN (server-side) and OUT (client-side) negotiation.
    return (
        bytes([TTI_DTY])
        + Charset
        + Charset
        + bytes([Flag])
        + CapabilityHeader
        + TableHeader
        + DataTypeTable
    )


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
    # Publish the field version for the bind-OAC encoder (encode_token_raw).
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    _ENCODE_FIELD_VERSION.set(FieldVersion)
    Type = Dictionary['query']['type']
    Auto = Dictionary['query']['auto']
    Fetch = Dictionary['query']['fetch']
    ServerVersion = (
        b''
        if (Dictionary['query']['server_version'] >> 24) == 10
        else bytes([0, 0, 0, 0, 0])
    )
    Cursor = Dictionary['query']['cursor']
    Query = Dictionary['query']['query'].encode('utf-8')
    QueryLen = len(Query)
    QueryFlag = 1 if QueryLen > 0 else 0
    Bind = Dictionary['query']['bind']
    BindLen = len(Bind)
    BindFlag = 1 if (Cursor == 0) and (BindLen > 0) else 0
    # DML RETURNING ... INTO (#120): the positions of the OUT (return) binds.
    # All binds get an OAC, but only the non-return binds carry a value in the
    # RXD row (the server fills the return binds from the affected rows).
    ReturnBinds = Dictionary['query'].get('return_binds') or frozenset()
    InBind = [V for I, V in enumerate(Bind) if I not in ReturnBinds]
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
    # Request pipelining (#158): a pipelined execute numbers itself 1..N so the
    # server tags each response with a matching TOKEN (33) marker. Ordinary
    # (non-pipelined) executes leave this 0 — encode_sb4(0) is the historical
    # single zero byte, so the bytes are unchanged.
    TokenNum = Dictionary.get('token_num', 0)

    if Cursor == 0:
        (Opt, LMax, Max, All8) = set_opts(Type, 1, BindFlag, BatchLen, Auto)
    elif Type == 'fetch':
        (Opt, LMax, Max, All8) = set_opts(Type, 0, DefFlag, 0, Fetch)
    elif Type == 'select':
        (Opt, LMax, Max, All8) = set_opts(Type, 0, 0, 0, Fetch)
    else:
        (Opt, LMax, Max, All8) = set_opts(Type, 0, 0, BatchLen, Auto)

    # Array-DML batch-error mode: with this exec option set, a per-row error
    # (e.g. a unique-constraint violation) no longer aborts the whole batch —
    # the server applies the good rows and returns the failures as the OER's
    # batch-error code/offset/message arrays (#18). Verified against an
    # oracledb-thin capture: it ORs 0x80000 into the leading Opt word.
    if Dictionary['query'].get('batcherrors'):
        Opt |= TNS_EXEC_OPTION_BATCH_ERRORS

    # Array-DML row counts (oracledb arraydmlrowcounts, #18): ask the server to
    # return a per-iteration affected-row count. This is a 12c+ feature (it
    # rides in the 12c+ OALL8 al8pidmlrc block below) and only meaningful for an
    # actual batch. Two coordinated request-side changes, both reverse-
    # engineered from an oracledb-thin capture: (1) al8i4[9] = 0xC000 here, and
    # (2) the al8pidmlrc pointer + iteration count in `Middle`. Omitting either
    # makes the server reject the execute as malformed (ORA-03137 kpoal8Check).
    ArrayDmlRowCounts = bool(
        Dictionary['query'].get('arraydmlrowcounts')
        and FieldVersion >= FIELD_VERSION_12_2
        and BatchLen > 0
    )
    if ArrayDmlRowCounts and len(All8) > 9:
        All8 = list(All8)
        All8[9] = TNS_AL8I4_ARRAY_DML_ROWCOUNTS

    # Implicit result sets (#121): opt in on PL/SQL block executes (12c+) by
    # setting TNS_EXEC_FLAGS_IMPLICIT_RESULTSET (0x8000) in al8i4[9]. Without it
    # a block calling DBMS_SQL.RETURN_RESULT fails with ORA-29481 ("implicit
    # results cannot be returned to client"). oracledb sets this on every
    # normal execute; scoping it to blocks keeps the DML/DDL paths untouched.
    if Type == 'block' and FieldVersion >= FIELD_VERSION_12_1 and len(All8) > 9:
        All8 = list(All8)
        All8[9] = All8[9] | 0x8000

    # 23ai (fv > 17, #89): the execute framing the server expects under field
    # version 24 differs from the legacy form in three spots, reverse-engineered
    # from an oracledb-thin fv24 capture (docs/PROTOCOL.md §20):
    #   - the prefetch-buffer-size field (LMax) must be 0, not the 0xffffffff
    #     long-fetch sentinel the first SELECT carries, or the server's stricter
    #     parse overflows (ORA-03120, two-task conversion integer overflow);
    #   - the exec-options word gains 0x40;
    #   - al8i4[9] (exec flags) gains 0x8000 (already implied by the array-DML
    #     0xC000 value, so only set it when that path didn't).
    if FieldVersion > FIELD_VERSION_23_1:
        if LMax == 0xFFFFFFFF:
            LMax = 0
        # The 0x40 options bit and al8i4[9] = 0x8000 are query-execute flags;
        # setting them on a DDL/DML execute makes the server reject it
        # (ORA-03137 kpoal8Check-5 [32768]).
        if Type in ('select', 'fetch'):
            Opt |= 0x40
            if not ArrayDmlRowCounts and len(All8) > 9:
                All8 = list(All8)
                All8[9] = 0x8000

    # Server-side scrollable cursor (#181): mark the cursor scrollable (and keep
    # it open past EOF) on the opening execute, and carry the scroll request
    # (orientation + 1-based position) on a scroll re-execute. al8i4[9] holds the
    # exec flags, al8i4[10] the orientation, al8i4[11] the position — validated
    # against a 23ai oracledb-thin capture (al8i4[9] reads 0x8082 = the 23ai
    # query flag | NO_CANCEL_ON_EOF | SCROLLABLE).
    Scroll = Dictionary['query'].get('scroll')  # (orient, pos) or None
    if (Dictionary['query'].get('scrollable') or Scroll) and len(All8) > 11:
        All8 = list(All8)
        All8[9] |= TNS_EXEC_FLAGS_SCROLLABLE | TNS_EXEC_FLAGS_NO_CANCEL_ON_EOF
        if Scroll:
            All8[10], All8[11] = Scroll
            # A scroll re-execute (open cursor, no new parse) is a FETCH-only
            # call: oracledb-thin sends exec options 0x8040, but set_opts forces
            # the EXECUTE bit (0x20) on for a Flag=0 select. Leaving it on makes
            # the server re-run the query and reset the result set, so the scroll
            # orientation positions from the top and every fetch returns empty
            # (#181). Clear it on a re-execute (Cursor != 0); the opening execute
            # (Cursor == 0) keeps PARSE+EXECUTE+FETCH (oracledb 0x8061).
            if Cursor != 0:
                Opt &= ~TNS_EXEC_OPTION_EXECUTE

    All8Len = len(All8)
    All8Flag = 1 if All8Len > 0 else 0
    All8s = reduce(lambda x, y: x + y, [encode_sb4(A) for A in All8])

    if BindLen == DefLen == 0:
        Tokens = b''
    elif DefLen == QueryLen == 0:
        if BatchLen > 0:
            Tokens = b''.join(encode_tokens_rxd(R, b'') for R in [Bind] + Batch)
        elif ReturnBinds:
            # Cached-cursor RETURNING: values for the input binds only.
            Tokens = encode_tokens_rxd(InBind, b'') if InBind else b''
        else:
            Tokens = encode_tokens_rxd(Bind, b'')
    elif DefLen == 0:
        if BatchLen > 0:
            # Array DML: OAC describes the columns once (sized to the widest
            # value in each column across all rows so a later row can't exceed
            # the declared buffer), then one RXD row per iteration.
            AllRows = [Bind] + Batch
            Oac = encode_tokens_oac(_oac_rep_row(AllRows), b'')
            Tokens = Oac + b''.join(encode_tokens_rxd(R, b'') for R in AllRows)
        elif ReturnBinds:
            # DML RETURNING ... INTO: OAC for every bind, then an RXD carrying
            # only the input binds' values (the return binds are server-filled).
            Oac = encode_tokens_oac(Bind, b'')
            Tokens = encode_tokens_rxd(InBind, Oac) if InBind else Oac
        else:
            Oac = encode_tokens_oac(Bind, b'')
            Tokens = encode_tokens_rxd(Bind, Oac)
    elif BindLen == QueryLen == 0:
        Tokens = encode_tokens_oac(Def, b'')
    else:
        raise Exception('Unhandled tokens combination', Bind, Batch, Def, Query)

    Head = (
        _fun_header(TTI_ALL8, Tseq, FieldVersion, TokenNum)
        + encode_sb4(Opt)
        + encode_sb4(Cursor)
        + bytes([QueryFlag])
        + encode_sb4(QueryLen)
        + bytes([All8Flag])
        + encode_sb4(All8Len)
        + bytes([0, 0])
        + encode_sb4(LMax)
        + encode_sb4(Fetch)
        + encode_sb4(Max)
        + bytes([BindFlag])
        + encode_sb4(BindLen)
        + bytes([0, 0, 0, 0, 0])
        + bytes([DefFlag])
        + encode_sb4(DefLen)
    )

    if FieldVersion >= FIELD_VERSION_12_2:
        # 12c+ OALL8 carries extra al8 fields after the 11g header: the DML
        # row-count block, then (12.2+) the SQL-signature / SQL-id pointers and
        # (12.2_EXT1+) the chunk-id pointers — all zero/null for us. The SQL is
        # length-prefixed (write_bytes_with_length). Without these the server
        # reads the SQL/al8i4 array from the wrong offset and returns ORA-03120
        # (two-task conversion routine: integer overflow). See oracledb
        # execute.pyx _write_execute_message.
        Middle = bytes([0, 0, 1]) + bytes([0, 0, 0, 0, 0])  # reg_lsb .. reg_msb
        if ArrayDmlRowCounts:
            # al8pidmlrc = pointer(1) + ub4 iteration count + 1. The server
            # returns that many per-iteration row counts in the response RPA
            # region (#18). Matches oracledb byte-for-byte (e.g. 4 iters →
            # 01 01 04 01).
            Middle += bytes([1]) + encode_sb4(1 + BatchLen) + bytes([1])
        else:
            Middle += bytes([0, 0, 0])  # al8pidmlrc block
        Middle += bytes([0, 0, 0, 0, 0])  # 12.2 al8sqlsig / SQL id
        if FieldVersion >= FIELD_VERSION_12_2_EXT1:
            Middle += bytes([0, 0])  # 12.2_EXT1 chunk ids
        # The length-prefixed SQL is written only when there is SQL to parse. On
        # a no-parse re-execute (Cursor != 0, empty query — e.g. a #181 scroll
        # re-execute) oracledb omits the SQL bytes entirely; emitting the
        # zero-length prefix (a stray 0x00) shifts the server's read of the
        # al8i4 array by one byte and it rejects the call as malformed
        # (ORA-03137 [12316]).
        Sql = _bytes_with_length(Query) if QueryLen else b''
        return Head + Middle + Sql + All8s + Tokens

    return Head + bytes([0, 0, 1]) + ServerVersion + Query + All8s + Tokens


def encode_dictionary_fetch(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    Cursor = encode_sb4(Dictionary['cursor'])
    Fetch = encode_sb4(Dictionary['fetch'])
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    return _fun_header(TTI_FETCH, Tseq, FieldVersion) + Cursor + Fetch


# ---------------------------------------------------------------------------
# Oracle 9i (pre-10g, field version 2) query/fetch — the TTI_ALL7 dialect.
# A SELECT is a four-call sequence (docs/PROTOCOL.md §19), reverse-engineered
# from the Oracle JDBC thin driver against a live 9.2.0.4 server (#97). Gate
# every fv2 path on `field_version < FIELD_VERSION_10_2`.
# ---------------------------------------------------------------------------
_O7_DESCRIBE_FUNC = 0x62  # describe columns (RPA carries the metadata)
_O7_CLOSE_FUNC = 0x14  # close cursor


def encode_o7_open(Seq: int) -> bytes:
    # Call 0: OOPEN — allocate a server cursor. The server tracks it as the
    # "current" cursor for the subsequent parse/describe/execute/close (which
    # all carry cursor field 0). Without it the parse fails ORA-01001.
    return bytes([TTI_FUN, 0x02, Seq, 0x01, 0x00])


def _o7_bind_oac(Value: object) -> bytes:
    # fv2 bind descriptor (same 13/14-byte shape as a define entry): the
    # client's declared type for an input bind. Number → VARNUM(6); str →
    # VARCHAR sized 4000 (what JDBC declares); bytes → RAW; None defaults to a
    # 1-byte VARCHAR. charset 31, csfrm 1 (csfrm 0 for RAW). #100.
    #
    # A `Var` (an OUT / IN OUT bind, #102) declares its registered type and
    # return-buffer size instead: NUMBER rides as VARNUM(6)/22 like an inline
    # number; RAW carries csfrm 0; everything else uses the Var's size (VARCHAR
    # defaults to 32767, matching JDBC). The mode (IN/OUT/IN OUT) is NOT in the
    # OAC — the server infers it from the block and signals it in the bind
    # prompt; see decode_fv2_block_out.
    from seerdb.common.datatypes import Var

    # Char binds declare AL32UTF8 (csfrm 1) — the driver negotiates an AL32UTF8
    # session and sends UTF-8, which the 9i server converts to its DB charset —
    # or AL16UTF16 for national (csfrm 2) binds, which ride as UTF-16BE (see
    # encode_token_rxd). The charset field is ignored for non-char types. #174.
    def _oac(Type, MaxSize, Csfrm):
        if Type in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR):
            Charset = AL16UTF16_CHARSET if Csfrm == 2 else AL32UTF8_CHARSET
        else:
            Charset = 31  # ignored by the server for non-char types (NUMBER /
            # DATE / RAW / INTERVAL); keep the historical value
        return (
            bytes([Type, 0x01, 0, 0])
            + encode_sb4(MaxSize)
            + bytes([0, 0, 0, 0])
            + encode_sb4(Charset)
            + bytes([Csfrm])
        )

    if isinstance(Value, Var):
        VType = Value.dbtype.tns_type
        Vcsfrm = getattr(Value.dbtype, 'csfrm', 1)
        if VType == TNS_TYPE_NUMBER:
            Type, MaxSize, Csfrm = 0x06, 22, 1
        elif VType == TNS_TYPE_RAW:
            Type, MaxSize, Csfrm = TNS_TYPE_RAW, Value.size, 0
        else:
            Type, MaxSize, Csfrm = VType, Value.size, Vcsfrm
        return _oac(Type, MaxSize, Csfrm)
    if isinstance(Value, str):
        Type, MaxSize, Csfrm = TNS_TYPE_VARCHAR, 4000, 1
    elif isinstance(Value, (bytes, bytearray)):
        Type, MaxSize, Csfrm = TNS_TYPE_RAW, 2000, 0
    elif isinstance(Value, bool) or isinstance(Value, (int, float, Decimal)):
        Type, MaxSize, Csfrm = 0x06, 22, 1  # VARNUM
    elif isinstance(Value, datetime.datetime):
        # A datetime/date bind must declare the same Oracle temporal type the
        # value carries on the wire (encode_token_datetime emits 7/11/13 bytes),
        # else the server reads the binary value as a VARCHAR and the implicit
        # date conversion fails with ORA-01858 (#172). Mirror encode_token_oac:
        # tz-aware -> TIMESTAMPTZ(13); sub-second -> TIMESTAMP(11); else DATE(7).
        if Value.tzinfo is not None:
            Type, MaxSize, Csfrm = TNS_TYPE_TIMESTAMPTZ, 13, 0
        elif Value.microsecond > 0:
            Type, MaxSize, Csfrm = TNS_TYPE_TIMESTAMP, 11, 0
        else:
            Type, MaxSize, Csfrm = TNS_TYPE_DATE, 7, 0
    elif isinstance(Value, datetime.date):
        Type, MaxSize, Csfrm = TNS_TYPE_DATE, 7, 0
    elif isinstance(Value, datetime.timedelta):
        # INTERVAL DAY TO SECOND (#173): encode_token_rxd emits the 11-byte
        # interval; declare the matching type so the server does not read it as
        # a VARCHAR and fail with ORA-01867.
        Type, MaxSize, Csfrm = TNS_TYPE_INTERVALDS, 11, 0
    elif isinstance(Value, IntervalYM):
        Type, MaxSize, Csfrm = TNS_TYPE_INTERVALYM, 5, 0  # 5-byte YM interval
    elif Value is None:
        Type, MaxSize, Csfrm = TNS_TYPE_VARCHAR, 1, 1
    else:
        Type, MaxSize, Csfrm = TNS_TYPE_VARCHAR, 4000, 1
    return _oac(Type, MaxSize, Csfrm)


def encode_o7_parse(Seq: int, Sql: str, Binds: list | None = None) -> bytes:
    # Call 1: TTI_ALL7 parse. The SQL is carried inline, sb4-length-prefixed,
    # between two fixed option blocks. With input binds (#100) the option word
    # flips to 0x29, a bind-count field precedes the SQL, and each bind's OAC
    # plus the values (one RXD with all values) are appended after the SQL.
    Binds = Binds or []
    SqlBytes = Sql.encode('utf-8')
    Opt = 0x29 if Binds else 0x21
    BindCount = bytes([0x01, 0x01, len(Binds)]) if Binds else bytes([0, 0])
    Out = (
        bytes([TTI_FUN, TTI_ALL7, Seq, 0x02, 0x80, Opt, 0x01, 0x01, 0x01])
        + encode_sb4(len(SqlBytes))
        + bytes([0, 0, 0x01, 0x01, 0x07, 0x01, 0x01, 0x02, 0, 0, 0])
        + BindCount
        + SqlBytes
        + bytes([0x01, 0x01, 0x01, 0x01, 0, 0, 0, 0, 0])
    )
    if Binds:
        Out += b''.join(_o7_bind_oac(V) for V in Binds)
        Out += encode_tokens_rxd(Binds, b'')
    return Out


def encode_o7_block(Seq: int, Sql: str, Binds: list | None = None) -> bytes:
    # Anonymous PL/SQL block parse-execute over TTI_ALL7 (#102, PROTOCOL §19.6).
    # Same framing as encode_o7_parse EXCEPT the option word: a block uses
    # `01 21` (no binds) / `02 04 29` (binds) where a SELECT/DML uses
    # `02 80 21` / `02 80 29` — the 0x8000 "values are inline" bit is NOT set,
    # so the server rejects DML opts on a block with ORA-00600. Consequently the
    # bind OACs are sent here but the VALUES are NOT appended inline; the server
    # answers with a "send the binds" prompt and the caller then sends the
    # values as a standalone RXD (encode_tokens_rxd). Verified byte-for-byte
    # against cap_9i_plsql_{noarg,inbind}.log.
    Binds = Binds or []
    SqlBytes = Sql.encode('utf-8')
    OptBytes = bytes([0x02, 0x04, 0x29]) if Binds else bytes([0x01, 0x21])
    BindCount = bytes([0x01, 0x01, len(Binds)]) if Binds else bytes([0, 0])
    Out = (
        bytes([TTI_FUN, TTI_ALL7, Seq])
        + OptBytes
        + bytes([0x01, 0x01, 0x01])
        + encode_sb4(len(SqlBytes))
        + bytes([0, 0, 0x01, 0x01, 0x07, 0x01, 0x01, 0x02, 0, 0, 0])
        + BindCount
        + SqlBytes
        + bytes([0x01, 0x01, 0x01, 0x01, 0, 0, 0, 0, 0])
    )
    if Binds:
        # Bind OACs only — the values follow in a separate RXD frame after the
        # server's bind prompt (the 0x8000-inline path is not used for blocks).
        Out += b''.join(_o7_bind_oac(V) for V in Binds)
    return Out


def encode_o7_describe(Seq: int) -> bytes:
    # Call 2: fixed describe-columns request; response is the metadata RPA.
    return bytes(
        [
            TTI_FUN,
            _O7_DESCRIBE_FUNC,
            Seq,
            0x07,
            0x01,
            0x01,
            0,
            0,
            0x01,
            0x02,
            0x01,
            0x01,
        ]
    )


def _o7_define_entry(Col: dict) -> bytes:
    # One 13/14-byte define entry: the client's requested return type for a
    # column (built from the describe). deftype = VARNUM(6) for NUMBER, else the
    # column type; CHAR carries flag 0x21; NUMBER/DATE/TIMESTAMP use a fixed
    # buffer size, everything else the described max. charset defaults to 31
    # (the server DB charset JDBC requests) unless the column is national.
    Type = Col['data_type']
    Csfrm = Col.get('csfrm') or 0
    if Type == TNS_TYPE_NUMBER:
        DefType, MaxSize = 0x06, 22
    elif Type == TNS_TYPE_DATE:
        DefType, MaxSize = TNS_TYPE_DATE, 7
    elif Type in (TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPTZ, 181):
        DefType, MaxSize = Type, 13
    elif Type in (TNS_TYPE_RID, TNS_TYPE_ROWID, TNS_TYPE_UROWID):
        # Request ROWID as VARCHAR so the server returns its text form (what
        # JDBC does); the native ROWID return form desyncs the fv2 row stream
        # (ORA-01002). The value arrives as the familiar 18-char rowid string.
        DefType, MaxSize, Csfrm = TNS_TYPE_VARCHAR, 128, 0
    elif Type in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW):
        # LONG / LONG RAW: request the native type with the 2 GiB max buffer
        # (as JDBC does); the value streams back in the chunked DALC form.
        DefType, MaxSize = Type, 0x7FFFFFFF
    else:
        DefType, MaxSize = Type, Col.get('max_size') or 0
    Flag = 0x21 if Type == TNS_TYPE_CHAR else 0x01
    Charset = Col.get('charset') or 31
    return (
        bytes([DefType, Flag, 0, 0])
        + encode_sb4(MaxSize)
        + bytes([0, 0, 0, 0])
        + encode_sb4(Charset)
        + bytes([Csfrm])
    )


def encode_o7_exec(Seq: int, Columns: list) -> bytes:
    # Call 3: TTI_ALL7 execute + fetch (option word 02 80 50), carrying a define
    # block (one entry per column) so the server returns the requested types.
    Head = bytes(
        [
            TTI_FUN,
            TTI_ALL7,
            Seq,
            0x02,
            0x80,
            0x50,
            0x01,
            0x01,
            0,
            0,
            0,
            0,
            0x01,
            0x01,
            0x07,
            0x01,
            0x01,
            0x02,
            0,
        ]
    )
    Defines = bytes(
        [0x01, 0x01, len(Columns), 0, 0, 0x01, 0x01, 0x01, 0x0A, 0, 0, 0, 0, 0]
    ) + b''.join(_o7_define_entry(C) for C in Columns)
    return Head + Defines


def encode_o7_close(Seq: int) -> bytes:
    # Call 4: close the cursor.
    return bytes([TTI_FUN, _O7_CLOSE_FUNC, Seq, 0x01, 0x01])


# ---------------------------------------------------------------------------
# fv2 (9i) LOB read — TTI_LOBOPS GETLEN + READ (PROTOCOL.md §19.5)
# ---------------------------------------------------------------------------
# 9i's TTI_LOBOPS request is far shorter than the modern (10g+) form, and JDBC
# issues it as a *pair* per LOB cell: first GETLEN to learn the content length,
# then READ to pull exactly that many chars (CLOB) / bytes (BLOB). The modern
# single-shot READ returns empty on 9i. The locator is `_read_lob_column`'s
# output (`00 <ub1 len><body>`); its leading byte is dropped and the rest
# (`<ub1 len><body>`) is sent verbatim. Every fv2 LOBOPS request shares the
# shape `03 60 <seq> 01 <sb4 locator-length> <op middle> <locator[1:]> <trailer>`
# — only the op-specific middle and trailer differ. Validated byte-for-byte
# against cap_9i_lobread.log (CLOB + BLOB GETLEN/READ) and cap_9i_bfile.log
# (BFILE FILE_OPEN/READ/CLOSE). (#102, PROTOCOL §19.5 / §19.8)
_LOBOP_GETLEN_MID = bytes.fromhex('000000000001000101000000')  # GETLEN
_LOBOP_READ_MID = bytes.fromhex('00000101000001000102000000')  # READ
_LOBOP_FOPEN_MID = bytes.fromhex('00000000000100020100000000')  # BFILE FILE_OPEN
_LOBOP_FCLOSE_MID = bytes.fromhex('00000000000000020200000000')  # BFILE FILE_CLOSE


def _encode_o7_lobop(Seq: int, Locator: bytes, Middle: bytes, Trailer: bytes) -> bytes:
    # Build a fv2 TTI_LOBOPS request. The source-locator length counts the full
    # `_read_lob_column` block (its leading byte plus the `<ub1 len><body>` that
    # goes on the wire); CLOB/BLOB locators are a fixed 86 bytes, BFILE locators
    # vary with the directory + file name, so it is computed rather than fixed.
    return (
        bytes([TTI_FUN, TTI_LOBOPS, Seq, 0x01])
        + encode_sb4(len(Locator))
        + Middle
        + Locator[1:]
        + Trailer
    )


def encode_o7_lob_getlen(Seq: int, Locator: bytes) -> bytes:
    # GETLEN: ask the server for the LOB's length. Trailer is a single 0x00
    # (no read amount). Response carries the amount — see decode_fv2_lob_getlen.
    return _encode_o7_lobop(Seq, Locator, _LOBOP_GETLEN_MID, bytes([0]))


def encode_o7_lob_read(Seq: int, Locator: bytes, Amount: int) -> bytes:
    # READ: pull `Amount` chars/bytes (the value GETLEN returned) starting at
    # offset 1. Response is `0e fe <chunks>` then an RPA + OER.
    return _encode_o7_lobop(Seq, Locator, _LOBOP_READ_MID, encode_sb4(Amount))


def encode_o7_bfile_open(Seq: int, Locator: bytes) -> bytes:
    # BFILE FILE_OPEN: open the external file read-only (trailer 01 0b = amount
    # pointer present + open mode 0x0b). The reply's RPA carries an *updated*
    # locator with the open flag set — GETLEN/READ/CLOSE must use that one
    # (decode_fv2_opened_locator). (#102, PROTOCOL §19.8)
    return _encode_o7_lobop(Seq, Locator, _LOBOP_FOPEN_MID, bytes.fromhex('010b'))


def encode_o7_bfile_close(Seq: int, Locator: bytes) -> bytes:
    # BFILE FILE_CLOSE: close the opened file (no trailer).
    return _encode_o7_lobop(Seq, Locator, _LOBOP_FCLOSE_MID, b'')


def decode_fv2_opened_locator(Packet: bytes) -> bytes | None:
    # Pull the opened BFILE locator out of a FILE_OPEN reply: TTI_RPA (08) 00
    # then `<ub1 len><body>` (the open-flagged locator), then `01 0b` + OER.
    # Returned in `_read_lob_column`'s full form (a leading 0x00 + the
    # `<ub1 len><body>`) so it feeds straight back into the LOBOPS encoders.
    if not Packet or Packet[0] != TTI_RPA or len(Packet) < 3:
        return None
    Olen = Packet[2]
    return bytes([0]) + bytes(Packet[2 : 3 + Olen])


def decode_fv2_lob_chunks(Data: bytes) -> tuple[bytes, bool]:
    # Parse the content of a 9i (fv2) TTI_LOBOPS READ reply: TTI_LOB (0e) then
    # 0xfe, then `<ub1 len><bytes>` chunks ending at a zero-length chunk; the
    # trailing RPA is ignored. Returns (content, complete). `complete` is False
    # when the zero-length terminator hasn't been reached yet (the content
    # spans more packets) — the caller appends the next packet and re-parses the
    # full accumulated buffer. Unlike modern (10g+) replies the fv2 READ reply
    # carries no `04 01 01` OER call-status (a single-row fetch happened to
    # include one; a multi-row fetch does not), so the zero-length chunk is the
    # only reliable terminator. (#102, PROTOCOL.md §19.5)
    if len(Data) < 2 or Data[0] != TTI_LOB:
        return (b'', False)
    # Data[1] is the 0xfe chunked marker; a non-chunked single value would be
    # `0e <len> <bytes>`, handled by treating Data[1] as the first chunk length.
    Pos = 2 if Data[1] == 0xFE else 1
    Content = b''
    while Pos < len(Data):
        ChunkLen = Data[Pos]
        if ChunkLen == 0:
            return (Content, True)  # zero-length chunk = end
        if Pos + 1 + ChunkLen > len(Data):
            break  # chunk split across packets
        Content += Data[Pos + 1 : Pos + 1 + ChunkLen]
        Pos += 1 + ChunkLen
    return (Content, False)


def decode_fv2_lob_getlen(Packet: bytes) -> int:
    # GETLEN response layout: TTI_RPA (08) 00 <ub1 loclen><locator echo>
    # <ub4 amount> TTI_OER. The amount is in chars for CLOB/NCLOB and bytes for
    # BLOB. Returns 0 on an unexpected shape (e.g. an empty LOB) so the caller
    # reads nothing rather than desyncing.
    if not Packet or Packet[0] != TTI_RPA:
        return 0
    Pos = 2  # skip RPA token + its 0x00
    if Pos >= len(Packet):
        return 0
    LocLen = Packet[Pos]
    Pos += 1 + LocLen  # skip the echoed locator
    if Pos >= len(Packet):
        return 0
    (Amount, _) = decode_ub4(Packet[Pos:])
    return Amount


def _decode_oac_fv2(Rest: bytes) -> tuple[dict, bytes]:
    # fv2 column descriptor = the modern decode_token_oac field order MINUS the
    # trailing Mxlc ub4 (a later addition). The leading DataType byte is the
    # standard Oracle type code (== TNS_TYPE_*), so existing value decoders are
    # reused. Returns a column dict shaped like decode_token_dcb's output.
    (DataType, Flag, Precision) = struct.unpack('>BBB', Rest[:3])
    Rest = Rest[3:]
    (DataScale, Rest) = decode_ub4(Rest)
    (MaxLen, Rest) = decode_ub4(Rest)
    (_Mal, Rest) = decode_ub4(Rest)
    (_Fl2, Rest) = decode_ub4(Rest)
    (_ToId, Rest) = decode_dalc(Rest)
    (_Vsn, Rest) = decode_ub4(Rest)
    (Charset, Rest) = decode_ub4(Rest)
    Csfrm = Rest[0]
    Rest = Rest[1:]
    Col = {
        'data_type': DataType,
        'data_length': MaxLen,
        'data_scale': DataScale,
        'precision': Precision,
        'max_size': MaxLen,
        'charset': Charset,
        'csfrm': Csfrm,
        'null_ok': 1,
        'domain_schema': None,
        'domain_name': None,
    }
    return (Col, Rest)


def decode_fv2_describe(Data: bytes) -> list[dict]:
    # Parse the TTI_RPA (0x08) answering the 0x62 describe-columns call into a
    # list of column dicts (docs/PROTOCOL.md §19.1). Layout:
    #   08 01 <numcols> then per column:
    #     <OAC-fv2> null_ok(1B) namelen_bytes(1B) ub4(namelen_chars) DALC(name) 00 00
    #
    # The first byte after the OAC is null_ok (0x00 = NOT NULL, 0x01 = nullable),
    # NOT part of the name length. The historic "two ub4 name-lengths" reading
    # only survived because every offline fixture was `SELECT <literal> AS name
    # FROM dual` — a literal is always nullable, so null_ok=0x01 read as a width-1
    # ub4 whose value happened to equal the name length. A real NOT-NULL column
    # sends null_ok=0x00, which decode_ub4 misreads as width-0/value-0 (one byte),
    # slipping the whole column stream and garbling the name (b'\x08USERNAM') — and
    # a multi-column NOT-NULL select then fails the fetch with ORA-03115. Read
    # null_ok + the 1-byte byte-length explicitly, then the genuine ub4 char-length.
    NumCols = Data[2]
    Rest = Data[3:]
    Columns = []
    for _ in range(NumCols):
        (Col, Rest) = _decode_oac_fv2(Rest)
        Col['null_ok'] = 0 if Rest[0] == 0 else 1  # 0x00 NOT NULL, 0x01 nullable
        Rest = Rest[2:]  # null_ok(1B) + namelen_bytes(1B)
        (_NlChars, Rest) = decode_ub4(Rest)  # name length in chars (ub4)
        (Name, Rest) = decode_dalc(Rest)
        Col['column_name'] = Name if isinstance(Name, bytes) else b''
        Columns.append(Col)
        # two-byte inter-column separator
        if len(Rest) >= 2 and Rest[0] == 0 and Rest[1] == 0:
            Rest = Rest[2:]
    return Columns


def _encode_8i_bind_oac(Value: object) -> bytes:
    # 25-byte 8i bind descriptor, mirroring the describe column OAC
    # (decode_8i_dcb_describe): data type, ub4be [flag 0x03 | max_size], 14 bytes
    # reserved, ub4be character set, reserved, csform. Reverse-engineered from a
    # live 9.2-client -> 8.1.7 bind trace (docs/PROTOCOL.md §19.11). max_size is
    # the largest value we may send / receive for this bind: 22 (the NUMBER max)
    # for numbers, 7 for DATE, and the value byte length for VARCHAR2 / RAW. An
    # OUT / IN OUT `Var` declares its registered type + return-buffer size (#362).
    from seerdb.common.datatypes import Var

    if isinstance(Value, Var):
        DType = Value.dbtype.tns_type
        if DType == 2:  # NUMBER
            Charset, Csform, MaxSize = 0, 0, 22
        elif DType in (1, 96):  # VARCHAR2, CHAR
            Charset, Csform, MaxSize = 31, Value.dbtype.csfrm, max(Value.size, 1)
        elif DType == 12:  # DATE
            Charset, Csform, MaxSize = 0, 0, 7
        else:
            Charset, Csform, MaxSize = 0, 0, max(Value.size, 1)
    elif Value is None:
        DType, Charset, Csform, MaxSize = 1, 31, 1, 1  # NULL rides as VARCHAR2(1)
    elif isinstance(Value, (bool, int, float, Decimal)):
        DType, Charset, Csform, MaxSize = 2, 0, 0, 22  # NUMBER
    elif isinstance(Value, (bytes, bytearray)):
        DType, Charset, Csform, MaxSize = 23, 0, 0, max(len(Value), 1)  # RAW
    elif isinstance(Value, (datetime.datetime, datetime.date)):
        DType, Charset, Csform, MaxSize = 12, 0, 0, 7  # DATE
    else:  # str (and anything else via its str() form) -> VARCHAR2
        DType, Charset, Csform = 1, 31, 1
        MaxSize = max(len(str(Value).encode('latin-1')), 1)
    # max_size rides as a 2-byte LITTLE-endian field at offset +4 (8i is x86):
    # `type, 0x03, 00, 00, <max_size LE16>, …`. For values <= 255 this is
    # byte-identical to a 3-byte big-endian field, which is why short binds
    # worked; at >= 256 the little-endian form is required — otherwise the 8i
    # server mis-reads the size and rejects the bind as a LONG value (ORA-01461).
    return (
        bytes([DType, 0x03, 0, 0])
        + min(MaxSize, 0xFFFF).to_bytes(2, 'little')
        + bytes(13)
        + Charset.to_bytes(4, 'big')
        + bytes([0, Csform])
    )


# A pure-OUT bind sends no input value: the 8i value section carries this fixed
# placeholder in the bind's slot (#362, captured verbatim).
_O8I_OUT_PLACEHOLDER = bytes([0xFD, 0x01])


def _encode_8i_bind_value(Value: object) -> bytes:
    # The bind value as a DALC (length-prefixed). Strings ride as WE8ISO8859P1
    # (latin-1), matching the 8i DB charset; everything else reuses the shared
    # value encoder (Oracle NUMBER, DATE, RAW, …). A pure-OUT `Var` sends the OUT
    # placeholder; an IN OUT `Var` (has_value) sends its input value inline.
    from seerdb.common.datatypes import Var

    if isinstance(Value, Var):
        return (
            _encode_8i_bind_value(Value._value)
            if Value.has_value
            else _O8I_OUT_PLACEHOLDER
        )
    if isinstance(Value, str):
        return encode_token_rxd(Value.encode('latin-1'))
    return encode_token_rxd(Value)


# The op-specific middles (25 bytes) of the 8i TTI_LOBOPS requests, captured
# verbatim from a 9.2-client -> 8.1.7 session (docs/PROTOCOL.md §19.15 / §19.17):
# the CLOB/BLOB READ, and the BFILE FILE_OPEN / GETLEN / FILE_CLOSE (#401). The
# op family shares one envelope; only the middle and trailer vary.
_O8I_LOBOP_READ_MID = bytes.fromhex(
    '00000000000100000000000000000100020000000000000000'
)
_O8I_LOBOP_FOPEN_MID = bytes.fromhex(
    '00000000000000000000000000000100000100000000000000'
)
_O8I_LOBOP_GETLEN_MID = bytes.fromhex(
    '00000000000000000000000000000100010000000000000000'
)
_O8I_LOBOP_FCLOSE_MID = bytes.fromhex(
    '00000000000000000000000000000000000200000000000000'
)


def _encode_o8i_lobop(Seq: int, Locator: bytes, Middle: bytes, Trailer: bytes) -> bytes:
    # An 8i TTI_LOBOPS (0x60) request: `03 60 seq 01` + ub4-LE locator length +
    # the 25-byte op middle + the locator + an op-specific trailer. Lengths ride
    # LITTLE-endian (8i is x86). The whole envelope is captured ground truth.
    return (
        bytes([TTI_FUN, TTI_LOBOPS, Seq & 0xFF, 0x01])
        + len(Locator).to_bytes(4, 'little')
        + Middle
        + Locator
        + Trailer
    )


def encode_8i_lob_read(Seq: int, Locator: bytes, Amount: int) -> bytes:
    # 8i CLOB/BLOB/BFILE READ: unlike 9i's GETLEN + READ pair, 8i reads the value
    # in one call whose reply is the shared `0e fe <chunks> 00` LOB content
    # (decode_fv2_lob_chunks). `Amount` is chars for a CLOB, bytes for a BLOB /
    # BFILE; the trailer is the ub4-LE read amount.
    return _encode_o8i_lobop(
        Seq, Locator, _O8I_LOBOP_READ_MID, Amount.to_bytes(4, 'little')
    )


def encode_o8i_bfile_open(Seq: int, Locator: bytes) -> bytes:
    # 8i BFILE FILE_OPEN (#401): open the external file read-only. The trailer is
    # the ub4-LE open mode 0x0b (read-only). The reply's RPA carries an *updated*
    # locator with the open flag set — GETLEN / READ / CLOSE must use that one
    # (decode_fv2_opened_locator, shared with the 9i path). §19.17.
    return _encode_o8i_lobop(
        Seq, Locator, _O8I_LOBOP_FOPEN_MID, (0x0B).to_bytes(4, 'little')
    )


def encode_o8i_bfile_getlen(Seq: int, Locator: bytes) -> bytes:
    # 8i BFILE GETLEN (#401): ask for the file length. Trailer is a ub4-LE 0. The
    # reply carries the length as a ub4-LE after the locator (decode_o8i_bfile_getlen).
    return _encode_o8i_lobop(
        Seq, Locator, _O8I_LOBOP_GETLEN_MID, (0).to_bytes(4, 'little')
    )


def encode_o8i_bfile_close(Seq: int, Locator: bytes) -> bytes:
    # 8i BFILE FILE_CLOSE (#401): close the opened file. No trailer.
    return _encode_o8i_lobop(Seq, Locator, _O8I_LOBOP_FCLOSE_MID, b'')


def decode_o8i_bfile_getlen(Packet: bytes) -> int:
    # Pull the file length out of an 8i BFILE GETLEN reply (#401): TTI_RPA (08),
    # then the echoed `<ub1 len><body>` locator, then the ub4-LE length. The
    # locator's inner ub1 length sits at Packet[2], so the length starts at
    # 3 + that (the RPA byte + the leading 0 + the ub1-length-led body).
    if not Packet or Packet[0] != TTI_RPA or len(Packet) < 3:
        return 0
    off = 3 + Packet[2]
    return int.from_bytes(Packet[off : off + 4], 'little')


def decode_8i_block_out(Data: bytes, NumOut: int) -> list:
    # Decode the OUT / IN OUT return values from an 8i PL/SQL block reply
    # (docs/PROTOCOL.md §19.14). After the bind prompt (0x0b), the values ride a
    # single TTI_RXD (07) as `NumOut` × (DALC value + 2-byte trailer), in OUT-bind
    # position order. Returns the raw value bytes per OUT bind (None for empty /
    # NULL), decoded against each Var's declared type by the cursor.
    Rest = strip_fv2_bind_prompt(Data)
    OutValues: list = []
    if NumOut > 0 and Rest[:1] == bytes([TTI_RXD]):
        Rest = Rest[1:]
        for _ in range(NumOut):
            (Val, Rest) = decode_dalc(Rest)
            Rest = Rest[2:]  # sb2 indicator / return code
            OutValues.append(
                bytes(Val) if isinstance(Val, (bytes, bytearray)) and Val else None
            )
    return OutValues


# 8i statement-type codes (the OCI OCI_STMT_* family), carried at trailer offset
# +28 of the OALL8 and driving the whole option word. 0 = transaction control
# (COMMIT / ROLLBACK), which has no cursor.
O8I_STMT_SELECT = 1
O8I_STMT_UPDATE = 2
O8I_STMT_DELETE = 3
O8I_STMT_INSERT = 4
O8I_STMT_CREATE = 5
O8I_STMT_DROP = 6
O8I_STMT_ALTER = 7
O8I_STMT_BEGIN = 8
O8I_STMT_DECLARE = 9
O8I_STMT_TXN = 0

_O8I_STMT_TYPES = {
    'SELECT': O8I_STMT_SELECT,
    'UPDATE': O8I_STMT_UPDATE,
    'DELETE': O8I_STMT_DELETE,
    'INSERT': O8I_STMT_INSERT,
    'CREATE': O8I_STMT_CREATE,
    'DROP': O8I_STMT_DROP,
    'ALTER': O8I_STMT_ALTER,
    'TRUNCATE': O8I_STMT_CREATE,  # DDL, no rowcount; rides the CREATE code
    'BEGIN': O8I_STMT_BEGIN,
    'DECLARE': O8I_STMT_DECLARE,
}


def o8i_stmt_type(Head: str) -> int:
    # Map an upper-cased, stripped statement to its 8i OALL8 statement-type code.
    # COMMIT / ROLLBACK / SAVEPOINT / SET (transaction control) fall through to
    # O8I_STMT_TXN (0), which the encoder treats as a cursor-less statement.
    return _O8I_STMT_TYPES.get(Head.split(None, 1)[0] if Head else '', O8I_STMT_TXN)


def _encode_8i_oall8(Seq: int, Sql: bytes, StmtType: int, Binds: list) -> bytes:
    # The shared 8i OALL8 (TTI_ALL8, 0x5e) execute request (docs/PROTOCOL.md
    # §19.9, DML §19.12, binds §19.11). 8i CANNOT parse the modern (10g+) OALL8
    # this driver builds for every other tier — it answers that with an empty
    # packet and hangs up — so 8i needs this byte-compatible pre-10g form,
    # reverse-engineered from a live 9.2-client -> 8.1.7 trace. Everything about
    # the option word and trailer derives from `StmtType`:
    #   - option byte 0x21 base, + 0x40 for a query (SELECT fetches), + 0x08 with
    #     binds; the two option bytes after it are 0x80 0x00 for a cursor
    #     statement, 0x00 0x00 for txn control, and 0x00/0x04 0x04 for a PL/SQL
    #     block (the trailing 0x04 marks the block; the 0x04 before it flags binds)
    #   - trailer exec flag 0 for a query (execute is deferred to the fetch), 1
    #     otherwise; the statement type rides at +28.
    # The SQL length rides twice: an encode_sb4 count in the header, then the text
    # as a pre-10g chunked string (encode_chr — a plain length byte up to 64
    # bytes, else the 0xFE / 64-byte-chunk form). With binds the header carries
    # iteration count 1 + the bind count, and the bind section (all OACs, a 0x07
    # marker, then all values) follows the trailer. Pin the encode field version
    # to fv2 so encode_chr / encode_token_rxd take their pre-12c forms regardless
    # of any concurrent connection.
    NumBinds = len(Binds)
    IsQuery = StmtType == O8I_STMT_SELECT
    IsBlock = StmtType in (O8I_STMT_BEGIN, O8I_STMT_DECLARE)
    Token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_9_2)
    try:
        Option = 0x21 | (0x40 if IsQuery else 0) | (0x08 if NumBinds else 0)
        if IsBlock:
            Byte4, Byte5 = (0x04 if NumBinds else 0x00), 0x04
        else:
            Byte4, Byte5 = (0x80 if StmtType != O8I_STMT_TXN else 0x00), 0x00
        ExecFlag = 0 if IsQuery else 1
        Al8 = (
            bytes([0, 0, 0, 1, NumBinds, 0, 0, 0, 0, 0, 0, 0])  # iters=1, nbinds
            if NumBinds
            else bytes(12)
        )
        Message = (
            bytes([TTI_FUN, TTI_ALL8, Seq & 0xFF])
            + bytes([Option, Byte4, Byte5, 0, 0, 0, 0, 0])
            # SQL length: a 0x01 marker + a FIXED 4-byte LITTLE-endian count (8i
            # is x86). The earlier `encode_sb4` wrote a variable-width big-endian
            # field — byte-identical for a length <= 255 (`01 <len> 00 00 00`) but
            # one byte longer at >= 256, which shifted the whole request and the
            # server rejected it with ORA-01009 (#391).
            + bytes([0x01])
            + len(Sql).to_bytes(4, 'little')
            + bytes([0x01, 0x0C, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0x01, 0, 0, 0, 0])
            + Al8
            + bytes([0x01])
            + encode_chr(Sql.decode('latin-1'))  # SQL text (chunked if > 64 B)
            + bytes([0x01, 0, 0, 0, ExecFlag])
            + bytes(23)
            + bytes([StmtType])  # trailer +28: statement type
            + bytes(19)
        )
        if NumBinds:
            for Value in Binds:
                Message += _encode_8i_bind_oac(Value)
            Message += bytes([0x07])  # bind-value section marker
            for Value in Binds:
                Message += _encode_8i_bind_value(Value)
        return Message
    finally:
        _ENCODE_FIELD_VERSION.reset(Token)


def encode_8i_oall8_query(Seq: int, Sql: bytes, Binds: list | None = None) -> bytes:
    # 8i SELECT (statement type 1); see _encode_8i_oall8.
    return _encode_8i_oall8(Seq, Sql, O8I_STMT_SELECT, Binds or [])


def encode_8i_oall8_dml(
    Seq: int, Sql: bytes, StmtType: int, Binds: list | None = None
) -> bytes:
    # 8i INSERT/UPDATE/DELETE/DDL and COMMIT/ROLLBACK (docs/PROTOCOL.md §19.12) —
    # the same OALL8 as a query but with no fetch; the affected-row count comes
    # back in the response OER (decode_8i_dml_response).
    return _encode_8i_oall8(Seq, Sql, StmtType, Binds or [])


def encode_8i_oall8_fetch(
    Seq: int, Cursor: int, Count: int, LongSize: int = 0x7FFFFFFF
) -> bytes:
    # Oracle 8i array fetch: the 9.2-era OALL8 (0x5e) with the fetch option
    # (0x40) and no SQL, pulling up to `Count` more rows from an open cursor
    # (docs/PROTOCOL.md §19.10). 8i's execute returns only the first row batch;
    # the client fetches the rest until a batch comes back empty (ORA-01403).
    # Reverse-engineered from the 9.2-client trace; fixed apart from the TTI
    # sequence byte, the cursor id, and two ub4 LITTLE-endian counts:
    #   - offset 31: the LONG fetch size — the maximum bytes of a LONG / LONG RAW
    #     column the server returns per row. 8i truncates the value to this size
    #     (it does NOT continue one LONG across fetch round trips), so the caller
    #     passes a large cap to read the whole value (#377). For a query with no
    #     LONG column it is just a prefetch hint. An earlier version wrote the row
    #     count here as big-endian, whose low byte landed on this field and capped
    #     every LONG at `fetch` bytes.
    #   - offset 49: the number of rows to return this call (1 when a LONG column
    #     is present — 8i forces single-row fetches for LONGs).
    Msg = bytearray(93)
    Msg[0:4] = bytes([TTI_FUN, TTI_ALL8, Seq & 0xFF, 0x40])
    Msg[4:8] = Cursor.to_bytes(4, 'big')
    Msg[16:18] = bytes([0x01, 0x0C])
    Msg[22] = 0x01
    Msg[31:35] = min(LongSize, 0xFFFFFFFF).to_bytes(4, 'little')  # LONG fetch size
    Msg[44] = 0x01
    Msg[49:53] = Count.to_bytes(4, 'little')  # rows to fetch
    Msg[73] = 0x01
    return bytes(Msg)


def decode_8i_cursor_id(Terminal: bytes) -> int:
    # The server-assigned cursor id, needed to drive the 8i fetch loop. It sits
    # at offset 11 of the response's post-row terminal — whether that terminal
    # opens with the 0x08 session-state piggyback (08 04 00 11 89 05 00 00 00 00
    # 00 <cid>) or goes straight to the 0x04 OER (04 01 00 00 00 00 00 00 00 00
    # 00 <cid>); the cursor id is a ub2 at [10:12] in both. Returns 0 when the
    # terminal is too short (an empty result set), which suppresses the fetch.
    if len(Terminal) < 12:
        return 0
    return int.from_bytes(Terminal[10:12], 'big')


def _decode_8i_rowid(DataType: int, Val: bytes) -> str | None:
    # Render an 8i ROWID / UROWID column value (#385). A physical ROWID (type 11)
    # is a fixed-width little-endian struct — data object (ub4), relative file
    # (ub2), an unused byte, block (ub4), slot (ub2) — rendered as the extended
    # base64 form (matches ROWIDTOCHAR). A UROWID (type 208, e.g. an
    # index-organized table's logical rowid) renders as the "*"-prefixed base64
    # form (urowid_to_string), the same as the 10g+ path.
    from seerdb.common.types import rowid_to_string, urowid_to_string

    if not Val:
        return None
    if DataType == 208:
        return urowid_to_string(Val)
    Obj = int.from_bytes(Val[0:4], 'little')
    File = int.from_bytes(Val[4:6], 'little')
    Block = int.from_bytes(Val[7:11], 'little')
    Slot = int.from_bytes(Val[11:13], 'little')
    return rowid_to_string(Obj, File, Block, Slot)


def decode_8i_exec_response(
    Data: bytes, Columns: list, PrevRow: list | None = None
) -> tuple[list, bytes, list | None]:
    # Decode an 8i execute/fetch row stream: repeated TTI_RXH (06) + TTI_RXD (07)
    # pairs, one row per RXD, terminated by the 0x08 piggyback / 0x04 OER
    # (docs/PROTOCOL.md §19.10). Unlike the 9i fv2 rows (decode_fv2_exec_response,
    # a 1-byte indicator), each 8i column value is a DALC followed by a FIXED
    # 4-byte trailer — an sb2 indicator + ub2 return code, both zero when the
    # value is present. A NULL column carries no value DALC at all: it is the
    # 4-byte `ff ff 00 00` (indicator -1) on its own. Values are WE8ISO8859P1
    # (latin-1); decode_value uses the column charset.
    #
    # 8i compresses duplicate columns: the RXH carries a column bit vector
    # (`ub1 length` then the vector, at offset 14) whose UNSET bits mark columns
    # that REPEAT the previous row and so carry no bytes in the following RXD
    # (LSB = column 0; an empty vector means every column is present). Since 8i
    # fetches one batch per round trip, a row can repeat a column from the last
    # row of the PREVIOUS batch, so the caller threads `PrevRow` in and the last
    # decoded row back out. Returns (rows, terminal, last_row) where `terminal`
    # is the bytes from the first post-row token (for the cursor id / EOF check).
    from seerdb.common.lob import LOB
    from seerdb.common.types import decode_value, reset_decode_8i, set_decode_8i

    # All 8i char data is WE8ISO8859P1 (latin-1); flag the decode so
    # decode_value picks Latin-1 rather than the UTF-8 / UTF-16 a modern session
    # would use (#366). Reset afterwards so the flag never leaks to other tiers.
    _FlagToken = set_decode_8i(True)
    Rows: list = []
    Rest = Data
    Last = PrevRow
    BitVec = b''
    try:
        while Rest:
            Token = Rest[0]
            if Token == TTI_RXH:
                # The bit vector is `ub1 len` + `len` bytes at offset 14; the RXD
                # (0x07) follows after a short trailer (skip up to it). An empty
                # vector (len 0) means all columns are present.
                VecLen = Rest[14] if len(Rest) > 14 else 0
                BitVec = bytes(Rest[15 : 15 + VecLen])
                Idx = 15 + VecLen
                while Idx < len(Rest) and Rest[Idx] not in (
                    TTI_RXD,
                    TTI_OER,
                    TTI_RPA,
                ):
                    Idx += 1
                Rest = Rest[Idx:]
            elif Token == TTI_RXD:
                Rest = Rest[1:]
                Row: list = []
                for ColIdx, Col in enumerate(Columns):
                    Present = not BitVec or bool(
                        (BitVec[ColIdx >> 3] >> (ColIdx & 7)) & 1
                    )
                    if not Present:
                        # Repeated column: reuse the previous row's value.
                        Row.append(
                            Last[ColIdx] if Last and ColIdx < len(Last) else None
                        )
                    elif Rest and Rest[0] == 0xFF:
                        # NULL column: sb2 indicator 0xFFFF + ub2 return code
                        # 0x0000, with no value DALC.
                        Rest = Rest[4:]
                        Row.append(None)
                    elif Col.get('data_type') in (112, 113, 114):
                        # LOB column (CLOB/BLOB/BFILE). A NULL LOB is ub4-LE
                        # num_bytes == 0 followed *directly* by the 4-byte trailer
                        # (sb2 indicator -1 + ub2 rc), with NO locator. A non-NULL
                        # cell — including an EMPTY_CLOB/EMPTY_BLOB — carries
                        # num_bytes == the locator length, then the DALC locator,
                        # then the trailer; it becomes a LOB the connection
                        # resolves after the fetch (_resolve_8i_lobs), an empty one
                        # reading back as ''/b''. Calling decode_dalc on a NULL
                        # cell (which has no locator) ate the indicator's first
                        # byte and desynced every later row (#387).
                        NumBytes = int.from_bytes(Rest[0:4], 'little')
                        Rest = Rest[4:]
                        if NumBytes == 0:
                            Rest = Rest[4:]  # sb2 indicator (-1) + ub2 rc
                            Row.append(None)
                        else:
                            (Locator, Rest) = decode_dalc(Rest)
                            Rest = Rest[4:]  # sb2 indicator + ub2 rc
                            Row.append(
                                LOB(Col['data_type'], bytes(Locator))
                                if not isinstance(Locator, list)
                                else None
                            )
                    elif Col.get('data_type') == 11:
                        # Physical ROWID (#385): a 1-byte reserved-size indicator
                        # (0 = NULL), then the FIXED 13-byte rowid struct (it is
                        # NOT a length-prefixed DALC), then the 4-byte trailer.
                        Indicator = Rest[0]
                        Rest = Rest[1:]
                        if Indicator == 0:
                            Rest = Rest[4:]  # trailer
                            Row.append(None)
                        else:
                            Struct = bytes(Rest[:13])
                            Rest = Rest[13 + 4 :]  # struct + trailer
                            Row.append(_decode_8i_rowid(11, Struct))
                    elif Col.get('data_type') == 208:
                        # UROWID (#385): a 1-byte indicator (0 = NULL), a reserved
                        # byte, a 1-byte body length, the logical-rowid body, then
                        # the 4-byte trailer.
                        Indicator = Rest[0]
                        if Indicator == 0:
                            Rest = Rest[1 + 4 :]
                            Row.append(None)
                        else:
                            BodyLen = Rest[2]
                            Body = bytes(Rest[3 : 3 + BodyLen])
                            Rest = Rest[3 + BodyLen + 4 :]  # header + body + trailer
                            Row.append(_decode_8i_rowid(208, Body))
                    else:
                        (Val, Rest) = decode_dalc(Rest)
                        Rest = Rest[4:]  # sb2 indicator (0) + ub2 return code (0)
                        Row.append(decode_value(Col, Val))
                Rows.append(Row)
                Last = Row
                BitVec = b''
            else:
                break
    finally:
        reset_decode_8i(_FlagToken)
    return (Rows, Rest, Last)


def _scan_ora_message(Data: bytes) -> tuple[int, str | None]:
    # Locate a server "ORA-NNNNN: ..." error in a response and return
    # (code, message), or (0, None) if there is none. Used for 8i non-query
    # responses, whose binary OER layout differs from 9i's — scanning the
    # human-readable text is layout-independent.
    Idx = Data.find(b'ORA-')
    if Idx < 0:
        return (0, None)
    Digits = Data[Idx + 4 : Idx + 9]
    if not Digits.isdigit():
        return (0, None)
    End = Data.find(b'\x00', Idx)
    Message = (
        Data[Idx : End if End >= 0 else len(Data)].decode('latin-1', 'replace').rstrip()
    )
    return (int(Digits), Message)


def decode_8i_dml_response(Data: bytes) -> tuple[int, int, str | None]:
    # Decode an 8i non-query (DML / DDL / transaction-control) response
    # (docs/PROTOCOL.md §19.12): a 0x08 RPA session-state piggyback (a fixed 23
    # bytes on 8i) then the OER, whose first field after the token is the
    # affected-row count as a LITTLE-endian ub4 (8i is x86 / Windows, so the
    # count rides native-endian — e.g. 300 = `2c 01 00 00`). Returns (rowcount,
    # ora_code, message); a server error is surfaced from the trailing
    # "ORA-NNNNN: ..." text so a failed statement raises instead of reporting a
    # bogus count.
    (ErrCode, Message) = _scan_ora_message(Data)
    Rest = Data[23:] if Data[:1] == bytes([TTI_RPA]) else Data
    RowCount = 0
    if not ErrCode and Rest[:1] == bytes([TTI_OER]):
        RowCount = int.from_bytes(Rest[1:5], 'little')
    return (RowCount, ErrCode, Message)


def decode_8i_dcb_describe(Data: bytes) -> tuple[list[dict], bytes]:
    # Oracle 8i answers the modern OALL8 (0x5e) execute with a TTI_DCB (0x10)
    # describe block whose header and per-column descriptors use FIXED-width
    # big-endian fields — NOT the ub1-length-prefixed ub4s the 10g+ DCB
    # (decode_token_dcb) expects. The modern decoder therefore reads num_columns
    # as 0 and desyncs, so 8i needs this dedicated parser. Reverse-engineered
    # from a live 9.2-client -> 8.1.7 SQL*Net trace (docs/PROTOCOL.md §19.9).
    # Returns (columns, rest) where `rest` begins at the fv2 row stream
    # (TTI_RXH / TTI_RXD / TTI_OER), which decode_fv2_exec_response consumes.
    #
    # Layout (offsets into the TTC payload):
    #   0        TTI_DCB (0x10)
    #   1        ub1 preamble length (0x19 = 25) — SCN + 7-byte date, skipped
    #   2..      preamble bytes
    #   header:  ub1 row width (sum of column widths, skipped)
    #            ub4be num_columns
    #            ub4be constant 0x33 (skipped)
    #   per column (num_columns times):
    #     +0      ub1  data type (1=VARCHAR2, 2=NUMBER, 96=CHAR, …)
    #     +1..+4  ub4be size field. For a NUMBER: `00 <precision> <scale sb1>
    #             <internal size 22>` (#386). For other types: bit31 = character
    #             flag, low 31 bits = max_size.
    #     +5..+18 14 reserved bytes (always 0 in captures)
    #     +19..22 ub4be character set id (31 = WE8ISO8859P1; 0 for NUMBER)
    #     +23     reserved (0)
    #     +24     ub1 csform (1 = character type, 0 = number)
    #     +25     ub1 null_ok (0 = NOT NULL, 1 = nullable)
    #     +26,+27 ub1 name length (twice)
    #     +28..31 ub4be name length
    #     +32..   name bytes (name length)
    #     +…      8-byte inter-column trailer (type-OID slot; 0 for scalar types)
    #   trailer  8i bytes-with-length current date: ub1 len, ub4be len, len bytes
    PreLen = Data[1]
    Off = 2 + PreLen  # skip the SCN/date preamble
    # Header: max row width, then num_columns — both LITTLE-endian ub4 (8i is
    # x86, so these ride native-endian; a wide row like a CLOB's 4000-byte width
    # is `a0 0f 00 00`). Then the constant 0x33 byte.
    Off += 4  # max row width (ub4 LE)
    NumCols = int.from_bytes(Data[Off : Off + 4], 'little')
    Off += 4
    Off += 1  # constant 0x33
    Columns: list[dict] = []
    for _ in range(NumCols):
        DataType = Data[Off]
        SizeField = int.from_bytes(Data[Off + 1 : Off + 5], 'big')
        if DataType == 2:
            # NUMBER family: the 4-byte size field packs `00 <precision>
            # <scale sb1> <internal size (22)>` — NOT a plain max_size (#386).
            # e.g. NUMBER(6,2) = `00 06 02 16`, NUMBER(38) = `00 26 00 16`.
            # Match the modern describe: max_size 0 (a NUMBER's display size is
            # derived from precision/scale), data_length = the 22-byte buffer.
            Precision = (SizeField >> 16) & 0xFF
            Scale = (SizeField >> 8) & 0xFF
            if Scale > 127:
                Scale -= 256  # scale is signed (e.g. NUMBER(5, -2))
            DataLength = SizeField & 0xFF
            MaxSize = 0
        else:
            Precision = 0
            Scale = 0
            MaxSize = SizeField & 0x7FFFFFFF  # bit31 is the character-type flag
            DataLength = MaxSize
        Charset = int.from_bytes(Data[Off + 19 : Off + 23], 'big')
        Csform = Data[Off + 24]
        NullOk = 0 if Data[Off + 25] == 0 else 1
        NameLen = int.from_bytes(Data[Off + 28 : Off + 32], 'big')
        Name = bytes(Data[Off + 32 : Off + 32 + NameLen])
        Columns.append(
            {
                'data_type': DataType,
                'data_length': DataLength,
                'data_scale': Scale,
                'precision': Precision,
                'max_size': MaxSize,
                'charset': Charset,
                'csfrm': Csform,
                'null_ok': NullOk,
                'domain_schema': None,
                'domain_name': None,
                'column_name': Name,
            }
        )
        Off += 32 + NameLen + 8  # descriptor + name + type-OID trailer
    # Describe trailer: the current date as an 8i bytes-with-length value
    # (ub1 len, ub4be len, data) — the same pre-10g coding the OSESSKEY login
    # uses. Skip it to land on the first row token (TTI_RXH / TTI_RXD).
    TLen = int.from_bytes(Data[Off + 1 : Off + 5], 'big')
    Off += 1 + 4 + TLen
    return (Columns, Data[Off:])


def _decode_fv2_oer(Rest: bytes) -> tuple[int, int, bytes]:
    # Minimal fv2 (9i) OER: the short pre-10g form. The exec+fetch terminates
    # with `04 <ub4 rows-this-fetch> <ub4 ORA code> …`; ORA-01403 ("no data
    # found") is the end-of-fetch marker, 0 is success (PROTOCOL.md §19.2). We
    # only need the status + error code; the message DALC trailing the fixed
    # middle is left to from_ora_code() in the caller.
    Rest = Rest[1:]  # OER token
    (RowsThisFetch, Rest) = decode_ub4(Rest)
    (ErrCode, Rest) = decode_ub4(Rest)
    return (RowsThisFetch, ErrCode, Rest)


def decode_fv2_oer_error(Packet: bytes) -> tuple[int, str | None]:
    # If `Packet` is a 9i OER token, return its (ora_code, message); otherwise
    # (0, None). Used to surface a parse/execute-time server error (e.g.
    # ORA-00942) with the server's own text instead of letting the caller march
    # on into a desync (#102). The human-readable "ORA-NNNNN: ..." is the
    # trailing length-prefixed string; the fixed middle fields between the error
    # code and it are version-specific, so locate the message as the final DALC
    # rather than walking every field.
    if not Packet or Packet[0] != TTI_OER:
        return (0, None)
    (_Rows, ErrCode, Rest) = _decode_fv2_oer(Packet)
    Message = None
    for I in range(len(Rest)):
        Length = Rest[I]
        if Length and I + 1 + Length == len(Rest):
            Message = bytes(Rest[I + 1 :]).decode('utf-8', errors='replace').rstrip()
            break
    return (ErrCode, Message)


def decode_fv2_exec_response(Data: bytes, Columns: list) -> tuple[list, int]:
    # Walk the fv2 (9i) execute+fetch response stream: TTI_RXH (06) then one
    # TTI_RXD (07) per row, terminated by the short TTI_OER (04). The 9i row
    # framing differs from 10g+: the RXH has no trailing bit-vector / rowid, and
    # each column value is a DALC blob followed by a 1-byte indicator. Row
    # values themselves use the version-independent §11 decoders. Returns
    # (rows, ora_code) where ora_code 1403 == end-of-fetch (PROTOCOL.md §19.2).
    from seerdb.common.lob import LOB
    from seerdb.common.types import decode_value

    Rows: list = []
    ErrCode = 0
    Rest = Data
    while Rest:
        Token = Rest[0]
        if Token == TTI_RXH:
            # token + 1B flags, then a run of small ub4 counts (numreq, iter,
            # numiters, buffer length, …). The count of trailing fields varies,
            # so consume ub4s until the next token appears. Safe because every
            # RXH field is a small value (width byte 0x00/0x01), never a token
            # byte (RXD 0x07 / OER 0x04 / RXH 0x06).
            Rest = Rest[2:]
            while Rest and Rest[0] not in (TTI_RXD, TTI_OER, TTI_RXH):
                (_, Rest) = decode_ub4(Rest)
        elif Token == TTI_RXD:
            Rest = Rest[1:]
            Row: list = []
            for Col in Columns:
                DataType = Col.get('data_type')
                if DataType in (112, 113, 114):
                    # CLOB / BLOB / BFILE. A present cell is a LOB locator (ub4
                    # num_bytes + DALC locator) followed by a 1-byte 0x00
                    # indicator; _read_lob_column extracts the locator and the
                    # connection round-trips it via TTI_LOBOPS (the fv2 dialect lob_read for
                    # CLOB/BLOB; bfile_read — FILE_OPEN/READ/CLOSE — for
                    # BFILE). A NULL LOB uses the scalar empty-value form instead
                    # — `00 81 01` (an empty DALC then the `81 01` null
                    # indicator). A present locator's num_bytes is always >= its
                    # minimum (first byte 0x01), so a leading 0x00 means NULL.
                    if Rest[:1] == b'\x00':
                        Rest = Rest[1:]  # empty DALC
                        if Rest[:1] == b'\x81':
                            Rest = Rest[2:]  # 81 01 null indicator
                        Row.append(None)
                    else:
                        (Locator, Rest) = _read_lob_column(Rest)
                        Rest = Rest[1:]  # present indicator (0x00)
                        Row.append(
                            LOB(DataType, Locator) if Locator is not None else None
                        )
                    continue
                # The value is a DALC; decode_dalc handles the 0xfe chunked form
                # that LONG / LONG RAW stream in (in batch fetch they arrive
                # inline as a plain chunked value, no trailing descriptor).
                (Val, Rest) = decode_dalc(Rest)
                # Per-column indicator: 0x00 = value present (one byte); 0x81 =
                # NULL, a two-byte (81 01) marker following an empty value.
                if Rest and Rest[0] == 0x81:
                    Rest = Rest[2:]
                    Row.append(None)
                elif DataType in (TNS_TYPE_RID, TNS_TYPE_ROWID, TNS_TYPE_UROWID):
                    # Defined as VARCHAR (see _o7_define_entry), so the value is
                    # already the rowid text — decode it directly, not via the
                    # native ROWID decoder.
                    Rest = Rest[1:]
                    Row.append(bytes(Val).decode('ascii', 'replace') if Val else None)
                else:
                    Rest = Rest[1:]
                    Row.append(decode_value(Col, Val))
            Rows.append(Row)
        elif Token == TTI_OER:
            (_, ErrCode, Rest) = _decode_fv2_oer(Rest)
            break
        else:
            break
    return (Rows, ErrCode)


def decode_fv2_dml_response(Data: bytes) -> tuple[int, int]:
    # 9i DML (INSERT/UPDATE/DELETE) over TTI_ALL7: a single parse-executes the
    # statement; the response is an RPA piggyback followed by the short OER
    # whose first field is the affected-row count and second the ORA code
    # (0 = success). Returns (rowcount, ora_code). #101.
    if not Data:
        return (0, 0)
    Rest = Data
    if Rest[0] == TTI_RPA:
        # Skip the RPA piggyback (same shape as decode_token_rpa_piggyback):
        # read the field count, consume that many ub4s, skip alignment zeros,
        # leaving the stream on the trailing OER token.
        Rest = Rest[1:]
        (Num, Rest) = decode_ub4(Rest)
        for _ in range(max(Num, 0)):
            if not Rest or Rest[0] in (TTI_OER, TTI_RXH, TTI_RXD, TTI_STA):
                break
            (_, Rest) = decode_ub4(Rest)
        while Rest and Rest[0] == 0:
            Rest = Rest[1:]
    if Rest and Rest[0] == TTI_OER:
        (RowCount, ErrCode, _) = _decode_fv2_oer(Rest)
        return (RowCount, ErrCode)
    return (0, 0)


# Token that opens the 9i bind-values prompt the server sends after a PL/SQL
# block parse-execute carrying binds: `0b 05 01 <numbinds> 00 01 01 00` then one
# direction byte per bind (0x20 = IN, 0x10 = OUT, 0x30 = IN OUT). #102.
_FV2_BIND_PROMPT = 0x0B


def strip_fv2_bind_prompt(Data: bytes) -> bytes:
    # Drop a leading bind prompt, if present, returning the bytes that follow
    # (the OUT-value RXD + RPA + OER). A pure-OUT block's reply packs the prompt,
    # the return values and the call status together; an IN / IN OUT block sends
    # the prompt in its own packet (consumed before the values are sent), so this
    # is a no-op there. The prompt is `0b 05 01 <numbinds> 00 01 01 00` then a
    # direction section (bytes 0x00 / 0x10 / 0x20 / 0x30 — IN/OUT/IN OUT masks
    # and padding) whose exact length varies, so rather than computing it we scan
    # past the 8-byte fixed prefix to the first RXD (07) or RPA (08) token — the
    # prompt itself never contains either. (#102, PROTOCOL §19.7)
    if len(Data) >= 8 and Data[0] == _FV2_BIND_PROMPT:
        Pos = 8
        while Pos < len(Data) and Data[Pos] not in (TTI_RXD, TTI_RPA):
            Pos += 1
        return Data[Pos:]
    return Data


def decode_fv2_block_out(Data: bytes, NumOut: int) -> tuple[list, int, int]:
    # Parse a 9i PL/SQL block reply that returns OUT / IN OUT values (#102,
    # PROTOCOL §19.7). After any bind prompt is stripped, the reply is an
    # optional TTI_RXD (07) carrying `NumOut` × (DALC value + 1-byte indicator)
    # in OUT-bind position order, then the RPA + short OER. Returns
    # (out_values, rowcount, ora_code); out_values holds the raw value bytes per
    # OUT bind (None for a NULL OUT), to be decoded by the caller against each
    # Var's declared type.
    Rest = strip_fv2_bind_prompt(Data)
    OutValues: list = []
    if NumOut > 0 and Rest and Rest[0] == TTI_RXD:
        Rest = Rest[1:]
        for _ in range(NumOut):
            (Val, Rest) = decode_dalc(Rest)
            if Rest and Rest[0] == 0x81:  # 81 01 NULL indicator
                Rest = Rest[2:]
                OutValues.append(None)
            else:
                if Rest:
                    Rest = Rest[1:]  # present indicator (00)
                OutValues.append(
                    bytes(Val) if isinstance(Val, (bytes, bytearray)) and Val else None
                )
    (RowCount, ErrCode) = decode_fv2_dml_response(Rest)
    return (OutValues, RowCount, ErrCode)


def encode_dictionary_lobops(Dictionary: dict) -> bytes:
    # TTI_LOBOPS request. See docs/PROTOCOL.md §14 for the field layout.
    # This builds a READ request specifically (operation = 0x0002) since
    # that's all the driver currently issues; other opcodes plug into the
    # same shape by varying `operation` and the pointer flags.
    Tseq = Dictionary['seq']
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    LobHead = _fun_header(TTI_LOBOPS, Tseq, FieldVersion)
    if Dictionary.get('create_temp'):
        # CREATE_TEMP (op 0x0110, #91): allocate a session-duration temporary
        # LOB; the server returns the new locator in the response RPA. The body
        # is fixed (no source locator), captured verbatim from python-oracledb
        # on 21c — it differs between CLOB (type 0x70) and BLOB (type 0x71) in
        # the type-spec bytes, and both forms still end with the trailing sb4
        # 0x0369. 12c+ only; 11g rejects CREATE_TEMP.
        if Dictionary.get('is_blob'):
            Body = (
                bytes.fromhex('01012800010a00000100010201100000000171')
                + bytes(47)
                + bytes.fromhex('020369')
            )
        else:
            Body = (
                bytes.fromhex('01012800010a0000010001020110000001010170')
                + bytes(47)
                + bytes.fromhex('020369')
            )
        return LobHead + Body
    if Dictionary.get('operation') == TNS_LOB_OP_WRITE:
        # WRITE (op 0x0040, #91): push `data` into the LOB at `source_offset`.
        # Reverse-engineered from python-oracledb on 21c (small + 60 KB CLOB
        # writes, byte-for-byte). Differences from the READ shape above:
        #   * operation = 0x0040
        #   * the source-locator-length field counts the ub2 length prefix too
        #     (len + 2), and the locator is sent as <ub2 len><bytes> rather than
        #     raw — READ declares the bare length and sends the locator raw
        #   * the amount pointer is absent (no trailing sb4 amount); the payload
        #     is appended instead as a 0x0E marker + a chunked-bytes field:
        #       <ub1 len><data>                       when len <= 0xFC, else
        #       0xFE (<sb4 chunklen><chunk>)... <00>   (chunks <= 0x7FFF bytes)
        # CLOB data must already be UTF-16BE; BLOB data is raw bytes.
        Locator = Dictionary['locator']
        Data = Dictionary['data']
        SourceOffset = Dictionary.get('source_offset', 1)
        Out = LobHead
        Out += bytes([1])  # source pointer present
        Out += encode_sb4(len(Locator) + 2)  # source locator length (+ub2)
        Out += bytes([0])  # dest pointer absent
        Out += encode_sb4(0)  # dest_length
        Out += encode_sb4(0)  # short source offset
        Out += encode_sb4(0)  # short dest offset
        Out += bytes([0])  # charset pointer absent
        Out += bytes([0])  # short amount absent
        Out += bytes([0])  # null lob pointer absent
        Out += encode_sb4(TNS_LOB_OP_WRITE)  # operation code
        Out += bytes([0])  # scn array pointer absent
        Out += bytes([0])  # scn array length
        Out += encode_sb4(SourceOffset)  # source offset (ub8)
        Out += encode_sb4(0)  # dest offset (ub8)
        Out += bytes([0])  # amount pointer absent
        Out += struct.pack('>HHH', 0, 0, 0)  # three reserved ub16be slots
        Out += struct.pack('>H', len(Locator))  # ub2 locator length prefix
        Out += Locator
        Out += bytes([0x0E])  # WRITE-data marker
        if len(Data) <= 0xFC:
            Out += bytes([len(Data)]) + Data
        else:
            Out += bytes([0xFE])
            for K in range(0, len(Data), 0x7FFF):
                Chunk = Data[K : K + 0x7FFF]
                Out += encode_sb4(len(Chunk)) + Chunk
            Out += encode_sb4(0)  # zero-length terminator
        return Out
    if Dictionary.get('operation') in (TNS_LOB_OP_FILE_OPEN, TNS_LOB_OP_FILE_CLOSE):
        # BFILE open / close (#46). Same field block as READ but with source
        # offset 0 and no read amount. FILE_OPEN sets the amount pointer and
        # sends the open mode (sb4 0x0B = read-only) where READ sends the read
        # amount; FILE_CLOSE sends neither. The locator is ub2-length-prefixed
        # (declared len + 2), like every temp / BFILE LOBOPS. Reverse-engineered
        # from python-oracledb on 21c, byte-for-byte.
        Locator = Dictionary['locator']
        Operation = Dictionary['operation']
        IsOpen = Operation == TNS_LOB_OP_FILE_OPEN
        Out = LobHead
        Out += bytes([1])  # source pointer present
        Out += encode_sb4(len(Locator) + 2)  # source locator length (+ub2)
        Out += bytes([0])  # dest pointer absent
        Out += encode_sb4(0)  # dest_length
        Out += encode_sb4(0)  # short source offset
        Out += encode_sb4(0)  # short dest offset
        Out += bytes([0])  # charset pointer absent
        Out += bytes([0])  # short amount absent
        Out += bytes([0])  # null lob pointer absent
        Out += encode_sb4(Operation)  # operation code
        Out += bytes([0])  # scn array pointer absent
        Out += bytes([0])  # scn array length
        Out += encode_sb4(0)  # source offset (ub8)
        Out += encode_sb4(0)  # dest offset (ub8)
        Out += bytes([1 if IsOpen else 0])  # amount pointer (open mode)
        Out += struct.pack('>HHH', 0, 0, 0)  # three reserved ub16be slots
        Out += struct.pack('>H', len(Locator)) + Locator  # ub2-prefixed
        if IsOpen:
            Out += encode_sb4(0x0B)  # open mode: read-only
        return Out
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
    SourceOffset = Dictionary.get('source_offset', 1)  # 1-based: start
    LocatorLen = len(Locator)

    Out = LobHead
    Out += bytes([1])  # source pointer present
    # Persistent-LOB locators read back correctly with the bare length + raw
    # locator. Temporary LOBs (#91) instead need the locator sent as a
    # ub2-length-prefixed field with the declared length counting that prefix
    # (len + 2) — exactly the form python-oracledb uses; without it a temp-LOB
    # read returns empty content. Switching persistent reads to the prefixed
    # form regresses them on 11g + 21c, so the prefix is opt-in per call.
    Prefixed = Dictionary.get('locator_prefixed', False)
    Out += encode_sb4(LocatorLen + 2 if Prefixed else LocatorLen)  # src loc len
    Out += bytes([0])  # dest pointer absent
    Out += encode_sb4(0)  # dest_length
    Out += encode_sb4(0)  # short source offset
    Out += encode_sb4(0)  # short dest offset
    Out += bytes([0])  # charset pointer absent
    Out += bytes([0])  # short amount absent
    Out += bytes([0])  # null lob pointer absent
    Out += encode_sb4(Operation)  # operation code
    Out += bytes([0])  # scn array pointer absent
    Out += bytes([0])  # scn array length
    Out += encode_sb4(SourceOffset)  # source offset (ub8; small fits sb4)
    Out += encode_sb4(0)  # dest offset (ub8)
    Out += bytes([1])  # amount pointer present
    Out += struct.pack('>HHH', 0, 0, 0)  # three reserved ub16be slots
    if Prefixed:
        Out += struct.pack('>H', LocatorLen) + Locator  # ub2-prefixed locator
    else:
        Out += Locator  # raw locator bytes (no DALC)
    Out += encode_sb4(Amount)  # amount to read
    return Out


def encode_dictionary_login(Dictionary: dict) -> bytes:
    # The CONNECT packet, in the protocol-version-319 ("large SDU" / end-of-
    # response era) layout (#155). seerdb previously sent version 313 to stay
    # below the EOR era; 319 is what a 23ai server needs to negotiate the
    # end-of-response framing that pipelining (#132) rides on. The header is
    # backward-compatible: 9i/10g/11g negotiate down (min(their_max, 319)) and
    # keep the legacy DATA framing, while a >=315 server switches to the 4-byte
    # ("large") packet length — see encode_packet/assemble_packet and the accept
    # handler that flips self._large_packets. The connect-data offset is 74 (the
    # legacy 58 plus the 16 trailing bytes: large SDU/TDU + connect flags).
    Sdu = Dictionary['sdu']
    PacketVersion = struct.pack('>H', 319)
    # Lowest compatible version we accept. The server negotiates
    # min(its_max, our PacketVersion); it REFUSES the connect if that is below
    # our floor. Oracle 9i's max protocol version is 312, so the 300 floor lets
    # 9i settle on 312 while newer servers negotiate up to 319 (#90).
    LowestCompatVersion = struct.pack('>H', 300)
    GSO = struct.pack('>H', 0x0401)  # global/service options
    SDU = struct.pack('>H', Sdu)
    TDU = struct.pack('>H', Sdu)
    ProtocolCharacteristics = struct.pack('>H', 0x4F98)
    MaxUnackPackets = bytes([0, 0])  # Max packets before ACK
    Endiannes = struct.pack('>h', 1)  # 1 in hardware byte order
    Data = encode_dictionary_description(Dictionary)
    DataLength = struct.pack('>H', len(Data))  # Connect Data length
    CDO = struct.pack('>H', 74)  # Connect Data offset (legacy 58 + 16 trailing)
    MaxConnDataRecv = bytes(4)  # Max connect data that can be received
    ANO = bytes([1, 1])  # advertise ANO (native encryption) capable (#437)
    Padding = bytes(24)
    # The 319-era trailing block before the connect data: 32-bit SDU and TDU,
    # then connect_flags_1 (0) and connect_flags_2 (1 = OOB check), per capture.
    Trailer = (
        struct.pack('>I', Sdu)
        + struct.pack('>I', Sdu)
        + struct.pack('>I', 0)
        + struct.pack('>I', 1)
    )
    return (
        PacketVersion
        + LowestCompatVersion
        + GSO
        + SDU
        + TDU
        + ProtocolCharacteristics
        + MaxUnackPackets
        + Endiannes
        + DataLength
        + CDO
        + MaxConnDataRecv
        + ANO
        + Padding
        + Trailer
        + Data
    )


def encode_dictionary_pig(Dictionary: dict) -> bytes:
    Request = Dictionary['req']  # single function-code byte (ping works)
    Tseq = Dictionary['seq']
    CursorsLen = encode_sb4(len(Dictionary['cursor']))
    Cursors = reduce(lambda x, y: x + y, [encode_sb4(C) for C in Dictionary['cursor']])
    return bytes([TTI_PFN, Request, Tseq, 1]) + CursorsLen + Cursors


def encode_dictionary_pro(Dictionary: dict) -> bytes:
    # TTI_PRO request: the descending TTC protocol-version vector (6..0) then a
    # NUL-terminated client self-identifier. A real Oracle client puts its
    # platform here (e.g. "x86_64/Linux"); we prefix a driver tag so the value is
    # informative and identifies seerdb, instead of the bare "python" we sent
    # before (#381). ASCII with a safe fallback — the field is a plain byte
    # string, and the server accepts an arbitrary length (verified 9i–23ai).
    Banner = f'seerdb {platform.machine()}/{platform.system()}'.encode(
        'ascii', 'replace'
    )
    return bytes([TTI_PRO, 6, 5, 4, 3, 2, 1, 0]) + Banner + bytes([0])


def encode_fast_auth(Pro: bytes, Dty: bytes, Sess: bytes) -> bytes:
    """Bundle the protocol, datatypes, and OSESSKEY (phase-one) messages into a
    single 23ai FAST_AUTH message (#89). Sending the legacy three messages
    separately is rejected with ORA-03146 once the client advertises a field
    version >= 18, so a fast-auth-capable server (it sets TNS_ACCEPT_FLAG_FAST_AUTH
    in the ACCEPT) gets this one packet instead. Layout reverse-engineered and
    byte-validated against a python-oracledb fv24 capture (docs/PROTOCOL.md §20):

        0x22 ver=1 SERVER_CONVERTS_CHARS flag2=0
        <PRO message>
        charset(ub2)=0  flag(ub1)=0  ncharset(ub2)=0
        ttc_field_version byte = FIELD_VERSION_19_1_EXT1
        <DTY message>            (its caps array still advertises the real fv)
        <OSESSKEY message>
    """
    return (
        bytes([TNS_MSG_TYPE_FAST_AUTH, 1, TNS_SERVER_CONVERTS_CHARS, 0])
        + Pro
        + b'\x00\x00\x00\x00\x00'
        + bytes([FIELD_VERSION_19_1_EXT1])
        + Dty
        + Sess
    )


def find_fast_auth_rpa(Body: bytes) -> int:
    """Return the offset of the auth-challenge TTI_RPA inside a bundled fast-auth
    response (PRO response + DTY response + RPA). The DTY datatype table contains
    0x08 bytes, so a naive token scan mis-hits; instead accept the first TTI_RPA
    whose decode yields the OSESSKEY challenge (a non-empty session key)."""
    for Off in range(len(Body)):
        if Body[Off] != TTI_RPA:
            continue
        try:
            Result = decode_token_rpa(Body[Off + 1 :], ())
        except Exception:
            continue
        if Result[0] == TTI_SESS and Result[1]:
            return Off
    return -1


def encode_dictionary_sess(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    Hostname = encode_kv(b'AUTH_MACHINE', socket.gethostname().encode('utf-8'))
    Pid = encode_kv(b'AUTH_PID', str(os.getpid()).encode('utf-8'))
    User = Dictionary['env']['user'].encode('utf-8')
    SID = encode_kv(b'AUTH_SID', Dictionary['env']['user'].encode('utf-8'))
    UserLen = encode_sb4(len(Dictionary['env']['user']))
    Role = Dictionary['env'].get('role', 0)
    Prelim = Dictionary['env'].get('prelim', 0)
    LogonMode = encode_sb4((Role * 32) | (Prelim * 128) | 1)
    AppName = encode_kv(
        b'AUTH_PROGRAM_NM',
        Dictionary['env'].get('app_name', 'seerdb').encode('utf-8'),
    )

    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    if FieldVersion >= FIELD_VERSION_12_1:
        # 12c+ OSESSKEY (python-oracledb auth.pyx _write_message phase one):
        # the username is length-prefixed (write_bytes_with_length) and the
        # pair count is 5, leading with AUTH_TERMINAL. 11g instead reads the
        # username by the earlier UserLen field and sends 4 pairs; sending the
        # 12c shape to 11g (or vice-versa) desyncs the server's parse.
        Terminal = encode_kv(b'AUTH_TERMINAL', b'unknown')
        UserField = bytes([len(User)]) + User
        return (
            bytes([TTI_FUN, TTI_SESS, Tseq, 1])
            + UserLen
            + LogonMode
            + bytes([1])
            + encode_sb4(5)
            + bytes([1, 1])
            + UserField
            + Terminal
            + AppName
            + Hostname
            + Pid
            + SID
        )

    return (
        bytes([TTI_FUN, TTI_SESS, Tseq, 1])
        + UserLen
        + LogonMode
        + bytes([1])
        + encode_sb4(4)
        + bytes([1, 1])
        + User
        + AppName
        + Hostname
        + Pid
        + SID
    )


# Pre-10g (9i) thin authentication uses O3LOGON: TTI_3LOGA (0x52) to fetch the
# session key, then TTI_3LOGON (0x51) to send the password (#90). The OSESSKEY
# path above (TTI_SESS) is what 10g+ thin clients and OCI use; 9i's field
# version 2 expects this older positional message instead. The two encoders
# below reproduce the Oracle JDBC thin driver's 9i messages byte-for-byte
# (verified — see tests/test_tns_encode.py). The terminal/machine/osuser/program
# strings are session metadata the server does not authenticate on, so we send
# the same values JDBC does; only the username and (phase two) the password vary.
_O3_ENV = b'unknown' + b'o9i' + b'root' + b'JDBC Thin Client'
# Fixed header skeleton between the length fields and the string blob, captured
# from JDBC (it bakes in the env-string lengths above).
_O3_MID1 = bytes.fromhex(
    '00000000000001010701010301010402100000000101100000000001011001'
)
_O3_MID2 = bytes.fromhex('0000000001010701010301010402100000000101100000000000011000')


def encode_o3logon_phase1(Seq: int, User: bytes) -> bytes:
    # TTI_3LOGA: request the session key. No password field.
    return (
        bytes([TTI_FUN, TTI_3LOGA, Seq, 1])
        + encode_sb4(len(User))
        + _O3_MID1
        + User
        + _O3_ENV
    )


def encode_o3logon_phase2(Seq: int, User: bytes, PwdField: bytes) -> bytes:
    # TTI_3LOGON: send the AUTH_PASSWORD (hex(DES blocks) + decimal pad count).
    return (
        bytes([TTI_FUN, TTI_3LOGON, Seq, 1])
        + encode_sb4(len(User))
        + bytes([1])
        + encode_sb4(len(PwdField))
        + _O3_MID2
        + User
        + PwdField
        + _O3_ENV
    )


# --- Oracle 8i (8.1.7) O3LOGON via the OSESSKEY/OAUTH envelope ---------------
# 8i uses the same DES O3LOGON *crypto* as 9i, but wraps it in the OSESSKEY
# (0x76) / OAUTH (0x73) function envelope with key-value AUTH_ pairs — NOT 9i's
# positional TTI_3LOGA/TTI_3LOGON. Sending 3LOGA to 8i draws a TTI_OER. The
# pre-10g key-value length coding is `ub1(len) ub4be(len) data`, then a ub4be
# padding word — distinct from the modern variable-length encode_sb4 form.
# Byte-for-byte reproduced from a live 9.2-client -> 8.1.7 capture
# (docs/PROTOCOL.md; ~/o8i/captures/cli8i_9.2_to_8i.trc).


def _kv8i(Key: bytes, Val: bytes) -> bytes:
    def field(Data: bytes) -> bytes:
        return (
            bytes([len(Data)]) + struct.pack('>I', len(Data)) + Data
            if Data
            else bytes([0])
        )

    return field(Key) + field(Val) + struct.pack('>I', 0)


def encode_o3logon_osesskey_phase1(
    Seq: int, User: bytes, Pairs: list[tuple[bytes, bytes]]
) -> bytes:
    # TTI_FUN + OSESSKEY (0x76): request the session key. Carries the username
    # and informational AUTH_ pairs (program/machine/pid — session metadata the
    # server does not authenticate on). The pair count is a ub1 at offset 13.
    return (
        bytes([TTI_FUN, TTI_SESS, Seq, 1])
        + bytes([len(User)])
        + struct.pack('>I', 1)  # logon mode
        + struct.pack('>I', 1)
        + bytes([len(Pairs)])  # number of key-value pairs
        + struct.pack('>I', 1)
        + bytes([1])  # has-username
        + bytes([len(User)])
        + User
        + b''.join(_kv8i(k, v) for k, v in Pairs)
    )


def encode_o3logon_oauth_phase2(
    Seq: int, User: bytes, PwdField: bytes, Pairs: list[tuple[bytes, bytes]]
) -> bytes:
    # TTI_FUN + OAUTH (0x73): send AUTH_PASSWORD (hex(DES blocks) + decimal pad
    # count) plus the informational pairs. Logon mode 0x105 marks phase two.
    return (
        bytes([TTI_FUN, TTI_AUTH, Seq, 1])
        + bytes([len(User)])
        + struct.pack('>I', 1)
        + bytes([1])
        + struct.pack('>I', 0x105)  # phase-two logon mode
        + struct.pack('>I', 1)
        + bytes([1])  # has-username
        + bytes([len(User)])
        + User
        + _kv8i(b'AUTH_PASSWORD', PwdField)
        + b''.join(_kv8i(k, v) for k, v in Pairs)
    )


def parse_8i_auth_sesskey(Packet: bytes) -> bytes:
    """Extract the 8-byte session key from an 8i OSESSKEY response RPA.

    The AUTH_SESSKEY value is a length-prefixed ASCII-hex string in the pre-10g
    key-value coding (``ub1 len``, ``ub4be len``, then the hex)."""
    from binascii import unhexlify

    from seerdb.common.exceptions import InterfaceError

    Idx = Packet.find(b'AUTH_SESSKEY')
    if Idx < 0:
        raise InterfaceError('8i OSESSKEY response carried no AUTH_SESSKEY')
    After = Packet[Idx + len(b'AUTH_SESSKEY') :]
    ValLen = After[0]  # ub1 length; the ub4be repeat follows in After[1:5]
    return unhexlify(After[5 : 5 + ValLen])


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
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    return _fun_header(Request, Tseq, FieldVersion)


##
## Decoders/Encoders for base types
##


def set_opts(
    Type: str, Flag: int, Id: int, Len: int, Param: int
) -> tuple[int, int, int, list[int]]:
    P0 = 32768
    P1 = (Id * 8) | (Param * 256)
    P2 = 0
    P3 = 2147483647  # 2^^31-1

    if Type == 'fetch':
        P1 = (Id * 16) | 64
        All8 = set_opts_all8(Flag, Param, 1)
    elif (Type == 'select') and (Flag == 0):
        P1 = (Id * 8) | 64
        All8 = set_opts_all8(Flag, Param, 1)
    elif (Type == 'select') and (Flag == 1):
        P1 = Id * 8
        P2 = 4294967295  # 2**32-1
        All8 = set_opts_all8(Flag, 0, 1)
    elif Type == 'change':
        All8 = set_opts_all8(Flag, 1 + Len, 0)
    elif Type == 'return':
        P0 = 1024
        All8 = set_opts_all8(Flag, 1, 0)
    elif Type == 'block':
        P0 = 1024
        P3 = 32760  # (2**15-1)^(2**3-1)
        All8 = set_opts_all8(Flag, 1, 0)
    else:
        raise Exception("Can't set opts", (Type, Flag, Id, Len, Param))

    # Opt = (Flag ^ 32 ^ P0) | P1  (^ binds tighter than |); verified across
    # SELECT / DML / PL/SQL-block / array-DML execs.
    return (Flag ^ 32 ^ P0 | P1, P2, P3, All8)


def set_opts_all8(Opts: int, Fetch: int, Type: int) -> list[int]:
    return [Opts, Fetch, 0, 0, 0, 0, 0, Type, 0, 0, 0, 0, 0]


def decode_ub4(Bytes: bytes) -> tuple[int, bytes]:
    # Variable-length integer (PROTOCOL.md §12.1): a length byte, then that many
    # big-endian magnitude bytes. The low 7 bits of the length byte are the
    # magnitude width (0..4 for a real ub4 / sb4); the high bit flags a negative
    # value (sign-magnitude, not two's complement). So -1 arrives as 0x81 0x01,
    # NUMBER scale -127 as 0x81 0x7f, and -256 as 0x82 0x01 0x00.
    Length = Bytes[0]
    Negative = bool(Length & 0x80)
    Width = Length & 0x7F
    if Width <= 4:
        Magnitude = int.from_bytes(Bytes[1 : Width + 1], 'big')
        Value = -Magnitude if Negative else Magnitude
        return (Value, Bytes[Width + 1 :])
    # Width 5..0x7f is not a valid 1..4-byte integer. In practice the only field
    # that reaches here is a raw ub2 / counter that decode_token_oer reads through
    # this function (its leading byte is frequently 5..255); the historic
    # behaviour is to consume exactly two bytes and return the negated second
    # byte. The value is always discarded there and the 2-byte consume keeps the
    # OER stream aligned for ordinary multi-row fetches. Keep it: a prior strict
    # version that raised here crashed plain
    # "SELECT level FROM dual CONNECT BY level <= 50" (#24).
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
    # Out of ub4 range (or negative); raise here rather than via `case _` so
    # every branch is a value-return for flow analysis.
    raise Exception("Can't encode value", Val)


def decode_dalc(Bytes: bytes) -> tuple[bytes | list, bytes]:
    # Data with Attached Length Code (PROTOCOL.md §12.2). 0x00 = empty,
    # 0xFF = null marker (no data follows), 0xFE = chunked, otherwise the
    # length byte is followed by that many data bytes. Both empty and null
    # are reported as [] here; callers that need the distinction look at the
    # enclosing bytes_with_length count.
    try:
        if Bytes[0] == 0 or Bytes[0] == 255:
            return ([], Bytes[1:])
        if Bytes[0] == 254:
            return decode_chr(Bytes)
        Length = Bytes[0]
        return (Bytes[1 : Length + 1], Bytes[Length + 1 :])
    except IndexError as Exc:
        # A truncated field (empty Bytes, or a chunk length in decode_chr that
        # runs past the buffer) indexes out of range; surface as DataError
        # rather than leaking a raw IndexError (#230).
        raise DataError('truncated DALC field') from Exc


def decode_chr(Bytes: bytes) -> tuple[bytes, bytes]:
    if Bytes[0] == 254:
        # LONG (chunked) value. 12c+ prefixes each chunk with a ub4 length and
        # ends with a zero-length chunk (same framing as _skip_chunked_bytes);
        # 11g uses a single length byte per chunk. The decode field version is
        # set by decode_packet for the current response.
        if _DECODE_FIELD_VERSION.get() >= 8:  # FIELD_VERSION_12_2
            Rest = Bytes[1:]
            Out = b''
            while True:
                (ChunkLen, Rest) = decode_ub4(Rest)
                if ChunkLen == 0:
                    return (Out, Rest)
                Out += Rest[:ChunkLen]
                Rest = Rest[ChunkLen:]
        j = 1
        i = Bytes[j]
        Out = b''
        while True:
            Out += Bytes[j + 1 : i + j + 1]
            if Bytes[i + j + 1] == 0:
                break
            j = i + j + 1
            i = Bytes[j]
        return (Out, Bytes[i + j + 1 + 1 :])
    else:
        return (Bytes[1 : Bytes[0] + 1], Bytes[Bytes[0] + 1 :])


def encode_chr(String: str | bytes) -> bytes:
    Bytes = String.encode('utf-8') if isinstance(String, str) else String
    if _ENCODE_FIELD_VERSION.get() >= 8:  # FIELD_VERSION_12_2
        # 12c+ bind data follows write_bytes_with_length: a single length byte
        # for values < 254, otherwise the 254 marker + ub4-prefixed chunks.
        # 11g instead chunks anything over 64 bytes with single-byte lengths;
        # sending that to a 12c server desyncs it (ORA-03120 integer overflow).
        return _bytes_with_length(Bytes)
    Length = len(Bytes)
    if Length > 64:
        Out = b''
        i = 0
        while i < Length - 64:
            Out += bytes([64]) + Bytes[i : i + 64]
            i += 64
        return bytes([254]) + Out + bytes([Length - i]) + Bytes[i:] + bytes([0])

    return bytes([Length]) + Bytes


def decode_kv(
    Data: bytes, Num: int, Acc: list, Flags: dict | None = None
) -> tuple[list, bytes]:
    # Flags (optional) collects each pair's trailing number (its "flag") keyed by
    # key name — needed for AUTH_VFR_DATA, whose flag names the verifier type
    # (#311). Left None by default so existing callers are unchanged.
    if Num <= 0 or not Data:
        return (sorted(Acc), Data)

    def decode_to_bin(D):
        if D[0] == 0:
            return (bytes([0]), D[1:])
        else:
            (Size, R) = decode_ub4(D)
            if R[0] == Size:
                return (R[1 : 1 + Size], R[1 + Size :])
            elif R[0] == 254:
                return decode_chr(R)
            else:
                return decode_chr(R)

    (Key, R0) = decode_to_bin(Data)
    (Val, R1) = decode_to_bin(R0)
    if Flags is not None and R1:
        (Flag, _) = decode_ub4(R1)  # the per-pair number precedes the next pair
        Flags[Key] = Flag
    if Val == bytes([0]):
        Val = None
    NewAcc = Acc + [(Key, Val)]
    if not R1:
        return (sorted(NewAcc), R1)
    Skip = R1[0] + 1
    return decode_kv(R1[Skip:], Num - 1, NewAcc, Flags)


def encode_kv(Key: bytes, Val: bytes, Padding: int = 0) -> bytes:
    def encode_to_bin(Data):
        Size = len(Data)
        if Size == 0:
            return bytes([0])
        # ub4 total length + the value in write_bytes_with_length form: a 1-byte
        # length for short values, or the 254 chunked marker for values >= 254
        # (e.g. an RSA token signature, #125) — the single-byte length prefix the
        # old code used could not carry a value longer than 255 bytes.
        return encode_sb4(Size) + _bytes_with_length(Data)

    return encode_to_bin(Key) + encode_to_bin(Val) + encode_sb4(Padding)


def encode_tokens_rxd(Tokens: list, Binary: bytes) -> bytes:
    Out = bytes([TTI_RXD])
    for Token in Tokens:
        Out += encode_token_rxd(Token)
    return Binary + Out


def encode_tokens_oac(Tokens: list, Binary: bytes) -> bytes:
    # OAC descriptors are emitted bare here (no leading TTI_OAC token byte) —
    # that's what the server expects inside the ALL8 bind section.
    Out = b''
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
        return b''
    if Batch:
        return encode_tokens_oac(_oac_rep_row([Bind] + Batch), b'')
    return encode_tokens_oac(Bind, b'')


def encode_token_rxd(Token: object) -> bytes:
    if isinstance(Token, Var):
        # OUT / IN OUT bind: send the current value (NULL for an unseeded pure
        # OUT). The server writes the result back in the IOV response.
        if Token.is_array:
            # Associative-array bind (#122): a ub4 element count then each
            # element value, in order. Empty (count 0) for a pure-OUT array.
            Elements = cast(list, Token._value or [])
            Out = encode_sb4(len(Elements))
            for Element in Elements:
                Out += encode_token_rxd(Element)
            return Out
        if Token.dbtype.tns_type == TNS_TYPE_REFCURSOR:
            return bytes([1, 0])  # REF CURSOR slot placeholder
        if Token._value is None:
            return bytes([0])
        if getattr(Token.dbtype, 'csfrm', 1) == 2 and isinstance(Token._value, str):
            # National-charset bind (NVARCHAR2 / NCHAR, #174): the value rides as
            # AL16UTF16 (UTF-16 big-endian), independent of the DB charset.
            # encode_chr length-frames the raw bytes (it only re-encodes str).
            return encode_chr(Token._value.encode('utf-16-be'))
        return encode_token_rxd(Token._value)
    if isinstance(Token, TempLob):
        # Temp-LOB locator bind (#91): the LOB-descriptor prefix `01 28 28`
        # (shared with the native VECTOR / JSON binds), a ub2 locator length,
        # then the locator bytes. Verified against python-oracledb on 21c.
        return (
            bytes.fromhex('012828')
            + struct.pack('>H', len(Token.locator))
            + Token.locator
        )
    if Token is None:
        return bytes([0])
    from seerdb.common.dbobject import DbObject, DbRef

    if isinstance(Token, DbObject):
        # SQL OBJECT (ADT) bind (#116): the write_dbobject framing + image.
        return _encode_object_bind_value(Token)
    if isinstance(Token, DbRef):
        # REF bind (#139): the opaque locator, length-prefixed.
        return _encode_ref_bind_value(Token)
    if isinstance(Token, (dict, JSON)):
        # JSON bind: native OSON image (#70) when encodable, else the text cast
        # (#50). The OAC path in encode_token_oac makes the same choice.
        Image = _json_oson_image(Token)
        if Image is not None:
            return _native_lob_bind_value(Image)
        Token = _json_bind_text(Token)
    elif is_vector_bind(Token):
        # Native VECTOR bind on 23ai (#62): the OAC counterpart is
        # VECTOR_BIND_OAC.
        return _native_lob_bind_value(encode_vector(Token))
    if isinstance(Token, bool):
        # Native SQL BOOLEAN bind on 23ai (#54): the value is a 2-byte DALC
        # `02 01 <0/1>` (TRUE = 01 01, FALSE = 01 00; captured from
        # python-oracledb). Pre-23ai servers have no BOOLEAN type, so fall back
        # to the historical NUMBER 0/1 binding there (bool is an int subclass).
        if _ENCODE_FIELD_VERSION.get() >= 17:  # FIELD_VERSION_23_1
            return bytes([2, 1, 1 if Token else 0])
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
        Bytes = encode_token_num(cast(float, Token))
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
        # Legacy seerdb.common.date.date with has_timestamp / timestamptz flags;
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
    raise Exception('Unknown RXD token', Token)


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
        # Associative-array bind (#122): the OAC declares the array capacity in
        # the max-num-elements field and sets the ARRAY flag (handled by A).
        A = Token.num_elements if Token.is_array else 0
        # National (csfrm 2) char Vars declare AL16UTF16 so encode_token_raw
        # sets csfrm 2 and the value rides as UTF-16BE (#174); ordinary char
        # Vars keep AL32UTF8.
        CharCs = (
            AL16UTF16_CHARSET
            if getattr(Token.dbtype, 'csfrm', 1) == 2
            else AL32UTF8_CHARSET
        )
        if DT == TNS_TYPE_NUMBER:
            return encode_token_raw(TNS_TYPE_NUMBER, 22, 0, 0, 0, A)
        if DT == TNS_TYPE_VARCHAR:
            return encode_token_raw(TNS_TYPE_VARCHAR, Token.size, 16, CharCs, 0, A)
        if DT == TNS_TYPE_CHAR:
            return encode_token_raw(TNS_TYPE_CHAR, Token.size, 16, CharCs, 0, A)
        if DT == TNS_TYPE_RAW:
            return encode_token_raw(TNS_TYPE_RAW, Token.size, 16, 0, 0, A)
        if DT == TNS_TYPE_DATE:
            return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0, A)
        if DT == TNS_TYPE_TIMESTAMP:
            return encode_token_raw(TNS_TYPE_TIMESTAMP, 11, 0, 0, 0, A)
        if DT == TNS_TYPE_TIMESTAMPTZ:
            return encode_token_raw(TNS_TYPE_TIMESTAMPTZ, 13, 0, 0, 0, A)
        if DT == TNS_TYPE_BFLOAT:
            return encode_token_raw(TNS_TYPE_BFLOAT, 4, 0, 0, 0, A)
        if DT == TNS_TYPE_BDOUBLE:
            return encode_token_raw(TNS_TYPE_BDOUBLE, 8, 0, 0, 0, A)
        if DT == TNS_TYPE_INTERVALDS:
            return encode_token_raw(TNS_TYPE_INTERVALDS, 11, 0, 0, 0, A)
        if DT == TNS_TYPE_INTERVALYM:
            return encode_token_raw(TNS_TYPE_INTERVALYM, 5, 0, 0, 0, A)
        if DT == TNS_TYPE_REFCURSOR:
            return encode_token_raw(TNS_TYPE_REFCURSOR, 1, 0, UTF8_CHARSET, 0)
        raise Exception('Unsupported Var OAC type', DT)
    if isinstance(Token, TempLob):
        # Temp-LOB locator bind (#91): a CLOB / BLOB OAC carrying the LOB
        # cont-flag 0x02000000 (the same flag the native VECTOR / JSON OACs
        # set). The announced length is the source value's byte budget. Built
        # explicitly because encode_token_raw zeroes the cont-flag.
        DT = TNS_TYPE_BLOB if Token.is_blob else TNS_TYPE_CLOB
        Charset = 0 if Token.is_blob else AL32UTF8_CHARSET
        Csfrm = 0 if Token.is_blob else 1
        return (
            bytes([DT, 1, 0, 0])
            + encode_sb4(Token.oac_size)
            + encode_sb4(0)  # max number of array elements
            + encode_sb4(0x02000000)  # cont flag (ub8) — LOB
            + encode_sb4(0)  # OID
            + encode_sb4(0)  # version
            + encode_sb4(Charset)  # charset id (ub2)
            + bytes([Csfrm])  # character set form
            + encode_sb4(0)  # LOB prefetch length
            + encode_sb4(0)
        )  # oaccolid (12.2+)
    if Token is None:
        # NULL value (0 bytes): a minimal VARCHAR OAC, again avoiding the
        # 32767 LONG-reorder swap when a NULL bind precedes another bind.
        return encode_token_raw(TNS_TYPE_VARCHAR, 1, 16, AL32UTF8_CHARSET, 0)
    from seerdb.common.dbobject import DbObject, DbRef

    if isinstance(Token, DbObject):
        # SQL OBJECT (ADT) bind OAC (#116): type 109 + the type's OID + version.
        return _encode_object_oac(Token)
    if isinstance(Token, DbRef):
        # REF bind OAC (#139): type 111 + the referenced type's OID.
        return _encode_ref_oac(Token)
    if isinstance(Token, (dict, JSON)):
        # JSON bind: a native JSON OAC (#70) when the value is OSON-encodable,
        # else the VARCHAR OAC for the text cast (#50). Must match the choice in
        # encode_token_rxd.
        if _json_oson_image(Token) is not None:
            from seerdb.common.oson import JSON_BIND_OAC

            return JSON_BIND_OAC
        Token = _json_bind_text(Token)
    elif is_vector_bind(Token):
        # Native VECTOR bind on 23ai (#62): type 127, cont-flag 0x02000000,
        # 1 MiB max — the fixed OAC python-oracledb sends. The image rides in
        # encode_token_rxd.
        return VECTOR_BIND_OAC
    if isinstance(Token, BinaryFloat):
        return encode_token_raw(TNS_TYPE_BFLOAT, 4, 0, 0, 0)
    if isinstance(Token, BinaryDouble):
        return encode_token_raw(TNS_TYPE_BDOUBLE, 8, 0, 0, 0)
    if isinstance(Token, float) and not math.isfinite(Token):
        # Non-finite floats (inf / nan) bind as native BINARY_DOUBLE — NUMBER
        # can't represent them (see encode_token_rxd).
        return encode_token_raw(TNS_TYPE_BDOUBLE, 8, 0, 0, 0)
    if isinstance(Token, bool):
        # Native BOOLEAN OAC on 23ai (#54): type 252, fixed size 4 (matches
        # python-oracledb's `fc 01 00 00 01 04 …`). Pre-23ai falls back to the
        # NUMBER OAC, pairing with the NUMBER value in encode_token_rxd.
        if _ENCODE_FIELD_VERSION.get() >= 17:  # FIELD_VERSION_23_1
            return encode_token_raw(TNS_TYPE_BOOLEAN, 4, 0, 0, 0)
        return encode_token_raw(TNS_TYPE_NUMBER, 22, 0, 0, 0)
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
            TNS_TYPE_VARCHAR,
            max(len(Token.encode('utf-8')), 1),
            16,
            AL32UTF8_CHARSET,
            0,
        )
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
    raise Exception('Unknown OAC token', Token)


def encode_token_decimal(Value: Decimal) -> bytes:
    # Exact base-100 Oracle NUMBER encoding for a Decimal — no float detour, so a
    # value with more than ~15 significant digits round-trips unchanged (up to
    # Oracle's ~38-digit / 20 base-100 group limit). Zero and integral values
    # keep the fast paths; a non-finite Decimal (NaN / Inf) has no NUMBER form.
    if not Value.is_finite():
        raise DataError(f'cannot encode a non-finite NUMBER: {Value}')
    if Value == 0:
        return bytes([128])
    if Value == Value.to_integral_value():
        IntVal = int(Value)
        # The legacy integer encoder (lnxmin) caps at 20 base-100 groups, i.e.
        # |value| < 10**40. A larger integral NUMBER (valid up to ~1e125 as long
        # as it has <= 38 significant digits) falls through to the exact base-100
        # encoder below, which folds trailing-zero groups into the exponent.
        if -(10**40) < IntVal < 10**40:
            return encode_token_num(IntVal)

    Sign, Digits, Exp10 = Value.as_tuple()
    # is_finite() above rules out the 'n'/'N'/'F' exponent forms as_tuple() uses
    # for NaN / Infinity, so Exp10 is a plain int here.
    assert isinstance(Exp10, int)
    DigitStr = ''.join(map(str, Digits))
    # Decimal power of the most-significant digit, and the base-100 exponent of
    # the leading group (each group spans decimal powers 10**2N .. 10**(2N+1)).
    MsdPower = Exp10 + len(Digits) - 1
    Exponent = MsdPower // 2
    # The leading group's high decimal digit sits at power 2*Exponent+1; pad one
    # leading zero when the MSD is instead the low digit of its group.
    LeadPad = (2 * Exponent + 1) - MsdPower  # 0 or 1
    Aligned = '0' * LeadPad + DigitStr
    if len(Aligned) % 2:
        Aligned += '0'
    Pairs = [int(Aligned[I : I + 2]) for I in range(0, len(Aligned), 2)]

    # Oracle NUMBER holds at most 20 base-100 groups; round half-up on the 21st.
    MaxGroups = 20
    if len(Pairs) > MaxGroups:
        RoundUp = Pairs[MaxGroups] >= 50
        Pairs = Pairs[:MaxGroups]
        if RoundUp:
            I = MaxGroups - 1
            while I >= 0:
                Pairs[I] += 1
                if Pairs[I] < 100:
                    break
                Pairs[I] = 0
                I -= 1
            else:
                # Carried past the most-significant group (999… → 100…).
                Pairs = [1] + Pairs[: MaxGroups - 1]
                Exponent += 1
    # Trailing all-zero groups carry no value.
    while len(Pairs) > 1 and Pairs[-1] == 0:
        Pairs.pop()

    if Sign == 0:
        return bytes([Exponent + 193] + [P + 1 for P in Pairs])
    return bytes([(Exponent + 193) ^ 0xFF] + [101 - P for P in Pairs] + [102])


# --- SQL OBJECT (ADT) bind encode (#116) — the inverse of _read_object_column
# and the #115 image walk. Mirrors python-oracledb's write_dbobject /
# _get_packed_data / _pack_value / create_new_object.

_OBJ_IMAGE_FLAGS = 0x84  # IS_VERSION_81 (0x80) | NO_PREFIX_SEG (0x04)
_OBJ_IMAGE_FLAGS_COLLECTION = 0x88  # IS_VERSION_81 (0x80) | IS_COLLECTION (0x08)
_OBJ_IMAGE_VERSION = 1
_OBJ_TOP_LEVEL = 0x01
_OBJ_NULL_ATTR = 255  # TNS_NULL_LENGTH_INDICATOR
_OBJ_LONG_LEN = 254  # TNS_LONG_LENGTH_INDICATOR
_OBJ_MAX_SHORT_LEN = 245  # TNS_OBJ_MAX_SHORT_LENGTH
# toid wrapper for a new object: 00 22 (NON_NULL_OID | HAS_EXTENT_OID) + oid +
# the fixed extent OID (python-oracledb create_new_object).
_OBJ_TOID_PREFIX = bytes([0x00, 0x22, 0x02, 0x08])
_OBJ_EXTENT_OID = bytes.fromhex('00000000000000000000000000010001')


def _obj_write_length(Length: int) -> bytes:
    # python-oracledb DbObjectPickleBuffer.write_length.
    if Length <= _OBJ_MAX_SHORT_LEN:
        return bytes([Length])
    return bytes([_OBJ_LONG_LEN]) + struct.pack('>I', Length)


def _obj_two_lengths(Value: bytes) -> bytes:
    # write_bytes_with_two_lengths: a ub4 count, then (for a non-empty value)
    # the length-prefixed bytes. An empty value is just the zero count.
    if not Value:
        return encode_sb4(0)
    return encode_sb4(len(Value)) + _bytes_with_length(Value)


def _encode_object_attr(DataType: int, Charset: int, Value: Any) -> bytes:
    # The raw scalar bytes for one attribute — the same on-wire encoding the
    # column form uses, so the #115 decoders read it back. (No length prefix;
    # the caller adds the image write_length.)
    if DataType in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_LONG):
        if isinstance(Value, (bytes, bytearray)):
            return bytes(Value)
        # AL32UTF8 session -> UTF-8; the CharsetDict lookup was a no-op (it
        # keyed a name->id map by an int, see #236).
        return str(Value).encode('utf-8')
    if DataType == TNS_TYPE_NUMBER:
        if isinstance(Value, Decimal):
            return encode_token_decimal(Value)
        return encode_token_num(Value)
    if DataType in (TNS_TYPE_RAW, TNS_TYPE_LONGRAW):
        return bytes(Value)
    if DataType in (
        TNS_TYPE_DATE,
        TNS_TYPE_TIMESTAMP,
        TNS_TYPE_TIMESTAMPTZ,
        TNS_TYPE_TIMESTAMPLTZ,
    ):
        if isinstance(Value, date):
            return encode_token_date(Value)
        return encode_token_datetime(Value)
    if DataType == TNS_TYPE_BFLOAT:
        return encode_token_binary_float(Value)
    if DataType == TNS_TYPE_BDOUBLE:
        return encode_token_binary_double(Value)
    if DataType == TNS_TYPE_INTERVALDS:
        return encode_token_interval_ds(Value)
    if DataType == TNS_TYPE_INTERVALYM:
        return encode_token_interval_ym(Value)
    if isinstance(Value, (bytes, bytearray)):
        return bytes(Value)
    return str(Value).encode('utf-8')


def _encode_object_attr_field(DataType: int, Charset: int, Value: Any) -> bytes:
    # One image field: a single 0xFF for NULL, else the write_length-prefixed
    # raw scalar bytes.
    if Value is None:
        return bytes([_OBJ_NULL_ATTR])
    Raw = _encode_object_attr(DataType, Charset or AL32UTF8_CHARSET, Value)
    return _obj_write_length(len(Raw)) + Raw


def encode_object_image(Obj: 'DbObject') -> bytes:
    # Pack a DbObject into its image. For an object: header (flags, version,
    # long-form length backpatched) then each attribute length-prefixed in
    # declaration order. For a collection (#117/#118): the header also carries a
    # prefix segment (01 01), then a collection-flags byte, the element count,
    # and each element. A NULL field is a single 0xFF. Mirrors python-oracledb
    # _get_packed_data / write_header / _pack_data / _pack_value.
    Typ = Obj._dbtype
    if Typ is not None and Typ.is_collection:
        Element = Typ.element or {}
        Charset = Element.get('charset') or AL32UTF8_CHARSET
        DataType = Element.get('data_type')
        Body = bytes([0])  # collection flags
        Body += _obj_write_length(len(Obj._elements))
        for Value in Obj._elements:
            Body += _encode_object_attr_field(cast(int, DataType), Charset, Value)
        # Collection header = flags, version, long-form length, prefix seg (01 01).
        Total = 9 + len(Body)
        return (
            bytes([_OBJ_IMAGE_FLAGS_COLLECTION, _OBJ_IMAGE_VERSION, _OBJ_LONG_LEN])
            + struct.pack('>I', Total)
            + bytes([1, 1])
            + Body
        )
    Body = b''
    for Attr in Typ.attrs:
        Body += _encode_object_attr_field(
            Attr.get('data_type'),
            Attr.get('charset') or AL32UTF8_CHARSET,
            Obj._attrs.get(Attr['name']),
        )
    # Header length is written long-form (0xFE + ub4) and covers the whole image
    # (the 7-byte header included), matching python-oracledb write_header.
    Total = 7 + len(Body)
    return (
        bytes([_OBJ_IMAGE_FLAGS, _OBJ_IMAGE_VERSION, _OBJ_LONG_LEN])
        + struct.pack('>I', Total)
        + Body
    )


def _encode_object_bind_value(Obj: 'DbObject') -> bytes:
    # The bind value framing (python-oracledb write_dbobject): the constructed
    # toid, an empty object OID, zero snapshot/version, the image length, the
    # TOP_LEVEL flags, then the image.
    Typ = Obj._dbtype
    Toid = _OBJ_TOID_PREFIX + Typ.oid + _OBJ_EXTENT_OID
    Image = encode_object_image(Obj)
    return (
        _obj_two_lengths(Toid)
        + _obj_two_lengths(b'')  # object OID (empty for new)
        + encode_sb4(0)  # snapshot
        + encode_sb4(0)  # version
        + encode_sb4(len(Image))  # image length
        + encode_sb4(_OBJ_TOP_LEVEL)  # flags
        + _bytes_with_length(Image)
    )  # the image


def _encode_object_oac(Obj: 'DbObject') -> bytes:
    # The bind OAC for an object (type 109): the 12c+ metadata layout injecting
    # the type's 16-byte OID + version (precision/scale 0, no charset). Mirrors
    # python-oracledb _write_column_metadata's object branch. 12c+ only — pre-12c
    # object binds are gated in the cursor (no thin reference for that OAC).
    Typ = Obj._dbtype
    Image = encode_object_image(Obj)
    return (
        bytes([TNS_TYPE_ADT, 1, 0, 0])  # type, flag (USE_INDICATORS), p, s
        + encode_sb4(len(Image))  # buffer size
        + encode_sb4(0)  # max number of array elements
        + encode_sb4(0)  # cont flag (ub8)
        + _obj_two_lengths(Typ.oid)  # type OID (16 bytes)
        + encode_sb4(Typ.version)  # type version
        + encode_sb4(0)  # charset id (ub2)
        + bytes([0])  # character set form
        + encode_sb4(0)  # LOB prefetch length
        + encode_sb4(0)
    )  # oaccolid (12.2+)


# Fixed buffer size the REF bind OAC advertises (matches the Oracle JDBC thin
# reference capture; the locator is self-describing so the exact value is not
# load-bearing).
_REF_OAC_BUFFER_SIZE = 4000


def _encode_ref_oac(Ref: 'DbRef') -> bytes:
    # The bind OAC for a REF (type 111, #139). Same 12c+ ADT-style metadata as
    # _encode_object_oac but with the REF type code and the *referenced* type's
    # 16-byte OID. Byte-for-byte from the Oracle JDBC thin reference (oracledb
    # has no REF type, so JDBC is the only reference). The type OID is carried on
    # the DbRef from its describe (#119); without it we cannot build the OAC.
    if Ref.type_oid is None:
        from seerdb.common.exceptions import NotSupportedError

        raise NotSupportedError(
            'cannot bind a REF without its referenced type OID; the value must '
            'come from a fetched DbRef whose describe carried the type identity'
        )
    return (
        bytes([TNS_TYPE_REF, 3, 0, 0])  # type 111, flag, prec, scale
        + encode_sb4(_REF_OAC_BUFFER_SIZE)  # buffer size
        + encode_sb4(0)  # max number of array elements
        + encode_sb4(0)  # cont flag (ub8)
        + _obj_two_lengths(Ref.type_oid)  # referenced type OID (16 bytes)
        + encode_sb4(1)  # type version
        + encode_sb4(2)  # charset id (ub2) — per capture
        + bytes([0])  # character set form
        + encode_sb4(0)  # LOB prefetch length
        + encode_sb4(0)
    )  # oaccolid (12.2+)


def _encode_ref_bind_value(Ref: 'DbRef') -> bytes:
    # The bind value for a REF (#139): just the opaque locator, length-prefixed —
    # the exact inverse of the read path (decode_dalc). Confirmed against the
    # JDBC reference for both an INSERT and a DEREF bind.
    return _bytes_with_length(Ref.bytes)


# --- Advanced Queuing (#128) ---

# AQ JSON payload descriptor (#150): the fixed prefix before the ub2 image
# length / 22 zero bytes / encode_chr(OSON). RE'd from an oracledb-thin capture.
_AQ_JSON_DESCRIPTOR = bytes.fromhex('012800260004610800000001000000000000')


def _encode_sb4i(Val: int) -> bytes:
    # Signed ub4: non-negative via encode_sb4; negative as 0x80|width then the
    # big-endian magnitude (e.g. expiration -1 -> 81 01). Mirrors write_sb4.
    if Val >= 0:
        return encode_sb4(Val)
    Mag = (-Val).to_bytes(4, 'big').lstrip(b'\x00') or b'\x00'
    return bytes([0x80 | len(Mag)]) + Mag


def _aq_value_with_length(Value) -> bytes:
    # write_value_with_length: None -> ub4 0; else write_bytes_with_two_lengths.
    if Value is None:
        return encode_sb4(0)
    if isinstance(Value, str):
        Value = Value.encode('utf-8')
    return _obj_two_lengths(bytes(Value))


def _aq_kv_pair(Text, Binary, Keyword: int) -> bytes:
    # write_keyword_value_pair: the text value, the binary value, then the ub2
    # keyword (each value length-prefixed; None -> ub4 0).
    return (
        _aq_value_with_length(Text)
        + _aq_value_with_length(Binary)
        + encode_sb4(Keyword)
    )


def _aq_write_msg_props(Props, FieldVersion: int) -> bytes:
    # write_msg_props (aq_base): priority/delay/expiration, correlation,
    # attempts, exception queue, state, enqueue time, txn id, then the four
    # fixed agent/extension keyword-value pairs, user-property/cscn/dscn/flags,
    # and (at fv >= 21.1) a shard id. RE'd from python-oracledb.
    Out = encode_sb4(Props.priority)
    Out += encode_sb4(Props.delay)
    Out += _encode_sb4i(Props.expiration)
    Out += _aq_value_with_length(Props.correlation)
    Out += encode_sb4(0)  # number of attempts
    Out += _aq_value_with_length(Props.exceptionq)
    Out += encode_sb4(Props.state)
    Out += encode_sb4(0)  # enqueue time length
    Out += _aq_value_with_length(Props.enq_txn_id)
    Out += encode_sb4(4)  # number of extensions
    Out += bytes([0x0E])  # unknown extra byte
    Out += _aq_kv_pair(None, None, TNS_AQ_EXT_KEYWORD_AGENT_NAME)
    Out += _aq_kv_pair(None, None, TNS_AQ_EXT_KEYWORD_AGENT_ADDRESS)
    Out += _aq_kv_pair(None, b'\x00', TNS_AQ_EXT_KEYWORD_AGENT_PROTOCOL)
    Out += _aq_kv_pair(None, None, TNS_AQ_EXT_KEYWORD_ORIGINAL_MSGID)
    Out += encode_sb4(0)  # user property
    Out += encode_sb4(0)  # cscn
    Out += encode_sb4(0)  # dscn
    Out += encode_sb4(0)  # flags
    if FieldVersion >= FIELD_VERSION_21_1:
        Out += encode_sb4(0xFFFFFFFF)  # shard id
    return Out


def _aq_write_payload(Queue, Props) -> bytes:
    # The payload bytes: JSON (OSON), a SQL object image, or RAW bytes.
    if Queue.is_json:
        # JSON payload (#150): the OSON image wrapped in the AQ JSON descriptor
        # (fixed 18-byte prefix + ub2 image length + 22 zero bytes + the image
        # framed like RAW via encode_chr). RE'd from an oracledb-thin capture --
        # it's the native-LOB value form (#70) but with a slightly different
        # descriptor than VECTOR_BIND_DESCRIPTOR (no second 0x28 byte).
        from seerdb.common.oson import encode_oson

        Oson = encode_oson(Props.payload)
        # _bytes_with_length (the 12c+ single-byte/0xFE-chunked form) -- NOT
        # encode_chr, whose 11g branch chunks at 64 bytes when the encode field
        # version isn't set in this context and desyncs the server (ORA-03120).
        return (
            _AQ_JSON_DESCRIPTOR
            + len(Oson).to_bytes(2, 'big')
            + b'\x00' * 22
            + _bytes_with_length(Oson)
        )
    if Queue.payload_type is not None:
        return _encode_object_bind_value(Props.payload)
    Payload = Props.payload if Props.payload is not None else b''
    if isinstance(Payload, str):
        Payload = Payload.encode('utf-8')
    return bytes(Payload)


def encode_aq_enq(Seq: int, FieldVersion: int, Queue, Props) -> bytes:
    # AQ enqueue (TNS_FUNC_AQ_ENQ). RE'd from python-oracledb AqEnqMessage.
    QName = Queue.name.encode('utf-8')
    Out = _fun_header(TNS_FUNC_AQ_ENQ, Seq, FieldVersion)
    Out += bytes([1]) + encode_sb4(len(QName))  # queue name ptr + len
    Out += _aq_write_msg_props(Props, FieldVersion)
    if Props.recipients is None:
        Out += bytes([0]) + encode_sb4(0)  # recipients ptr + count
    else:
        Out += bytes([1]) + encode_sb4(3 * len(Props.recipients))
    Out += encode_sb4(Queue.enqoptions.visibility)
    Out += bytes([0]) + encode_sb4(0)  # relative message id ptr+len
    Out += encode_sb4(0)  # sequence deviation
    Out += bytes([1]) + encode_sb4(16)  # payload TOID ptr + len
    Out += encode_sb4(TNS_AQ_MESSAGE_VERSION)  # message version (ub2)
    if Queue.is_json:
        Out += bytes([0, 0]) + encode_sb4(0)  # payload 0, RAW 0, RAW len 0
    elif Queue.payload_type is not None:
        Out += bytes([1, 0]) + encode_sb4(0)  # payload 1, RAW 0, RAW len 0
    else:
        RawLen = len(Props.payload) if Props.payload is not None else 0
        Out += bytes([0, 1]) + encode_sb4(RawLen)  # payload 0, RAW 1, RAW len
    Out += bytes([1]) + encode_sb4(TNS_AQ_MESSAGE_ID_LENGTH)  # return msgid ptr+len
    EnqFlags = (
        TNS_KPD_AQ_BUFMSG
        if Queue.enqoptions.delivery_mode == TNS_AQ_MSG_BUFFERED
        else 0
    )
    Out += encode_sb4(EnqFlags)  # enqueue flags
    Out += bytes([0]) + encode_sb4(0)  # extensions 1 ptr + count
    Out += bytes([0]) + encode_sb4(0)  # extensions 2 ptr + count
    Out += bytes([0]) + encode_sb4(0)  # source sequence num ptr+len
    Out += bytes([0]) + encode_sb4(0)  # max sequence num ptr + len
    Out += bytes([0])  # output ack length
    Out += bytes([0]) + encode_sb4(0)  # correlation ptr + len
    Out += bytes([0]) + encode_sb4(0)  # sender name ptr + len
    Out += bytes([0]) + encode_sb4(0)  # sender address ptr + len
    Out += bytes([0])  # sender charset id ptr
    Out += bytes([0])  # sender ncharset id ptr
    if FieldVersion >= FIELD_VERSION_20_1:
        Out += bytes([1 if Queue.is_json else 0])  # JSON payload ptr
    # data section
    Out += _bytes_with_length(QName)
    Out += Queue.payload_toid  # 16-byte type OID (raw)
    Out += _aq_write_payload(Queue, Props)
    return Out


def encode_aq_deq(Seq: int, FieldVersion: int, Queue) -> bytes:
    # AQ dequeue (TNS_FUNC_AQ_DEQ). RE'd from python-oracledb AqDeqMessage.
    Opts = Queue.deqoptions
    QName = Queue.name.encode('utf-8')
    Out = _fun_header(TNS_FUNC_AQ_DEQ, Seq, FieldVersion)
    Out += bytes([1]) + encode_sb4(len(QName))  # queue name ptr + len
    Out += bytes([1, 1, 1, 1])  # msg props + recipient list ptrs
    Consumer = Opts.consumer_name.encode('utf-8') if Opts.consumer_name else None
    if Consumer is not None:
        Out += bytes([1]) + encode_sb4(len(Consumer))
    else:
        Out += bytes([0]) + encode_sb4(0)
    Out += _encode_sb4i(Opts.mode)
    Out += _encode_sb4i(Opts.navigation)
    Out += _encode_sb4i(Opts.visibility)
    Out += _encode_sb4i(Opts.wait)
    if Opts.msgid:
        Out += bytes([1]) + encode_sb4(TNS_AQ_MESSAGE_ID_LENGTH)
    else:
        Out += bytes([0]) + encode_sb4(0)
    Correlation = Opts.correlation.encode('utf-8') if Opts.correlation else None
    if Correlation is not None:
        Out += bytes([1]) + encode_sb4(len(Correlation))
    else:
        Out += bytes([0]) + encode_sb4(0)
    Out += bytes([1]) + encode_sb4(16)  # payload TOID ptr + len
    Out += encode_sb4(TNS_AQ_MESSAGE_VERSION)  # message version (ub2)
    Out += bytes([1])  # payload ptr
    Out += bytes([1]) + encode_sb4(TNS_AQ_MESSAGE_ID_LENGTH)  # return msgid ptr+len
    DeqFlags = 0
    if Opts.delivery_mode == TNS_AQ_MSG_BUFFERED:
        DeqFlags |= TNS_KPD_AQ_BUFMSG
    elif Opts.delivery_mode == TNS_AQ_MSG_PERSISTENT_OR_BUFFERED:
        DeqFlags |= TNS_KPD_AQ_EITHER
    Out += encode_sb4(DeqFlags)  # dequeue flags
    Condition = Opts.condition.encode('utf-8') if Opts.condition else None
    if Condition is not None:
        Out += bytes([1]) + encode_sb4(len(Condition))
    else:
        Out += bytes([0]) + encode_sb4(0)
    Out += bytes([0]) + encode_sb4(0)  # extensions ptr + count
    if FieldVersion >= FIELD_VERSION_20_1:
        Out += bytes([0])  # JSON payload ptr
    if FieldVersion >= FIELD_VERSION_21_1:
        Out += _encode_sb4i(-1)  # shard id
    # data section
    Out += _bytes_with_length(QName)
    if Consumer is not None:
        Out += _bytes_with_length(Consumer)
    if Opts.msgid:
        Out += bytes(Opts.msgid[:16]).ljust(16, b'\x00')
    if Correlation is not None:
        Out += _bytes_with_length(Correlation)
    Out += Queue.payload_toid  # 16-byte type OID (raw)
    if Condition is not None:
        Out += _bytes_with_length(Condition)
    return Out


def _aq_write_array_enq(Queue, PropsList, FieldVersion: int) -> bytes:
    QName = Queue.name.encode('utf-8')
    Flags = (
        TNS_KPD_AQ_BUFMSG
        if Queue.enqoptions.delivery_mode == TNS_AQ_MSG_BUFFERED
        else 0
    )
    Out = encode_sb4(0)  # relative msgid length
    Out += bytes([TTI_RXH])  # ROW_HEADER marker
    Out += _obj_two_lengths(QName)
    Out += Queue.payload_toid
    Out += encode_sb4(TNS_AQ_MESSAGE_VERSION)
    Out += encode_sb4(Flags)
    for Props in PropsList:
        Out += bytes([TTI_RXD])  # ROW_DATA marker
        Out += encode_sb4(Flags)  # aqi flags
        Out += _aq_write_msg_props(Props, FieldVersion)
        Out += encode_sb4(0)  # num recipients (None)
        Out += encode_sb4(Queue.enqoptions.visibility)
        Out += encode_sb4(0)  # relative message id
        Out += encode_sb4(0)  # sequence deviation
        if Queue.payload_type is None and not Queue.is_json:
            Out += encode_sb4(len(Props.payload))
        Out += _aq_write_payload(Queue, Props)
    Out += bytes([TTI_STA])  # STATUS marker
    return Out


def _aq_write_array_deq(Queue, PropsList, FieldVersion: int) -> bytes:
    Opts = Queue.deqoptions
    QName = Queue.name.encode('utf-8')
    Flags = 0
    if Opts.delivery_mode == TNS_AQ_MSG_BUFFERED:
        Flags |= TNS_KPD_AQ_BUFMSG
    elif Opts.delivery_mode == TNS_AQ_MSG_PERSISTENT_OR_BUFFERED:
        Flags |= TNS_KPD_AQ_EITHER
    Consumer = Opts.consumer_name.encode('utf-8') if Opts.consumer_name else None
    Correlation = Opts.correlation.encode('utf-8') if Opts.correlation else None
    Condition = Opts.condition.encode('utf-8') if Opts.condition else None
    Out = b''
    for Props in PropsList:
        Out += _obj_two_lengths(QName)
        Out += _aq_write_msg_props(Props, FieldVersion)
        Out += encode_sb4(0)  # num recipients
        Out += _aq_value_with_length(Consumer)
        Out += _encode_sb4i(Opts.mode)
        Out += _encode_sb4i(Opts.navigation)
        Out += _encode_sb4i(Opts.visibility)
        Out += _encode_sb4i(Opts.wait)
        Out += _aq_value_with_length(Opts.msgid)
        Out += _aq_value_with_length(Correlation)
        Out += _aq_value_with_length(Condition)
        Out += encode_sb4(0)  # extensions
        Out += encode_sb4(0)  # relative message id
        Out += encode_sb4(0)  # sequence deviation
        Out += _obj_two_lengths(Queue.payload_toid)
        Out += encode_sb4(TNS_AQ_MESSAGE_VERSION)
        Out += encode_sb4(0)  # payload length
        Out += encode_sb4(0)  # raw payload length
        Out += encode_sb4(0)
        Out += encode_sb4(Flags)
        Out += encode_sb4(0)  # extensions length
        Out += encode_sb4(0)  # source sequence length
    return Out


def encode_aq_array(
    Seq: int, FieldVersion: int, Queue, Operation: int, PropsList, NumIters: int
) -> bytes:
    # AQ array enqueue / dequeue (TNS_FUNC_ARRAY_AQ). RE'd from python-oracledb
    # AqArrayMessage. For dequeue PropsList is NumIters placeholder properties.
    Out = _fun_header(TNS_FUNC_ARRAY_AQ, Seq, FieldVersion)
    if Operation == TNS_AQ_ARRAY_ENQ:
        Out += bytes([0]) + encode_sb4(0)  # input params ptr + len
    else:
        Out += bytes([1]) + encode_sb4(NumIters)
    Out += encode_sb4(TNS_AQ_ARRAY_FLAGS_RETURN_MESSAGE_ID)
    if Operation == TNS_AQ_ARRAY_ENQ:
        Out += bytes([1, 0])  # output params ptr + len
    else:
        Out += bytes([1, 1])
    Out += _encode_sb4i(Operation)
    Out += bytes([1 if Operation == TNS_AQ_ARRAY_ENQ else 0])  # num iters ptr
    if FieldVersion >= FIELD_VERSION_21_1:
        Out += encode_sb4(0xFFFF)  # shard id
    if Operation == TNS_AQ_ARRAY_ENQ:
        Out += encode_sb4(NumIters)
        Out += _aq_write_array_enq(Queue, PropsList, FieldVersion)
    else:
        Out += _aq_write_array_deq(Queue, PropsList, FieldVersion)
    return Out


def encode_token_datetime(DT: datetime.datetime) -> bytes:
    # 7-byte DATE prefix is shared by all three temporal formats. TIMESTAMP
    # appends 4 BE bytes of nanoseconds. TIMESTAMP WITH TIME ZONE normalises
    # the wall clock to UTC, appends nanoseconds, then the offset bias bytes.
    if DT.tzinfo is not None:
        Utc = DT.astimezone(datetime.timezone.utc)
        Base = _encode_date_prefix(Utc)
        Nanos = (DT.microsecond * 1000).to_bytes(4, 'big')
        Offset = DT.utcoffset()
        assert Offset is not None
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
    return bytes(
        [
            DT.year // 100 + 100,
            DT.year % 100 + 100,
            DT.month,
            DT.day,
            DT.hour + 1,
            DT.minute + 1,
            DT.second + 1,
        ]
    )


def encode_token_date(Token: date) -> bytes:
    # Retained for any caller that still constructs the legacy seerdb.common.date.date
    # subclass. New code should pass a stdlib datetime.datetime instead.
    if Token.has_timestamp and Token.timestamptz:
        T = Token.set_timestamptz(Token.timestamptz)
        return (
            bytes(
                [
                    T.year // 100 + 100,
                    T.year % 100 + 100,
                    T.month,
                    T.day,
                    T.hour + 1,
                    T.minute + 1,
                    T.second + 1,
                ]
            )
            + (Token.microsecond * 1000).to_bytes(4, 'big')
            + bytes([Token.timestamptz // 3600 + 20, 60])
        )
    elif Token.has_timestamp:
        return bytes(
            [
                Token.year // 100 + 100,
                Token.year % 100 + 100,
                Token.month,
                Token.day,
                Token.hour + 1,
                Token.minute + 1,
                Token.second + 1,
            ]
        ) + (Token.microsecond * 1000).to_bytes(4, 'big')
    else:
        return bytes(
            [
                Token.year // 100 + 100,
                Token.year % 100 + 100,
                Token.month,
                Token.day,
                Token.hour + 1,
                Token.minute + 1,
                Token.second + 1,
            ]
        )


def encode_token_num(Token: int | float) -> bytes:
    if Token == 0:
        return bytes([128])
    elif isinstance(Token, int):
        # lnxmin handles at most 20 base-100 groups (|Token| < 10**40). Beyond
        # that, a valid Oracle NUMBER (up to ~1e125 with <= 38 significant
        # digits) needs its exponent to absorb trailing-zero groups, so defer to
        # the exact base-100 encoder rather than raising 'LnxMin cannot handle'.
        if -(10**40) < Token < 10**40:
            return bytes(lnxfmt(lnxmin(abs(Token), 1, []), Token))
        return encode_token_decimal(Decimal(Token))
    elif isinstance(Token, float):
        return bytes(lnxfmt(lnxren(abs(Token), 0), Token))
    else:
        raise Exception('Unhandled number token', Token)


def encode_token_binary_float(Value: float) -> bytes:
    # BINARY_FLOAT is a 32-bit IEEE-754 value stored in Oracle's order-
    # preserving form: for a positive number the sign bit is set, for a
    # negative number every bit is flipped. Decoding reverses this.
    Raw = struct.pack('>f', Value)
    if Raw[0] & 0x80:
        return bytes(B ^ 0xFF for B in Raw)
    return bytes([Raw[0] ^ 0x80]) + Raw[1:]


def encode_token_binary_double(Value: float) -> bytes:
    # BINARY_DOUBLE: same order-preserving transform as BINARY_FLOAT over the
    # 64-bit IEEE-754 representation.
    Raw = struct.pack('>d', Value)
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
            -Days,
            -Hours,
            -Minutes,
            -Seconds,
            -Nanos,
        )
    return (
        (Days + 2**31).to_bytes(4, 'big')
        + bytes([Hours + 60, Minutes + 60, Seconds + 60])
        + (Nanos + 2**31).to_bytes(4, 'big')
    )


def encode_token_interval_ym(IV: IntervalYM) -> bytes:
    # INTERVAL YEAR TO MONTH: 4-byte years biased by 2**31, then 1-byte months
    # biased by 60. IntervalYM has already normalised the two fields to share a
    # sign with abs(months) < 12.
    return (IV.years + 2**31).to_bytes(4, 'big') + bytes([IV.months + 60])


def encode_token_raw(
    DataType: int, Length: int, Flag: int, Charset: int, Max: int, Array: int = 0
) -> bytes:
    # Array > 0 marks a PL/SQL associative-array bind (#122): the flag gains
    # TNS_BIND_ARRAY (0x40) and the max-number-of-array-elements field carries
    # the array's declared capacity (0 for a scalar bind).
    FormOfUse = 2 if Charset == AL16UTF16_CHARSET else 1
    if _ENCODE_FIELD_VERSION.get() >= 8:  # FIELD_VERSION_12_2
        # 12c+ bind OAC (oracledb _write_column_metadata): a fixed flag byte
        # (TNS_BIND_USE_INDICATORS = 1), a ub8 cont-flag, OID + version, the
        # bind charset as a ub2 (AL32UTF8 / AL16UTF16, 0 for non-char), the
        # csfrm byte, a LOB-prefetch length, and a trailing oaccolid ub4. The
        # 11g layout below is shorter/differently shaped and a 12c server
        # rejects it with ORA-03115 (unsupported network datatype).
        if Charset == 0:
            BindCharset, Csfrm = 0, 0
        elif Charset == AL16UTF16_CHARSET:
            BindCharset, Csfrm = AL16UTF16_CHARSET, 2
        else:
            BindCharset, Csfrm = AL32UTF8_CHARSET, 1
        FlagByte = 0x41 if Array else 1  # USE_INDICATORS | ARRAY
        return (
            bytes([DataType, FlagByte, 0, 0])
            + encode_sb4(Length)
            + encode_sb4(Array)  # max number of array elements
            + encode_sb4(0)  # cont flag (ub8)
            + encode_sb4(0)  # OID
            + encode_sb4(0)  # version
            + encode_sb4(BindCharset)  # charset id (ub2)
            + bytes([Csfrm])  # character set form
            + encode_sb4(0)  # LOB prefetch length
            + encode_sb4(0)
        )  # oaccolid (12.2+)
    FlagOut = (Flag | 0x40) if Array else Flag
    MaxOut = Array if Array else Max
    return (
        bytes([DataType, 3, 0, 0])
        + encode_sb4(Length)
        + bytes([0])
        + encode_sb4(FlagOut)
        + bytes([0, 0])
        + encode_sb4(Charset)
        + bytes([FormOfUse])
        + encode_sb4(MaxOut)
    )


##
## Some other specific transformation functions
##


def lnxmin(N: int, I: int, Acc: list[int]) -> list[int]:
    if N // 100 == 0:
        return lnxpak(([I - 1] + [N % 100] + Acc)[::-1])
    elif I < 20:
        return lnxmin(N // 100, I + 1, [N % 100] + Acc)
    else:
        raise Exception('LnxMin cannot handle this', N, I, Acc)


def lnxpak(List: list[int]) -> list[int]:
    i = 0
    while List[i] == 0:
        i += 1
    return List[: None if i == 0 else i - 1 : -1]


def lnxpak2(List: list[int], I: int) -> list[int]:
    if List == [100] and I == 8:
        return [100 - 1]
    elif len(List) > 1 and List[0] == 100 and I < 8:
        return lnxpak2([List[1] + 1] + List[2:], I + 1)
    else:
        return List


def lnxren(N: float, I: int) -> list[int]:
    if N < 1.0:
        return lnxren(N * 100.0, I - 1)
    elif N < 10.0:  # 1.0 <= N < 10.0 (the cascade guarantees ≥1.0)
        return lnxpak(([I] + lnxren4(N, 0, 1, []))[::-1])
    elif N < 100.0:  # 10.0 <= N < 100.0
        return lnxpak(([I] + lnxren4(N, 0, 0, []))[::-1])
    else:  # N >= 100.0
        return lnxren(N * 0.01, I + 1)


def lnxren4(N: float, I: int, J: int, Acc: list[int]) -> list[int]:
    if J == 0 and I == 8 and len(Acc) > 1:
        return lnxpak2([(Acc[0] + 5) // 10 * 10] + Acc[1:], 1)[::-1]
    elif J == 1 and I == 8 and len(Acc) > 1:
        return lnxpak2([Acc[0] + (Acc[0] // 50)] + Acc[1:], 1)[::-1]
    else:
        return lnxren4((N - int(N)) * 100.0, I + 1, J, [int(N)] + Acc)


def lnxfmt(List: list[int], Data: int | float) -> list[int]:
    if Data > 0:
        return [List[0] + 192 + 1] + list(map(lambda x: x + 1, List[1:]))
    elif Data < 0:
        return (
            [(List[0] + 192 + 1) ^ 255] + list(map(lambda x: 101 - x, List[1:])) + [102]
        )
    else:
        raise Exception('LnxFmt cannot handle zeroes', List, Data)
