# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side query path — parse the client's OALL8 execute (11g).

The inverse of ``tns.encode_dictionary_exec`` for the 11g wire shape: an
``OALL8`` (TTI_ALL8) function message whose fixed header carries the SQL length
and option/bind counts, followed by the raw SQL text. The describe / row
encoders that answer it are layered on separately.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from decimal import Decimal

from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import (
    _bytes_with_length,
    decode_ub4,
    encode_sb4,
    encode_token_datetime,
    encode_token_num,
)
from seerdb.common.tns_consts import (
    TTI_ALL8,
    TTI_DCB,
    TTI_FUN,
    TTI_OER,
    TTI_RXD,
    TTI_RXH,
)

# AL32UTF8 — what seerdb advertises and what an 11g DUAL column reports.
_CHARSET_AL32UTF8 = 873
_CSFRM_DB = 1

# The 11g tail between the fixed header and the SQL: a [0, 0, 1] marker and a
# 5-byte server-version slot (empty only when the client thinks it is talking to
# 10g; an 11g-pinned Mirror always gets the 5-byte form).
_MARKER_LEN = 3
_SERVER_VERSION_SLOT = 5


@dataclass(frozen=True)
class ExecRequest:
    """A parsed execute: the SQL text and the surrounding execute options."""

    sql: str
    cursor: int
    bind_count: int
    fetch: int


def parse_exec(payload: bytes) -> ExecRequest:
    """Parse an OALL8 execute payload (the TTC message from ``read_packet``).

    Extracts the SQL text; bind *values* are not decoded yet (``bind_count``
    reports how many there are). Raises :class:`InterfaceError` if the message
    is not a TTI_ALL8 execute.
    """
    if len(payload) < 3 or payload[0] != TTI_FUN or payload[1] != TTI_ALL8:
        raise InterfaceError('not an OALL8 execute')

    rest = payload[3:]  # skip TTI_FUN, TTI_ALL8, seq
    _opt, rest = decode_ub4(rest)
    cursor, rest = decode_ub4(rest)
    query_flag, rest = rest[0], rest[1:]
    query_len, rest = decode_ub4(rest)
    _all8_flag, rest = rest[0], rest[1:]
    _all8_len, rest = decode_ub4(rest)
    rest = rest[2:]  # two reserved bytes
    _lmax, rest = decode_ub4(rest)
    fetch, rest = decode_ub4(rest)
    _max, rest = decode_ub4(rest)
    _bind_flag, rest = rest[0], rest[1:]
    bind_count, rest = decode_ub4(rest)
    rest = rest[5:]  # five reserved bytes
    _def_flag, rest = rest[0], rest[1:]
    _def_len, rest = decode_ub4(rest)

    rest = rest[_MARKER_LEN + _SERVER_VERSION_SLOT :]
    sql = rest[:query_len].decode('utf-8') if query_flag else ''
    return ExecRequest(sql=sql, cursor=cursor, bind_count=bind_count, fetch=fetch)


@dataclass(frozen=True)
class ColumnMeta:
    """One result column's metadata for the describe (11g scalar column)."""

    name: bytes
    data_type: int
    data_length: int
    max_size: int
    charset: int = _CHARSET_AL32UTF8
    csfrm: int = _CSFRM_DB
    precision: int = 0
    scale: int = 0
    null_ok: int = 1


def _str_with_length(data: bytes) -> bytes:
    # Inverse of _read_str_with_length: a ub4 char-count then a DALC. An empty
    # value is just the zero count (the reader returns b'' without a DALC).
    if not data:
        return encode_sb4(0)
    return encode_sb4(len(data)) + _bytes_with_length(data)


def _encode_dcb_column(col: ColumnMeta, position: int) -> bytes:
    # Inverse of _decode_dcb_column (11g / fv < 12.2). Fields the client skips
    # are written as well-formed zeros; only type/precision/scale/length/
    # charset/csfrm/max_size/null_ok/name carry meaning.
    return (
        bytes([col.data_type, 0, col.precision])
        + encode_sb4(col.scale)
        + encode_sb4(col.data_length)  # buffer size
        + encode_sb4(0)  # max array elements
        + encode_sb4(0)  # cont flags
        + encode_sb4(0)  # type OID length (no ADT)
        + encode_sb4(0)  # version
        + encode_sb4(col.charset)
        + bytes([col.csfrm])
        + encode_sb4(col.max_size)
        + bytes([col.null_ok, 0])  # null_ok + (skipped) v7 name length
        + _str_with_length(col.name)
        + _str_with_length(b'')  # type schema (ADT owner)
        + _str_with_length(b'')  # type name
        + encode_sb4(position)  # column position
        + encode_sb4(0)  # uds flags (11g addition)
    )


def encode_describe(columns: list[ColumnMeta]) -> bytes:
    """Build the describe (TTI_DCB) block for a result's columns — §19.1 (11g).

    Returns the TTC payload starting at the TTI_DCB token. The cursor-uuid
    preamble is empty (the client skips it); the row tokens are appended
    separately by the exec-response encoder.
    """
    body = encode_sb4(sum(c.max_size for c in columns))  # max row size (skipped)
    body += encode_sb4(len(columns))
    if columns:
        body += bytes([0])  # reserved
    for position, col in enumerate(columns, start=1):
        body += _encode_dcb_column(col, position)
    body += _bytes_with_length(b'')  # current date (skipped)
    body += encode_sb4(0) * 4  # dcbflag / dcbmdbz / dcbmnpr / dcbmxpr
    body += _bytes_with_length(b'')  # dcbqcky query-cache key (11g)
    preamble = _bytes_with_length(b'')  # cursor uuid / timestamp (skipped)
    return bytes([TTI_DCB]) + preamble + body


def _encode_value(value: object) -> bytes:
    # A scalar column value as a DALC (1-byte length + data). NULL is the empty
    # DALC; text is UTF-8; a number is Oracle's base-100 NUMBER encoding. Other
    # types (DATE, LOB, …) carry their own wire formats and land with later work.
    if value is None:
        return bytes([0])
    if isinstance(value, bool):
        # No 11g BOOLEAN type; a bool is a NUMBER 0/1 (bool is an int subclass,
        # so match it before the int branch would silently swallow it).
        return _bytes_with_length(encode_token_num(int(value)))
    if isinstance(value, (int, float)):
        return _bytes_with_length(encode_token_num(value))
    if isinstance(value, Decimal):
        # NUMBER: integral Decimals stay exact; fractional ones go through the
        # float path (fine for typical values; >15 significant digits lose
        # precision until a Decimal-native encoder lands).
        integral = value == value.to_integral_value()
        return _bytes_with_length(
            encode_token_num(int(value) if integral else float(value))
        )
    if isinstance(value, datetime.datetime):
        # Oracle DATE: date + time to the second. Sub-second precision and time
        # zones (TIMESTAMP / TIMESTAMP WITH TIME ZONE) are dropped for now — the
        # 7-byte DATE form keeps a fixed width for the column.
        return _bytes_with_length(
            encode_token_datetime(value.replace(microsecond=0, tzinfo=None))
        )
    if isinstance(value, datetime.date):
        # A plain date is midnight of that day as a DATE (datetime is a date
        # subclass, so it is matched above first).
        return _bytes_with_length(
            encode_token_datetime(datetime.datetime(value.year, value.month, value.day))
        )
    if isinstance(value, str):
        return _bytes_with_length(value.encode('utf-8'))
    if isinstance(value, bytes):
        return _bytes_with_length(value)
    raise InterfaceError(f'unsupported column value type: {type(value).__name__}')


def encode_rows(
    rows: list[tuple], columns: list[ColumnMeta], *, fetch: int = 15
) -> bytes:
    """Build the row-transfer tokens for a fetch — §6.2 (11g).

    One row-header (TTI_RXH) followed by one TTI_RXD per row, each carrying the
    columns' values as DALC blobs. The caller frames these after the describe
    and before the fetch terminator. ``columns`` fixes the value order.
    """
    header = (
        bytes([TTI_RXH, 0])  # token + (skipped) flags
        + encode_sb4(1)  # num requests
        + encode_sb4(0)  # iteration number
        + encode_sb4(fetch)  # num iterations
        + encode_sb4(0)  # buffer length
        + encode_sb4(0)  # bit-vector length (no column compression)
        + _bytes_with_length(b'')  # rxhrid
    )
    body = b''
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        body += bytes([TTI_RXD]) + b''.join(_encode_value(v) for v in row)
    return header + body


# The end-of-fetch OER (ORA-01403 "no data found"), captured verbatim from a real
# 11g response. It terminates a fetch that has returned all of its rows; the
# client reads the 1403 status as "cursor drained" rather than an error.
_END_OF_FETCH = (
    bytes.fromhex(
        '0401010104010102057b00000101010e03000000000000000000000000070001010000000019'
    )
    + b'ORA-01403: no data found\n'
)


def _encode_oer(
    call_status: int, ora_code: int, rowcount: int, message: bytes
) -> bytes:
    # An OER return-status token (§6.5, 11g) — the terminal of every response.
    # All rowid / batch / cursor fields are zero here; only call status, the ORA
    # error number, the affected-row count, and the message text carry meaning.
    return (
        bytes([TTI_OER])
        + encode_sb4(call_status)
        + encode_sb4(0)  # end-to-end seq
        + encode_sb4(rowcount)  # current row number == DML affected rows on 11g
        + encode_sb4(ora_code)  # the ORA error number (0 on success)
        + encode_sb4(0)  # array element error 1
        + encode_sb4(0)  # array element error 2
        + encode_sb4(0)  # cursor id
        + encode_sb4(0)  # error position
        + bytes(6)  # sql_type, fatal, flags, user_cursor_opts, upi_param, warn
        + encode_sb4(0)  # rowid data object number
        + encode_sb4(0)  # rowid relative file number
        + bytes(1)  # rowid reserved
        + encode_sb4(0)  # rowid block number
        + encode_sb4(0)  # rowid slot number
        + encode_sb4(0)  # os error
        + bytes(2)  # statement number, call number
        + encode_sb4(0)  # padding
        + encode_sb4(1)  # successful iterations
        + _bytes_with_length(b'')  # oerrdd (logical rowid)
        + encode_sb4(0)  # batch error codes count
        + encode_sb4(0)  # batch error offsets count
        + encode_sb4(0)  # batch error messages count
        + _bytes_with_length(message)  # the message DALC (read only when ora_code≠0)
    )


def encode_error(ora_code: int, message: str) -> bytes:
    """OER reporting an error: the client raises ``ORA-<code>: <message>`` and
    the connection stays usable."""
    return _encode_oer(1, ora_code, 0, message.encode('utf-8'))


def encode_status(rowcount: int = 0) -> bytes:
    """OER reporting success for a non-query (DDL / DML), with the affected-row
    count. No describe, no rows — the client just sees the statement completed."""
    return _encode_oer(0, 0, rowcount, b'')


def encode_query_response(columns: list[ColumnMeta], rows: list[tuple]) -> bytes:
    """Assemble a full SELECT response: describe + rows + end-of-fetch (§6).

    The TTC payload the Mirror sends in reply to an OALL8 execute for a query
    that returns ``rows`` over ``columns``.
    """
    return encode_describe(columns) + encode_rows(rows, columns) + _END_OF_FETCH
