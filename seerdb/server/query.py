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
from dataclasses import dataclass, field
from decimal import Decimal

from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import (
    _bytes_with_length,
    _encode_date_prefix,
    decode_dalc,
    decode_token_oac,
    decode_ub4,
    encode_chr,
    encode_sb4,
    encode_token_binary_double,
    encode_token_binary_float,
    encode_token_datetime,
    encode_token_decimal,
    encode_token_num,
)
from seerdb.common.tns_consts import (
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPTZ,
    TTI_ALL8,
    TTI_DCB,
    TTI_FETCH,
    TTI_FUN,
    TTI_OER,
    TTI_RXD,
    TTI_RXH,
)
from seerdb.common.types import decode_value

# AL32UTF8 — what seerdb advertises and what an 11g DUAL column reports.
_CHARSET_AL32UTF8 = 873
_CSFRM_DB = 1

# The 11g tail between the fixed header and the SQL: a [0, 0, 1] marker and a
# 5-byte server-version slot (empty only when the client thinks it is talking to
# 10g; an 11g-pinned Mirror always gets the 5-byte form).
_MARKER_LEN = 3
_SERVER_VERSION_SLOT = 5


# The autocommit bit in the OALL8 options word: the client sets it (0x100) when
# the connection is in autocommit mode, asking the server to commit after this
# statement (set_opts encodes it as Param * 256 into the options word).
_EXEC_OPTION_COMMIT = 0x100


@dataclass(frozen=True)
class ExecRequest:
    """A parsed execute: the SQL text, its options, and any bind values."""

    sql: str
    cursor: int
    bind_count: int
    fetch: int
    binds: list = field(default_factory=list)
    # One entry per array-DML (executemany) iteration; a plain execute has a
    # single row equal to ``binds`` (empty for a statement with no binds).
    bind_rows: list = field(default_factory=list)
    autocommit: bool = False


def _decode_bind_value(data_type: int, raw: bytes | list) -> object:
    # A bind value from the RXD, decoded by its OAC type. An empty/NULL DALC
    # (reported as a list by decode_dalc) is None.
    if isinstance(raw, list) or not raw:
        return None
    column = {
        'data_type': data_type,
        'data_length': 0,
        'precision': 0,
        'data_scale': 0,
        'charset': _CHARSET_AL32UTF8,
        'csfrm': _CSFRM_DB,
    }
    return decode_value(column, bytes(raw))


def parse_exec(payload: bytes) -> ExecRequest:
    """Parse an OALL8 execute payload (the TTC message from ``read_packet``).

    Extracts the SQL text and any bind values (positional, decoded by their OAC
    type). Raises :class:`InterfaceError` if the message is not a TTI_ALL8
    execute.
    """
    if len(payload) < 3 or payload[0] != TTI_FUN or payload[1] != TTI_ALL8:
        raise InterfaceError('not an OALL8 execute')

    rest = payload[3:]  # skip TTI_FUN, TTI_ALL8, seq
    options, rest = decode_ub4(rest)
    autocommit = bool(options & _EXEC_OPTION_COMMIT)
    cursor, rest = decode_ub4(rest)
    query_flag, rest = rest[0], rest[1:]
    query_len, rest = decode_ub4(rest)
    _all8_flag, rest = rest[0], rest[1:]
    all8_len, rest = decode_ub4(rest)
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

    binds: list = []
    bind_rows: list = []
    if bind_count > 0:
        # After the SQL: the al8 option array, then one OAC (type descriptor)
        # per bind column, then one RXD row of values per array-DML iteration
        # (an ordinary single execute is just one row).
        after = rest[query_len:]
        for _ in range(all8_len):
            _, after = decode_ub4(after)
        types = []
        for _ in range(bind_count):
            data_type, _maxlen, _scale, _charset, after = decode_token_oac(after, ())
            types.append(data_type)
        # Each row is a TTI_RXD token followed by one DALC per bind column; loop
        # until the rows run out (executemany sends N, a plain execute sends 1).
        while after and after[0] == TTI_RXD:
            after = after[1:]
            row = []
            for data_type in types:
                raw, after = decode_dalc(after)
                row.append(_decode_bind_value(data_type, raw))
            bind_rows.append(row)
        if bind_rows:
            binds = bind_rows[0]

    return ExecRequest(
        sql=sql,
        cursor=cursor,
        bind_count=bind_count,
        fetch=fetch,
        binds=binds,
        bind_rows=bind_rows,
        autocommit=autocommit,
    )


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


def _encode_temporal(value: datetime.date, data_type: int) -> bytes:
    # A temporal column has a fixed wire width fixed by its *type*, not by the
    # particular value — so we dispatch on the column's data_type rather than
    # letting encode_token_datetime() pick 7/11/13 bytes from the value. A plain
    # date is promoted to midnight of that day.
    dt = (
        value
        if isinstance(value, datetime.datetime)
        else datetime.datetime(value.year, value.month, value.day)
    )
    if data_type == TNS_TYPE_TIMESTAMPTZ:
        # 13 bytes: DATE prefix + nanoseconds + offset. Assume UTC if the value
        # carries no zone (a naive value in a TZ column).
        aware = (
            dt if dt.tzinfo is not None else dt.replace(tzinfo=datetime.timezone.utc)
        )
        return encode_token_datetime(aware)
    if data_type == TNS_TYPE_TIMESTAMP:
        # 11 bytes always: DATE prefix + 4 BE nanosecond bytes (zero when the
        # value has no sub-second part), keeping the column a fixed width.
        naive = dt.replace(tzinfo=None)
        return _encode_date_prefix(naive) + (naive.microsecond * 1000).to_bytes(
            4, 'big'
        )
    # Oracle DATE: date + time to the second, 7 bytes. Sub-second and zone parts
    # are dropped (that is what DATE, as distinct from TIMESTAMP, means).
    return _encode_date_prefix(dt.replace(microsecond=0, tzinfo=None))


def _encode_value(value: object, data_type: int) -> bytes:
    # A scalar column value as a DALC (1-byte length + data). NULL is the empty
    # DALC; text is UTF-8; a number is Oracle's base-100 NUMBER encoding; a
    # datetime/date is encoded per the column's temporal type. Other types (LOB,
    # …) carry their own wire formats and land with later work.
    if value is None:
        return bytes([0])
    if isinstance(value, bool):
        # No 11g BOOLEAN type; a bool is a NUMBER 0/1 (bool is an int subclass,
        # so match it before the int branch would silently swallow it).
        return _bytes_with_length(encode_token_num(int(value)))
    if isinstance(value, (int, float)):
        # A BINARY_FLOAT / BINARY_DOUBLE column carries the IEEE-754 value in
        # Oracle's order-preserving form, not base-100 NUMBER.
        if data_type == TNS_TYPE_BDOUBLE:
            return _bytes_with_length(encode_token_binary_double(float(value)))
        if data_type == TNS_TYPE_BFLOAT:
            return _bytes_with_length(encode_token_binary_float(float(value)))
        return _bytes_with_length(encode_token_num(value))
    if isinstance(value, Decimal):
        # NUMBER via the exact base-100 Decimal encoder: high-precision values
        # (beyond float's ~15 significant digits) round-trip unchanged.
        return _bytes_with_length(encode_token_decimal(value))
    if isinstance(value, datetime.date):
        # datetime is a date subclass, so this one branch covers both; the
        # column's data_type decides DATE / TIMESTAMP / TIMESTAMPTZ width.
        return _bytes_with_length(_encode_temporal(value, data_type))
    if isinstance(value, (str, bytes)):
        # A VARCHAR2 / RAW column value: length-prefixed data, chunked when it
        # exceeds the single-byte length. encode_chr honours the negotiated field
        # version (11g single-byte chunks vs 12c+ ub4 chunks) — _bytes_with_length
        # always writes the 12c+ form, which an 11g client mis-decodes past 253
        # bytes ("truncated DALC field").
        return encode_chr(value)
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
        body += bytes([TTI_RXD]) + b''.join(
            _encode_value(v, col.data_type) for v, col in zip(row, columns)
        )
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
    call_status: int, ora_code: int, rowcount: int, message: bytes, cursor_id: int = 0
) -> bytes:
    # An OER return-status token (§6.5, 11g) — the terminal of every response.
    # Rowid / batch fields are zero; call status, the ORA error number, the
    # affected-row count, the cursor id (for a mid-fetch "more rows" status), and
    # the message text carry meaning.
    return (
        bytes([TTI_OER])
        + encode_sb4(call_status)
        + encode_sb4(0)  # end-to-end seq
        + encode_sb4(rowcount)  # current row number == DML affected rows on 11g
        + encode_sb4(ora_code)  # the ORA error number (0 on success)
        + encode_sb4(0)  # array element error 1
        + encode_sb4(0)  # array element error 2
        + encode_sb4(cursor_id)  # current cursor id
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


def encode_more_rows(cursor_id: int) -> bytes:
    """Terminate a batch that did NOT drain the cursor: ``call_status = 1``, no
    error, and the cursor id — the client reads this as "more rows on cursor N"
    and issues ``TTI_FETCH`` for the rest (§5.2). The ``1403`` end-of-fetch
    (:data:`_END_OF_FETCH`) is sent only once the cursor is drained."""
    return _encode_oer(1, 0, 0, b'', cursor_id=cursor_id)


def _terminator(cursor_id: int, more: bool) -> bytes:
    return encode_more_rows(cursor_id) if more else _END_OF_FETCH


def encode_query_response(
    columns: list[ColumnMeta],
    rows: list[tuple],
    *,
    cursor_id: int = 0,
    more: bool = False,
) -> bytes:
    """Assemble a SELECT execute response: describe + rows + terminator (§6).

    ``more=True`` ends the batch with a "more rows on ``cursor_id``" status
    instead of the ``ORA-01403`` end-of-fetch, so the client fetches the rest.
    """
    return (
        encode_describe(columns)
        + encode_rows(rows, columns)
        + _terminator(cursor_id, more)
    )


def encode_fetch_response(
    columns: list[ColumnMeta],
    rows: list[tuple],
    *,
    cursor_id: int = 0,
    more: bool = False,
) -> bytes:
    """Assemble a ``TTI_FETCH`` continuation response: rows + terminator, with
    **no** describe (the column metadata was established on the execute)."""
    return encode_rows(rows, columns) + _terminator(cursor_id, more)


@dataclass(frozen=True)
class FetchRequest:
    """A parsed ``TTI_FETCH``: which cursor, and how many rows to return."""

    cursor: int
    fetch: int


def parse_fetch(payload: bytes) -> FetchRequest:
    """Parse a ``TTI_FETCH`` message: ``[TTI_FUN, TTI_FETCH, seq]`` + ub4 cursor
    id + ub4 row count (the inverse of ``encode_dictionary_fetch``)."""
    if len(payload) < 3 or payload[0] != TTI_FUN or payload[1] != TTI_FETCH:
        raise InterfaceError('not a TTI_FETCH')
    rest = payload[3:]  # skip TTI_FUN, TTI_FETCH, seq
    cursor, rest = decode_ub4(rest)
    fetch, _rest = decode_ub4(rest)
    return FetchRequest(cursor=cursor, fetch=fetch)
