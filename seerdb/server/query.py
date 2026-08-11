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
    TNS_TYPE_CHAR,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
    TTI_ALL8,
    TTI_DCB,
    TTI_FETCH,
    TTI_FUN,
    TTI_OER,
    TTI_RPA,
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


# The classic sqlplus / thick-OCI (deadbeef) OALL8 marshals the same execute
# fields as the thin form above, but with the OCI conventions: an 8-byte
# 0xFE indicator (0xFFFFFFFFFFFFFFFE LE) stands in for each thin 0x01 pointer
# flag, and lengths are fixed 4-byte little-endian ub4s. For a single statement
# with no binds the header up to the SQL is a **fixed 195-byte preamble** (the
# token sequence is constant — verified across captured executes of different
# SQL lengths), so the SQL, a ub1-length-prefixed text field, sits at a fixed
# offset (#265). The preamble also carries 3x the SQL byte length as a ub4 (the
# worst-case max-byte buffer for the DB charset), which cross-checks the parse.
_OCI_ALL8_IND = b'\xfe\xff\xff\xff\xff\xff\xff\xff'
_OCI_ALL8_CURSOR_OFF = 7  # ub4 LE; 0 = a new statement
_OCI_ALL8_SQLLEN3_OFF = 19  # ub4 LE = 3 x the SQL byte length
_OCI_ALL8_SQL_OFF = 196  # SQL text; the ub1 length prefix is the byte before it


def parse_exec_oci(payload: bytes) -> ExecRequest:
    """Parse a sqlplus / thick-OCI (deadbeef dialect) OALL8 execute (#265).

    The OCI counterpart of :func:`parse_exec`. Extracts the SQL text and cursor
    id from the fixed-shape OCI header. Scope: a single statement with no binds
    and SQL up to 253 bytes (the ub1 length prefix) — binds and chunked/long SQL
    are a follow-up, gated by the length cross-check below. Raises
    :class:`InterfaceError` if the message is not an OCI OALL8 in that shape.
    """
    if (
        len(payload) < _OCI_ALL8_SQL_OFF
        or payload[0] != TTI_FUN
        or payload[1] != TTI_ALL8
    ):
        raise InterfaceError('not an OCI OALL8 execute')
    # Validate the indicators where the thin form has 0x01 flags, so a
    # differently-shaped message errors rather than yielding a garbage SQL.
    for ind_off in (11, 27):
        if payload[ind_off : ind_off + 8] != _OCI_ALL8_IND:
            raise InterfaceError(f'OCI OALL8: no indicator at offset {ind_off}')
    cursor = int.from_bytes(
        payload[_OCI_ALL8_CURSOR_OFF : _OCI_ALL8_CURSOR_OFF + 4], 'little'
    )
    marker = payload[_OCI_ALL8_SQL_OFF - 1]  # ub1 length prefix (0xFE = chunked)
    declared_len = (
        int.from_bytes(
            payload[_OCI_ALL8_SQLLEN3_OFF : _OCI_ALL8_SQLLEN3_OFF + 4], 'little'
        )
        // 3
    )
    if marker == 0xFE:
        # Long SQL — chunked from the marker: 0xFE, then <ub1 len><chunk> repeated
        # (a zero length, or the declared total, ends it).
        raw_sql = _read_chunked_sql(payload[_OCI_ALL8_SQL_OFF - 1 :], declared_len)
    elif marker == declared_len:
        raw_sql = payload[_OCI_ALL8_SQL_OFF : _OCI_ALL8_SQL_OFF + marker]
    else:
        # The two lengths disagree only for a bound statement (the bind section
        # shifts things) — out of this increment's scope, a clean error.
        raise InterfaceError('OCI OALL8: SQL length mismatch (binds not supported)')
    # sqlplus null-terminates its *internal* queries (the length counts the NUL);
    # a user-typed statement has none. Strip trailing NULs so the backend sees
    # clean SQL either way.
    sql = raw_sql.rstrip(b'\x00').decode('utf-8')
    return ExecRequest(sql=sql, cursor=cursor, bind_count=0, fetch=0)


def _read_chunked_sql(data: bytes, total_len: int) -> bytes:
    # `data` starts at the 0xFE chunk marker; collect <ub1 len><chunk> runs until
    # the declared total is reached or a zero-length chunk terminates it.
    out = bytearray()
    i = 1  # skip the 0xFE marker
    while len(out) < total_len and i < len(data):
        chunk_len = data[i]
        i += 1
        if chunk_len == 0:
            break
        out += data[i : i + chunk_len]
        i += chunk_len
    return bytes(out[:total_len])


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


def _oci_ub4(n: int) -> bytes:
    return int(n).to_bytes(4, 'little')


# The very first thing sqlplus / thick OCI sends after login is a version call
# (its TTC payload leads with 0x11 0x6b); the server answers with its banner, and
# sqlplus prints "Connected to: <banner>". The reply is a TTI_RPA carrying the
# banner as a DALC (ub2 count + ub1-chunked string) plus a fixed 10-byte packed
# version/flags trailer (#265).
_OCI_VERSION_CALL = b'\x11\x6b'
# Packed 11.2 version + capability flags, as the real XE 11.2 listener returns.
_OCI_VERSION_TRAILER = bytes.fromhex('02200b09010000000300')


def is_version_call_oci(payload: bytes) -> bool:
    """True if this is the sqlplus / thick-OCI post-login version request."""
    return payload[:2] == _OCI_VERSION_CALL


def encode_version_banner_oci(banner: bytes) -> bytes:
    """Build the sqlplus / thick-OCI version reply — the server's banner (#265).

    Returns the TTC payload from the TTI_RPA token: the banner as a DALC value
    (ub2 count + single ub1 chunk, since the banner is well under 254 bytes) and
    the fixed packed-version trailer.
    """
    return (
        bytes([TTI_RPA])
        + len(banner).to_bytes(2, 'little')
        + bytes([len(banner)])
        + banner
        + b'\x00'  # DALC terminator
        + _OCI_VERSION_TRAILER
    )


# The classic sqlplus / thick-OCI (deadbeef) describe (TTI_DCB) marshals the
# same per-column metadata as the thin form, but field-by-field in the OCI
# conventions: fixed 4-byte little-endian lengths, a fixed 49-byte pre-name
# block per column, then the ub1-prefixed name, then a 12-byte post-name block.
# Every meaningful field (type / precision / scale / length / charset / csfrm /
# max_size / null_ok / name) is computed; the opaque server-constant trailer
# (an embedded describe-timestamp and instance ids the client skips) is emitted
# as zeros — a real codec, not a captured template (#265). Field offsets within
# the 49-byte pre-name block, verified against live 11g describes of VARCHAR2,
# NUMBER, and DATE columns:
_OCI_DCB_PREAMBLE_LEN = 23  # cursor-uuid preamble (zeroed; the client skips it)
_OCI_DCB_COL_PRENAME = 48
_OCI_DCB_COL_POSTNAME = 13
# A char type carries a charset + form-of-use and sets the pre-name char flag.
_OCI_CHAR_TYPES = frozenset({TNS_TYPE_VARCHAR, TNS_TYPE_CHAR})
_OCI_DCB_CHAR_FLAG = 0x80


def _encode_dcb_column_oci(col: ColumnMeta, position: int, first: bool) -> bytes:
    pre = bytearray(_OCI_DCB_COL_PRENAME)
    pre[0] = 0x51 if first else 0x00  # a first-column marker byte
    pre[1] = 0x01
    pre[2] = col.data_type
    is_char = col.data_type in _OCI_CHAR_TYPES
    pre[3] = _OCI_DCB_CHAR_FLAG if is_char else 0x00
    pre[4] = col.precision & 0xFF
    pre[5] = col.scale & 0xFF  # signed byte (e.g. -127 for a NUMBER literal)
    pre[6:10] = _oci_ub4(col.data_length)
    if is_char:
        pre[30:32] = int(col.charset).to_bytes(2, 'little')
        pre[32] = col.csfrm
    pre[34:38] = _oci_ub4(col.max_size)
    pre[42] = col.null_ok
    pre[43] = len(col.name)
    pre[44:48] = _oci_ub4(len(col.name))
    name = bytes([len(col.name)]) + col.name
    # The post-name block is zeroed — a live 11g describe carries no column
    # position here (verified against the captured single-column reply).
    post = bytes(_OCI_DCB_COL_POSTNAME)
    return bytes(pre) + name + post


def encode_describe_oci(columns: list[ColumnMeta]) -> bytes:
    """Build the sqlplus / thick-OCI (deadbeef dialect) describe block (#265).

    The OCI counterpart of :func:`encode_describe`. Returns the TTC payload from
    the TTI_DCB token: a zeroed cursor-uuid preamble, the max-row-size and column
    count, one fixed-shape block per column, then a zeroed opaque trailer.
    """
    out = bytearray([TTI_DCB])
    out += _oci_ub4(_OCI_DCB_PREAMBLE_LEN) + bytes(_OCI_DCB_PREAMBLE_LEN)
    # Max row size: the thick/OCI client allocates a row buffer of this many
    # bytes, so it must cover the widest row — a zero here overflows and crashes
    # sqlplus (unlike the thin client, which skips the field).
    out += _oci_ub4(sum(c.data_length for c in columns))
    out += _oci_ub4(len(columns))
    for position, col in enumerate(columns, start=1):
        out += _encode_dcb_column_oci(col, position, first=(position == 1))
    return bytes(out)


# The two OCI execute-response trailers, reduced to their load-bearing structure
# by live bisection against sqlplus (#265): everything a real 11g reply carries
# here — a describe timestamp, the query SCN, assorted counts — is zeroable; only
# the field *framing* and a few structural constants matter (zeroing them
# segfaults sqlplus or draws ORA-03113). So both are computed as mostly-zero with
# those constants in place, not replayed from a capture.
_OCI_DCB_TAIL_LEN = 83
_OCI_DCB_DATE_LEN = 7  # describe-time DALC: length is load-bearing, value is not
_OCI_DCB_MARKER_OFF = 33
_OCI_DCB_MARKER = bytes.fromhex('060122')  # a required 3-byte descriptor marker
# The column count sits one byte past the marker; the client reads it to know how
# many values to expect in each row, so it is load-bearing for a multi-column
# result (verified: 1/2/3 across live 1/2/3-column describes).
_OCI_DCB_NUMCOLS_OFF = 37
# The execute return status (an OCI OER, offsets 32:65 of the status trailer):
# call status + the return marker sqlplus needs to accept the row set. Reproduced
# as a unit — the row-count fields inside are constant for the single-row replies
# handled so far; generalising it is a follow-up.
_OCI_EXEC_OER_OFF = 32
_OCI_EXEC_OER = bytes.fromhex(
    '000000040100000013000101000000000000000000020000000300000000000000'
)
_OCI_ROW_STATUS_LEN = 171


def _oci_dcb_tail(numcols: int) -> bytes:
    tail = bytearray(_OCI_DCB_TAIL_LEN)
    tail[1:5] = _oci_ub4(_OCI_DCB_DATE_LEN)  # describe-time DALC char length
    tail[5] = _OCI_DCB_DATE_LEN  # DALC byte length; the value stays zero
    off = _OCI_DCB_MARKER_OFF
    tail[off : off + len(_OCI_DCB_MARKER)] = _OCI_DCB_MARKER
    tail[_OCI_DCB_NUMCOLS_OFF] = numcols
    return bytes(tail)


def _oci_row_status() -> bytes:
    status = bytearray(_OCI_ROW_STATUS_LEN)
    status[0:3] = b'\x08\x06\x00'  # return marker
    status[11] = 0x02  # a required sentinel
    off = _OCI_EXEC_OER_OFF
    status[off : off + len(_OCI_EXEC_OER)] = _OCI_EXEC_OER
    return bytes(status)


# The OCI end-of-fetch terminator sqlplus reads after the execute's rows: an OER
# carrying ORA-01403 ("no data found"), which the client treats as "cursor
# drained" rather than an error (the thin path keeps the same thing as its
# captured _END_OF_FETCH). Reduced to structure by live bisection (#265): a
# 24-byte OER header (call status + the 1403 code) and one instance constant,
# the rest zero, then the message computed.
_OCI_FETCH_OER_LEN = 136
_OCI_FETCH_OER_HEADER = bytes.fromhex(
    '0401000000140001010000007b0500000000020000000300'
)
_OCI_FETCH_CONST_OFF = 73
_OCI_FETCH_CONST = bytes.fromhex('f6310a')
_OCI_END_OF_FETCH_MSG = b'ORA-01403: no data found\n'


def encode_fetch_terminator_oci() -> bytes:
    """The sqlplus / thick-OCI end-of-fetch reply (ORA-01403 = cursor drained)."""
    oer = bytearray(_OCI_FETCH_OER_LEN)
    oer[0 : len(_OCI_FETCH_OER_HEADER)] = _OCI_FETCH_OER_HEADER
    off = _OCI_FETCH_CONST_OFF
    oer[off : off + len(_OCI_FETCH_CONST)] = _OCI_FETCH_CONST
    return bytes(oer) + bytes([len(_OCI_END_OF_FETCH_MSG)]) + _OCI_END_OF_FETCH_MSG


# A real 11g OCI error OER (captured for ORA-00942), the structure before the
# message. Its call status (0x05) and frame differ from the end-of-fetch OER — a
# real error, not "cursor drained" — so reusing the terminator here crashes
# sqlplus. The ORA code goes at offset 12 (ub4 LE); the rest is the error frame +
# the 0x20f6310a instance constant, mostly zero (#265, #350).
_OCI_ERROR_OER = bytes.fromhex(
    '04050000001300010000000000000000000002000e0003000000000000000000000000'
    '0000000000000000000000000000150000010000003601000000000000000000000000'
    '000020f6310a0000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000'
)
_OCI_ERROR_CODE_OFF = 12


def encode_error_oci(ora_code: int, message: str) -> bytes:
    """OCI error reply — an OER carrying ORA-<code>: <message>, connection intact.

    The deadbeef-dialect counterpart of :func:`encode_error`: a failing statement
    surfaces in sqlplus as the ORA error and the session stays usable.
    """
    oer = bytearray(_OCI_ERROR_OER)
    oer[_OCI_ERROR_CODE_OFF : _OCI_ERROR_CODE_OFF + 4] = int(ora_code).to_bytes(
        4, 'little'
    )
    text = f'ORA-{ora_code:05d}: {message}\n'.encode('utf-8')
    return bytes(oer) + bytes([len(text)]) + text


def encode_query_response_oci(columns: list[ColumnMeta], rows: list[tuple]) -> bytes:
    """Assemble a sqlplus / thick-OCI SELECT execute response (#265).

    describe + DCB tail + one TTI_RXD per row + the status trailer. The whole
    result comes back on the execute (sqlplus fetches only the terminator after).
    Renders live in sqlplus 11.2; the two trailers are computed (:func:`_oci_dcb_tail`
    / :func:`_oci_row_status`), not captured blobs.
    """
    out = bytearray(encode_describe_oci(columns))
    out += _oci_dcb_tail(len(columns))
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        out += bytes([TTI_RXD]) + b''.join(
            _encode_value(v, col.data_type) for v, col in zip(row, columns)
        )
    out += _oci_row_status()
    return bytes(out)


# The reply for a statement that returns no rows — a PL/SQL block or DDL. Same
# shape as the row-status trailer (:func:`_oci_row_status`), but its own sentinel
# and OER (this one reports zero rows). Structure only; the SCN / counts a live
# reply carries are zero (#265).
_OCI_STATUS_OER = bytes.fromhex(
    '000000040100000007000101000000000000000000010000002f00000000000000'
)


def encode_status_oci() -> bytes:
    """OCI reply for a no-row statement (PL/SQL / DDL): success, nothing to fetch."""
    status = bytearray(_OCI_ROW_STATUS_LEN)
    status[0:3] = b'\x08\x06\x00'
    status[11] = 0x01
    off = _OCI_EXEC_OER_OFF
    status[off : off + len(_OCI_STATUS_OER)] = _OCI_STATUS_OER
    return bytes(status)


# A live commit reply — a small TTI_STA status (the value is the affected-row
# count / message length, zero here). sqlplus sends a bare commit before the
# user's statement; this acknowledges it.
_OCI_COMMIT_STATUS = bytes.fromhex('09050000001200')


def encode_commit_status_oci() -> bytes:
    """OCI reply to a bare commit / rollback — a TTI_STA acknowledgement."""
    return _OCI_COMMIT_STATUS


# sqlplus waits for this TTI_STA acknowledgement of its logoff before closing;
# without it the client sees an abrupt EOF and reports ORA-03113 on exit.
_OCI_LOGOFF_STATUS = bytes.fromhex('09010000000000')


def encode_logoff_status_oci() -> bytes:
    """OCI reply acknowledging a client logoff (TTI_LOGOFF)."""
    return _OCI_LOGOFF_STATUS


# The classic sqlplus / thick-OCI OALL8 arrives wrapped in an OCCA (close-cursors)
# piggyback for every statement past the first: `0x11 0x69`, then a fixed prefix
# (seq, an 8-byte indicator, the ub4 cursor count, and one 8-byte entry per closed
# cursor), then the real TTI_FUN execute. Strip it so the execute can be parsed.
_OCI_PIGGYBACK = b'\x11\x69'
_OCI_PIGGYBACK_FIXED = 3 + 8 + 4  # 0x11 0x69 seq | indicator | ub4 count


def strip_oci_piggyback(body: bytes) -> bytes:
    """Return the OALL8 execute inside an OCCA piggyback, or ``body`` unchanged."""
    if body[:2] != _OCI_PIGGYBACK:
        return body
    count = int.from_bytes(body[11:15], 'little')
    return body[_OCI_PIGGYBACK_FIXED + count * 8 :]


def _decode_describe_oci(payload: bytes) -> list[dict]:
    # A minimal reader for encode_describe_oci's own output — the thin client
    # can't parse the OCI describe, so this round-trips the meaningful fields to
    # prove the field layout is self-consistent (offline; sqlplus is the wire
    # conformance check).
    assert payload[0] == TTI_DCB
    plen = int.from_bytes(payload[1:5], 'little')
    body = payload[5 + plen :]
    numcols = int.from_bytes(body[4:8], 'little')
    cols = []
    off = 8
    for _ in range(numcols):
        pre = body[off : off + _OCI_DCB_COL_PRENAME]
        namelen = pre[43]
        name = body[
            off + _OCI_DCB_COL_PRENAME + 1 : off + _OCI_DCB_COL_PRENAME + 1 + namelen
        ]
        cols.append(
            {
                'data_type': pre[2],
                'precision': pre[4],
                'scale': pre[5] - 256 if pre[5] > 127 else pre[5],
                'data_length': int.from_bytes(pre[6:10], 'little'),
                'charset': int.from_bytes(pre[30:32], 'little'),
                'max_size': int.from_bytes(pre[34:38], 'little'),
                'null_ok': pre[43],
                'name': name,
            }
        )
        off += _OCI_DCB_COL_PRENAME + 1 + namelen + _OCI_DCB_COL_POSTNAME
    return cols


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
