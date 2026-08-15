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
import re
from dataclasses import dataclass, field
from decimal import Decimal

from seerdb.common.exceptions import DataError, InterfaceError
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
    TNS_TYPE_BLOB,
    TNS_TYPE_CHAR,
    TNS_TYPE_CLOB,
    TNS_TYPE_DATE,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
    TTI_ALL8,
    TTI_DCB,
    TTI_FETCH,
    TTI_FUN,
    TTI_LOB,
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
_OCI_ALL8_IND_OFF = 11  # the SQL pointer indicator; absent on a re-execute
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
    bind_count = int.from_bytes(
        payload[_OCI_BIND_COUNT_OFF : _OCI_BIND_COUNT_OFF + 4], 'little'
    )
    binds: list = []
    if bind_count and marker != 0xFE:
        binds = _parse_oci_binds(payload, _OCI_ALL8_SQL_OFF + marker, bind_count)
    return ExecRequest(
        sql=sql,
        cursor=cursor,
        bind_count=bind_count,
        fetch=0,
        binds=binds,
        bind_rows=[binds] if binds else [],
    )


def is_reexecute_oci(payload: bytes) -> bool:
    """True if an OCI OALL8 is a re-execute of an already-described cursor — it
    carries no SQL (the SQL pointer at offset 11 is absent). sqlplus issues one
    to pull a LONG / LONG RAW row after setting up its streaming define, so the
    Mirror answers it with the row it parked on the describe (#407)."""
    return (
        len(payload) > _OCI_ALL8_IND_OFF + 8
        and payload[0] == TTI_FUN
        and payload[1] == TTI_ALL8
        and payload[_OCI_ALL8_IND_OFF : _OCI_ALL8_IND_OFF + 8] != _OCI_ALL8_IND
    )


# The bind count sits at this fixed ub4 in the OCI OALL8 header. After the SQL
# come an option array, one OAC type-descriptor per bind (each led by
# ``01 <TNS type> 03 00 00``), and an RXD row (``0x07`` + one DALC value per
# bind) — the same value framing the thin form uses (#265, #347).
_OCI_BIND_COUNT_OFF = 83
_OCI_OAC_MARKER = re.compile(rb'\x01(.)\x03\x00\x00')
_OCI_BIND_TYPES = frozenset(
    {
        TNS_TYPE_VARCHAR,
        TNS_TYPE_NUMBER,
        TNS_TYPE_DATE,
        TNS_TYPE_RAW,
        TNS_TYPE_CHAR,
        TNS_TYPE_TIMESTAMP,
        TNS_TYPE_TIMESTAMPTZ,
        TNS_TYPE_BFLOAT,
        TNS_TYPE_BDOUBLE,
    }
)


def _parse_oci_binds(payload: bytes, sql_end: int, bind_count: int) -> list:
    # Read the bind values from the OCI bind section: collect each bind's TNS
    # type from its OAC marker, then decode the RXD row's DALC values by type.
    tail = payload[sql_end:]
    types = []
    for match in _OCI_OAC_MARKER.finditer(tail):
        data_type = match.group(1)[0]
        if data_type in _OCI_BIND_TYPES:
            types.append(data_type)
        if len(types) == bind_count:
            break
    if len(types) != bind_count:
        return []
    # The RXD row is the 0x07 token whose following DALCs decode cleanly into one
    # value per bind — a position robust to 0x07 bytes appearing in the OAC area.
    for i, byte in enumerate(tail):
        if byte != TTI_RXD:
            continue
        rest = tail[i + 1 :]
        values: list = []
        try:
            for data_type in types:
                raw, rest = decode_dalc(rest)
                values.append(_decode_bind_value(data_type, raw))
        except (IndexError, DataError):
            continue
        if len(values) == bind_count:
            return values
    return []


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
# LONG (#407) and CLOB (#405) are character types (charset + form-of-use, like
# VARCHAR2); LONG RAW and BLOB are binary. LONG / LONG RAW stream inline, LOBs
# are fetched by locator — but neither has a fixed width, so a live 11g describe
# reports data_length / max_size / max-row-size all 0 for both.
_OCI_CHAR_TYPES = frozenset(
    {TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_LONG, TNS_TYPE_CLOB}
)
_OCI_LONG_TYPES = frozenset({TNS_TYPE_LONG, TNS_TYPE_LONGRAW})
_OCI_LOB_TYPES = frozenset({TNS_TYPE_CLOB, TNS_TYPE_BLOB})
# Types with no fixed row width: excluded from the column max size and the
# describe max-row-size (their value is a locator or an inline stream, not a
# fixed-width buffer).
_OCI_UNSIZED_TYPES = _OCI_LONG_TYPES | _OCI_LOB_TYPES
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
    # A LONG / LONG RAW / LOB carries no fixed max size — the value is a locator or
    # an inline stream, unbounded — so a live 11g describe leaves this zero (like
    # the data length the backend already sets to 0). Only fixed-width columns fill
    # it (#405, #407).
    if col.data_type not in _OCI_UNSIZED_TYPES:
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
    # sqlplus (unlike the thin client, which skips the field). A LONG / LONG RAW /
    # LOB is a locator or an inline stream, unbounded, so it contributes nothing to
    # the fixed row buffer (its data_length is 0 anyway); it is excluded to match a
    # live 11g describe, which reports max-row-size 0 for such a result (#405, #407).
    out += _oci_ub4(
        sum(c.data_length for c in columns if c.data_type not in _OCI_UNSIZED_TYPES)
    )
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


# When the execute delivers fewer rows than the result holds, this byte in the
# status is non-zero — the client reads it as "more rows, issue a fetch" (0 =
# the cursor is already drained). The exact value is not load-bearing beyond
# non-zero; 0x1e is what a live reply carries.
_OCI_MORE_ROWS_OFF = 55
_OCI_MORE_ROWS_FLAG = 0x1E


def _oci_row_status(*, more: bool = False) -> bytes:
    status = bytearray(_OCI_ROW_STATUS_LEN)
    status[0:3] = b'\x08\x06\x00'  # return marker
    status[11] = 0x02  # a required sentinel
    off = _OCI_EXEC_OER_OFF
    status[off : off + len(_OCI_EXEC_OER)] = _OCI_EXEC_OER
    if more:
        status[_OCI_MORE_ROWS_OFF] = _OCI_MORE_ROWS_FLAG
    return bytes(status)


# The row-header (TTI_RXH) that leads a fetch batch: a small fixed frame plus the
# query SCN (zeroable). Reduced to its non-zero structure from a live fetch reply
# (#265, #351).
_OCI_RXH_LEN = 50
_OCI_RXH_NONZERO = {0: 0x06, 1: 0x01, 2: 0x02, 4: 0x02, 10: 0x0F}


def _oci_rxh() -> bytes:
    rxh = bytearray(_OCI_RXH_LEN)
    for off, value in _OCI_RXH_NONZERO.items():
        rxh[off] = value
    return bytes(rxh)


def encode_fetch_batch_oci(columns: list[ColumnMeta], rows: list[tuple]) -> bytes:
    """A sqlplus / thick-OCI fetch reply: RXH + one RXD per row + end-of-fetch.

    Used when the execute parked rows for follow-up fetches — the batch carries
    the next rows and, since the Mirror returns the remainder in one go, the
    ORA-01403 terminator (#351).
    """
    out = bytearray(_oci_rxh())
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        out += bytes([TTI_RXD]) + b''.join(
            _encode_oci_value(v, col) for v, col in zip(row, columns)
        )
    out += encode_fetch_terminator_oci()
    return bytes(out)


def encode_reexec_row_oci(
    columns: list[ColumnMeta], rows: list[tuple], *, more: bool = False
) -> bytes:
    """The reply to a re-execute-to-fetch (a LONG / streamed column, #407).

    sqlplus describes the query, sets up its streaming define, then re-executes
    the cursor to pull the rows — one LONG row per reply, each led by a row header
    and ended with the row status (``more`` set while rows remain), then a final
    fetch draws the 1403 terminator. No describe (the client already has it).
    Matches a live 11g LONG re-execute / fetch reply."""
    out = bytearray(_oci_rxh())
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        out += bytes([TTI_RXD]) + b''.join(
            _encode_oci_value(v, col) for v, col in zip(row, columns)
        )
    out += _oci_row_status(more=more)
    return bytes(out)


# The OER status that trails a *fetch*-delivered LONG row (as opposed to the
# execute row-status of the re-execute reply): a 136-byte OER with no error and a
# "more rows" call status, captured from a live 11g LONG fetch. It carries no
# message (unlike the 1403 terminator) — the final empty fetch draws the
# terminator instead (#407).
_OCI_LONG_FETCH_STATUS = bytes.fromhex(
    '04010000001100010200000000000000000002000000030000000000000000000000'
    '00000000000000000000000000000013000001000000360100000000000000000000'
    '0000000020f6310a0000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000'
)


def encode_long_fetch_row_oci(columns: list[ColumnMeta], row: tuple) -> bytes:
    """The fetch reply carrying one LONG row (#407): row header + the row, then a
    "more rows" OER status (not the execute row-status the re-execute reply uses,
    nor the 1403 terminator — a following empty fetch drains that)."""
    if len(row) != len(columns):
        raise InterfaceError('row width does not match the column count')
    out = bytearray(_oci_rxh())
    out += bytes([TTI_RXD]) + b''.join(
        _encode_oci_value(v, col) for v, col in zip(row, columns)
    )
    return bytes(out) + _OCI_LONG_FETCH_STATUS


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


def encode_query_response_oci(
    columns: list[ColumnMeta], rows: list[tuple], *, more: bool = False
) -> bytes:
    """Assemble a sqlplus / thick-OCI SELECT execute response (#265).

    describe + DCB tail + one TTI_RXD per row + the status trailer. ``more=True``
    marks the result as not fully delivered, so sqlplus follows up with a fetch
    (see :func:`encode_fetch_batch_oci`); the trailers are computed, not blobs.
    """
    out = bytearray(encode_describe_oci(columns))
    out += _oci_dcb_tail(len(columns))
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        out += bytes([TTI_RXD]) + b''.join(
            _encode_oci_value(v, col) for v, col in zip(row, columns)
        )
    out += _oci_row_status(more=more)
    return bytes(out)


# The execute reply for a LOB SELECT is a describe with NO row inline — sqlplus
# sets up its LOB define from it and fetches the locator rows separately. It is
# NOT the ordinary describe: instead of the 83-byte DCB tail that precedes inline
# rows it carries a 33-byte describe tail (a describe-timestamp form, no DCB
# marker), and its own execute status/OER. Both are reduced from a live 11g CLOB
# describe with the instance-specific bytes (the timestamp, the SCN) zeroed (#405).
_OCI_LOB_DESCRIBE_TAIL = bytes.fromhex(
    '0007000000070000000000000000000000e81f0000000000000000000000000000'
)
_OCI_LOB_DESCRIBE_STATUS = bytes.fromhex(
    '08060000000000000000000200000000000000000000000000000000000000000000'
    '0004010000000f00010000000000000000000002000e000300000000000000000000'
    '00000000000000000000000000000000110000010000003601000000000000000000'
    '000000000020f6310a00000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000'
    '00'
)


def encode_lob_describe_oci(columns: list[ColumnMeta]) -> bytes:
    """The execute reply for a LOB (CLOB/BLOB) SELECT (#405): the TTI_DCB block +
    a 33-byte describe tail + the LOB execute status — describe only, no row (the
    locator rows come on the follow-up fetch). Matching this exactly is what makes
    sqlplus set up its LOB define correctly and accept the locator row rather than
    break (an ordinary describe, with the inline-row DCB tail, is rejected)."""
    return (
        bytes(encode_describe_oci(columns))
        + _OCI_LOB_DESCRIBE_TAIL
        + _OCI_LOB_DESCRIBE_STATUS
    )


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


# Execute-status replies for OCI DML (#348), reproduced from live 11g replies so
# sqlplus renders the right completion message ("N rows updated.") instead of the
# generic PL/SQL one. sqlplus derives the *verb* from statement-type fields in the
# reply (the SQL command code — INSERT 2, UPDATE 6, DELETE 7 — and neighbours), so
# each DML verb needs its own captured template; the *count* is a `ub4`
# little-endian at offset 43 of the body, the one field computed. The surrounding
# structure (return marker, SCN region, cursor/rowid trailer, and a session
# row-counter at 75/186 that is NOT the count) is carried as-is. Fully computing
# the OER is a follow-up.
_OCI_DML_STATUS = {
    'INSERT': bytes.fromhex(
        '08060024e85b00000000000200000001000000000000000000000000000000000000'
        '0004020000001300010100000000000000000002000c000200000000007fb5010001'
        '000000b1b40000000000000000000000150000010000003601000000000000000000'
        '000000000020f6310a000000000d0000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000'
        '000d000d010001b57f00010000b4b10000'
    ),
    'UPDATE': bytes.fromhex(
        '08060025e85b00000000000200000001000000000000000000000000000000000000'
        '00040200000019000102000000000000000000020007000600000000007fb5010001'
        '000000b1b400000100000000000000001b0000010000003601000000000000000000'
        '000000000020f6310a000000000d0000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000'
        '000d000d010001b57f00010000b4b10001'
    ),
    'DELETE': bytes.fromhex(
        '08060026e85b00000000000300000001000000000000000000000000000000000000'
        '0004020000001b00010100000000000000000003000c000700000000007fb5010001'
        '000000b1b400000200000000000000001d0000010000003601000000000000000000'
        '000000000020f6310a000000000d0000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000'
        '000d000d010001b57f00010000b4b10002'
    ),
}
_OCI_DML_ROWCOUNT_OFF = 43


def encode_dml_status_oci(keyword: str, rowcount: int) -> bytes:
    """OCI reply for a DML — success carrying the affected-row count so sqlplus
    prints ``N rows created/updated/deleted``. ``keyword`` (INSERT/UPDATE/DELETE)
    selects the verb template; MERGE and anything else fall back to INSERT."""
    status = bytearray(_OCI_DML_STATUS.get(keyword, _OCI_DML_STATUS['INSERT']))
    status[_OCI_DML_ROWCOUNT_OFF : _OCI_DML_ROWCOUNT_OFF + 4] = rowcount.to_bytes(
        4, 'little'
    )
    return bytes(status)


# Execute-status replies for OCI DDL (#349), CREATE TABLE / DROP TABLE captured
# from live 11g. Same shape as the DML status above: sqlplus reads the SQL command
# code at body offset 57 (CREATE TABLE 1, DROP TABLE 12 — the V$SQL COMMAND_TYPE
# values) plus neighbouring type fields at 40/53/55/84 to pick "Table created."
# vs "Table dropped.". DDL affects no rows, so unlike DML nothing is computed —
# each verb carries its own captured 171-byte body verbatim. Only CREATE and DROP
# are captured; other DDL verbs/objects keep the generic no-row status (a follow-up
# would capture ALTER/TRUNCATE and the non-TABLE object variants).
_OCI_DDL_STATUS = {
    'CREATE': bytes.fromhex(
        '080600b0eb5b00000000000100000000000000000000000000000000000000000000'
        '00040100000011000100000000000000000000010000000100000000000000000000'
        '00000000000000000000000000000000130000010000003601000000000000000000'
        '000000000020f6310a00000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000'
        '00'
    ),
    'DROP': bytes.fromhex(
        '080600c1eb5b00000000000300000000000000000000000000000000000000000000'
        '0004010000001300010000000000000000000003000b000c00000000000000000000'
        '00000000000000000000000000000000150000010000003601000000000000000000'
        '000000000020f6310a00000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000'
        '00'
    ),
}


def encode_ddl_status_oci(keyword: str) -> bytes:
    """OCI reply for a DDL — success so sqlplus prints ``Table created.`` /
    ``Table dropped.``. ``keyword`` (CREATE/DROP) selects the captured body;
    anything else falls back to CREATE."""
    return _OCI_DDL_STATUS.get(keyword, _OCI_DDL_STATUS['CREATE'])


# The sqlplus / thick-OCI reply to a PL/SQL block that assigned OUT binds — the
# ``VARIABLE v NUMBER`` / ``EXEC :v := 42`` flow. The client parked bind buffers
# and expects their values back: a ttc=0b01 message whose body is a fixed header
# (bind count at offset 4), one 0x10 define-marker per bind, then an RXD row
# (``0x07`` + one DALC per OUT value, each followed by a 2-byte per-bind return
# code) and a fixed status/OER tail. Reduced to structure from live 11g replies
# (single NUMBER, two NUMBERs, VARCHAR): the server pointer (@18), SCN and an
# internal sequence counter are instance-specific and zeroed; everything else is
# computed from the OUT values (#347).
_OCI_OUTBIND_HEADER = bytes.fromhex(
    '0b0105cc000000000000010000000000000000000000000000000000e807000000000000'
    '0000000000000000000000000000'
)
_OCI_OUTBIND_BINDCOUNT_OFF = 4
_OCI_OUTBIND_DEFINE_MARKER = 0x10
_OCI_OUTBIND_RETCODE = b'\x00\x00'
_OCI_OUTBIND_TAIL = bytes.fromhex(
    '08060000000000000000000200000000000000000000000000000000000000000000000401000000'
    '00000101000000000000000000020000002f00000000000000000000000000000000000000000000'
    '00000000000000010000003601000000000000000000000000000020f6310a000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000'
)


def encode_out_bind_response_oci(values: list[object]) -> bytes:
    """OCI reply returning a PL/SQL block's OUT bind values (``EXEC :v := ...``).

    ``values`` are the assigned OUT values in bind order; each is marshalled as a
    DALC (the same wire form as a fetched column) so the client reads it back into
    its bound buffer. The header/tail are computed structure, not blobs (#347).
    """
    header = bytearray(_OCI_OUTBIND_HEADER)
    header[_OCI_OUTBIND_BINDCOUNT_OFF] = len(values)
    define_markers = bytes([_OCI_OUTBIND_DEFINE_MARKER]) * len(values)
    rxd = bytes([TTI_RXD]) + b''.join(
        _encode_value(v, 0) + _OCI_OUTBIND_RETCODE for v in values
    )
    return bytes(header) + define_markers + rxd + _OCI_OUTBIND_TAIL


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
    # datetime/date is encoded per the column's temporal type.
    if value is None:
        return bytes([0])
    if data_type in _OCI_LOB_TYPES:
        # A thin (seerdb / oracledb-thin) CLOB / BLOB value is delivered as an
        # opaque locator, not inline; the content follows over TTI_LOBOPS. The
        # session registers each cell's content row-major and answers the reads
        # in order (#413).
        return encode_lob_locator_thin()
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


# --- OCI LONG / LONG RAW row value (#407) ---
# A LONG (type 8, character) or LONG RAW (type 24, binary) column is streamed
# inline in the RXD — no LOB locator. The value is always the chunked form
# (0xFE marker, then a run of <ub1 len><bytes> chunks terminated by a zero-length
# chunk) even when it fits one chunk, followed by a trailing ub4 indicator (0),
# reproduced from a live 11g capture. A NULL LONG is a single 0x00. Character LONG
# content is UTF-8, LONG RAW is raw bytes.
_OCI_LONG_CHUNK = 0xFC  # max bytes per inline LONG chunk
_OCI_LONG_TRAILER = bytes(4)  # trailing ub4 indicator (actual/return length = 0)


def encode_long_value_oci(value: object) -> bytes:
    """The RXD value for a LONG / LONG RAW column (#407): the content streamed
    inline as 0xFE-chunked bytes + a zero trailing indicator. NULL is an empty
    value (0x00) still followed by the trailing indicator. ``str`` content is
    UTF-8 (LONG), ``bytes`` is raw (LONG RAW)."""
    if value is None:
        return bytes([0]) + _OCI_LONG_TRAILER
    if isinstance(value, str):
        content = value.encode('utf-8')
    elif isinstance(value, (bytes, bytearray)):
        content = bytes(value)
    else:
        content = str(value).encode('utf-8')
    out = bytearray([0xFE])
    for start in range(0, len(content), _OCI_LONG_CHUNK):
        chunk = content[start : start + _OCI_LONG_CHUNK]
        out += bytes([len(chunk)]) + chunk
    out += bytes([0])  # zero-length chunk terminates the run
    return bytes(out) + _OCI_LONG_TRAILER


# --- OCI LOB read round-trip (CLOB / BLOB SELECT, #405) ---
# STATUS: WORKING — sqlplus displays CLOB and BLOB values over the Mirror
# (single-packet and multi-packet content, session stays clean afterward). The
# load-bearing pieces, verified against live 11g out-of-line CLOB captures:
#   * the locator's size field is the content BYTE count (2× characters for a
#     CLOB, raw bytes for a BLOB), big-endian — NOT the character count the first
#     attempt used (the core unit bug);
#   * the LOB execute reply is a describe with a distinct 33-byte tail + LOB
#     status (encode_lob_describe_oci) and data_length 4000, NOT the ordinary
#     inline-row DCB tail — THE UNLOCK; with the wrong describe sqlplus rejects
#     even a byte-perfect locator row;
#   * the locator row is fetched (_oci_lob_rxh) and ends with a non-terminator
#     "more" OER (encode_lob_fetch_rows_oci); a following fetch draws the 1403;
#   * the READ reply's LOB_DATA uses 0xFF-byte chunks (matches 11g).
# The row locator template and the READ reply tail below come from ONE live 11g
# out-of-line CLOB capture (2000 chars → 4000 content bytes), so they echo the
# same opaque locator and stay mutually consistent.
#
# KNOWN LIMITATION (follow-up): the read returns the WHOLE LOB regardless of the
# amount sqlplus requested in the TTI_LOBOPS call, so the client must read it in
# one go — works when SET LONGCHUNKSIZE covers the content, but a default-settings
# read (80-char chunks, looping) over-reads. Honoring the request's amount/offset
# for a proper read loop is the next step.
#
# A LOB column is not sent inline: the row carries an opaque locator, and sqlplus
# fetches the content with a separate TTI_LOBOPS READ (§14). The locator is opaque
# to sqlplus (it echoes it back verbatim in the READ), so the Mirror mints it from
# this one template, patching the content **byte** size (ub4 big-endian) that
# sqlplus reads to size its READ — a CLOB counts UTF-16 bytes (2× characters), a
# BLOB counts its raw bytes. The content never rides in the locator (out-of-line):
# it returns in the READ reply's LOB_DATA. A ub4-LE num_bytes frames the locator
# in the row; a NULL LOB is num_bytes 0, no READ.
# CLOB and BLOB locators are the same shape but differ in the LOB **type** bytes
# (offsets 9/11/14 in the row value) and the **charset** (offset 37: `03 69` =
# 873 AL32UTF8 for a CLOB, `00 00` binary for a BLOB). The charset is load-bearing:
# with the CLOB template, sqlplus decodes a BLOB's content as characters and
# mangles it (raw `CA FE BA BE` → `??`). Both are captured from live 11g
# out-of-line reads (a 2000-char CLOB / a 4000-byte BLOB), keyed by is_clob.
_OCI_LOB_ROW_VALUE = {
    True: bytes.fromhex(
        '6a0000006a00680001020c88000002000000010000005643350001b58f0001b58e00'
        '020002036900020040b523000000000000000000000000005bfd6e00000000000000'
        '000000000000000000000000000001b58e0040b519000000140500000000000fa000'
        '00000000020040b523'
    ),
    False: bytes.fromhex(
        '6a0000006a00680001010c080000010000000100000056471d0001b6490001b64800'
        '020002000000020040b583000000000000000000000000005d0d5e00000000000000'
        '000000000000000000000000000001b6480040b579000000140500000000000fa000'
        '00000000020040b583'
    ),
}
_OCI_LOB_ROW_SIZE_OFF = 97  # ub4 BE content byte size inside the row locator value
# The TTI_LOBOPS READ reply tail after the LOB_DATA content: TTI_RPA (the echoed
# locator + amount read) then the OER call status. sqlplus skips the RPA to the
# OER, but the echoed locator's byte size and the amount are patched so they stay
# consistent with the content delivered. Same CLOB/BLOB split as the row value.
_OCI_LOB_READ_TAIL = {
    True: bytes.fromhex(
        '0800680001020c88000002000000010000005643350001b58f0001b58e0002000203'
        '6900020040b523000000000000000000000000005bfd6e0000000000000000000000'
        '0000000000000000000001b58e0040b519000000140500000000000fa00000000000'
        '020040b523d007000000000000040100000011000101000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000130000010000'
        '003601000000000000000000000000000020f6310a00000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000'
    ),
    False: bytes.fromhex(
        '0800680001010c080000010000000100000056471d0001b6490001b6480002000200'
        '0000020040b583000000000000000000000000005d0d5e0000000000000000000000'
        '0000000000000000000001b6480040b579000000140500000000000fa00000000000'
        '020040b583a00f000000000000040100000011000101000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000130000010000'
        '003601000000000000000000000000000020f6310a00000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000'
    ),
}
_OCI_LOB_TAIL_SIZE_OFF = 93  # ub4 BE byte size in the echoed locator
_OCI_LOB_TAIL_AMOUNT_OFF = 107  # ub4 LE amount read (characters for CLOB / bytes)
_OCI_LOB_CHUNK = 0xFF  # content bytes per 11g LOB_DATA chunk (matches live 11g)


def _oci_lob_byte_size(value: object, is_clob: bool) -> int:
    # The LOB content byte count sqlplus reads from the locator: a CLOB is UTF-16
    # on the wire (2 bytes per character), a BLOB is its raw bytes.
    if is_clob:
        return len(str(value)) * 2
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    return len(str(value))


def encode_lob_locator_oci(value: object, is_clob: bool) -> bytes:
    """The RXD value for a LOB column (#405): a minted opaque locator carrying the
    content **byte** size so sqlplus issues a TTI_LOBOPS READ. NULL is a zero
    num_bytes and draws no read."""
    if value is None:
        return bytes([0])
    byte_size = _oci_lob_byte_size(value, is_clob)
    loc = bytearray(_OCI_LOB_ROW_VALUE[is_clob])
    loc[_OCI_LOB_ROW_SIZE_OFF : _OCI_LOB_ROW_SIZE_OFF + 4] = byte_size.to_bytes(
        4, 'big'
    )
    return bytes(loc)


def _oci_lob_data(content: bytes) -> bytes:
    # TTI_LOB content: token + single-byte-length chunks (the 11g form). Content up
    # to one chunk is a plain <len><data>; larger content uses the 0xFE chunked
    # form, a run of <ub1 len><bytes> terminated by a zero-length chunk.
    if len(content) <= _OCI_LOB_CHUNK:
        return bytes([TTI_LOB, len(content)]) + content
    out = bytearray([TTI_LOB, 0xFE])
    for start in range(0, len(content), _OCI_LOB_CHUNK):
        chunk = content[start : start + _OCI_LOB_CHUNK]
        out += bytes([len(chunk)]) + chunk
    out += bytes([0])  # zero-length chunk terminates the run
    return bytes(out)


# A TTI_LOBOPS READ request carries the slice sqlplus wants: a 1-based source
# offset and an amount, both counts (characters for a CLOB, bytes for a BLOB),
# at these fixed ub8-LE offsets in the OCI request. sqlplus loops over them (in
# SET LONGCHUNKSIZE-sized steps) until a read returns fewer than it asked for.
_OCI_LOBOPS_OFFSET_OFF = 91
_OCI_LOBOPS_AMOUNT_OFF = 269


def parse_lobops_read(body: bytes) -> tuple[int, int]:
    """Extract ``(source_offset, amount)`` from an OCI TTI_LOBOPS READ (#405) —
    both 1-based counts (characters for a CLOB, bytes for a BLOB). A malformed /
    short request falls back to reading the whole LOB from the start."""
    if len(body) < _OCI_LOBOPS_AMOUNT_OFF + 8:
        return 1, 2**31
    offset = int.from_bytes(
        body[_OCI_LOBOPS_OFFSET_OFF : _OCI_LOBOPS_OFFSET_OFF + 8], 'little'
    )
    amount = int.from_bytes(
        body[_OCI_LOBOPS_AMOUNT_OFF : _OCI_LOBOPS_AMOUNT_OFF + 8], 'little'
    )
    return max(offset, 1), amount


def encode_lob_read_response_oci(
    content: bytes, amount: int, total_bytes: int | None = None, *, is_clob: bool = True
) -> bytes:
    """The TTI_LOBOPS READ reply (#405): the LOB content slice (LOB_DATA) then the
    captured TTI_RPA + OER tail. ``content`` is the UTF-16BE (CLOB) / raw (BLOB)
    bytes read this call; ``amount`` is that read's count (characters for a CLOB,
    bytes for a BLOB); ``total_bytes`` is the whole LOB's byte size the echoed
    locator reports (defaults to this slice, for a single read-it-all call).
    ``is_clob`` selects the echoed-locator template (character vs binary, #406)."""
    if total_bytes is None:
        total_bytes = len(content)
    tail = bytearray(_OCI_LOB_READ_TAIL[is_clob])
    tail[_OCI_LOB_TAIL_SIZE_OFF : _OCI_LOB_TAIL_SIZE_OFF + 4] = total_bytes.to_bytes(
        4, 'big'
    )
    tail[_OCI_LOB_TAIL_AMOUNT_OFF : _OCI_LOB_TAIL_AMOUNT_OFF + 4] = amount.to_bytes(
        4, 'little'
    )
    return _oci_lob_data(content) + bytes(tail)


def oci_lob_contents(
    columns: list[ColumnMeta], rows: list[tuple]
) -> list[tuple[bytes, bool]]:
    """The (wire-content, is_clob) of each non-NULL LOB cell, row-major (#405).

    The order matches the locators :func:`_encode_oci_value` emits, so the session
    reads this queue in sequence as sqlplus issues TTI_LOBOPS calls. CLOB content
    is UTF-16BE (``is_clob`` True — offsets/amounts count characters, 2 bytes
    each); BLOB content is raw bytes (counts bytes). The session slices this per
    the offset/amount each read requests."""
    out: list[tuple[bytes, bool]] = []
    for row in rows:
        for value, col in zip(row, columns):
            if col.data_type not in _OCI_LOB_TYPES or value is None:
                continue
            if col.data_type == TNS_TYPE_CLOB:
                out.append((str(value).encode('utf-16-be'), True))
            else:
                out.append((bytes(value), False))
    return out


# --- Thin (seerdb / oracledb-thin) LOB read (#413) ---
# The thin client keeps the RXD LOB locator opaque and hands it straight back in a
# TTI_LOBOPS READ (it asks for the whole LOB at once — amount 0x40000000 — so no
# read loop). The Mirror therefore mints a fixed placeholder locator and answers
# the reads from a row-major queue in order, matching the locators the row emits.
# The RXD block is `ub4 num_bytes | DALC(locator)` (a NULL LOB is a lone 0x00).
_THIN_LOB_LOCATOR = b'\x00seerdb-mirror-lob-locator-0000000000\x00'


def encode_lob_locator_thin() -> bytes:
    """The RXD value for a thin LOB column (#413): a minted opaque locator the
    client echoes back over TTI_LOBOPS. The content follows in the read reply."""
    return encode_sb4(len(_THIN_LOB_LOCATOR)) + _bytes_with_length(_THIN_LOB_LOCATOR)


def encode_lob_read_response_thin(content: bytes) -> bytes:
    """The thin TTI_LOBOPS READ reply (#413): the whole LOB content as LOB_DATA
    then a success OER (the client reads the content, skips to the OER, and stops).
    ``content`` is UTF-16BE for a CLOB, raw for a BLOB."""
    return _oci_lob_data(content) + _encode_oer(1, 0, 0, b'')


def _encode_oci_value(value: object, col: ColumnMeta) -> bytes:
    # A row value in the OCI dialect: a LOB column emits its locator (content comes
    # later over TTI_LOBOPS, #405); a LONG / LONG RAW column streams inline via the
    # chunked form (#407); everything else is the ordinary inline DALC value.
    if col.data_type in _OCI_LOB_TYPES:
        return encode_lob_locator_oci(value, col.data_type == TNS_TYPE_CLOB)
    if col.data_type in _OCI_LONG_TYPES:
        return encode_long_value_oci(value)
    return _encode_value(value, col.data_type)


# The OER status that trails a LOB locator row on the fetch — NOT the 1403
# terminator: the LOB content still has to come over TTI_LOBOPS, so the cursor is
# not drained. Captured from a live 11g out-of-line CLOB fetch; a following fetch
# (after the LOBOPS reads) draws the 1403 terminator (#405).
_OCI_LOB_FETCH_STATUS = bytes.fromhex(
    '04010000001000010100000000000000000002000000030000000000000000000000'
    '00000000000000000000000000000012000001000000360100000000000000000000'
    '0000000020f6310a0000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000'
)


# The row header that leads a LOB locator fetch differs from the ordinary fetch
# RXH — a live 11g LOB fetch carries this fixed frame (verified constant across
# CLOB sizes). Using the ordinary RXH makes sqlplus break on the locator row.
_OCI_LOB_RXH_NONZERO = {0: 0x06, 1: 0x01, 2: 0x22, 3: 0xFD, 4: 0x01, 10: 0x01}


def _oci_lob_rxh() -> bytes:
    rxh = bytearray(_OCI_RXH_LEN)
    for off, value in _OCI_LOB_RXH_NONZERO.items():
        rxh[off] = value
    return bytes(rxh)


def encode_lob_fetch_rows_oci(columns: list[ColumnMeta], rows: list[tuple]) -> bytes:
    """The fetch reply carrying LOB locator row(s) (#405): a row header + the rows,
    then a non-terminator OER status. The LOB content still comes over TTI_LOBOPS,
    so the cursor is not yet drained; a following fetch draws the 1403 terminator."""
    out = bytearray(_oci_lob_rxh())
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        out += bytes([TTI_RXD]) + b''.join(
            _encode_oci_value(v, col) for v, col in zip(row, columns)
        )
    return bytes(out) + _OCI_LOB_FETCH_STATUS


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
