# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side query path — parse the client's OALL8 execute (11g).

The inverse of ``tns.encode_dictionary_exec`` for the 11g wire shape: an
``OALL8`` (TTI_ALL8) function message whose fixed header carries the SQL length
and option/bind counts, followed by the raw SQL text. The describe / row
encoders that answer it are layered on separately.
"""

from __future__ import annotations

import re
import struct

from seerdb.common import oci
from seerdb.common.exceptions import DataError, InterfaceError
from seerdb.common.tns import (
    _CREATE_TEMP_PREFIX as _CREATE_TEMP_PREFIX,
)
from seerdb.common.tns import (
    _CSFRM_DB,
    _OCI_COMMIT_STATUS,
    _OCI_DCB_MARKER,
    _OCI_DDL_STATUS_FRAME,
    _OCI_DML_STATUS_FRAME,
    _OCI_EXEC_OER,
    _OCI_LOB_DESCRIBE_STATUS,
    _OCI_LOB_DESCRIBE_TAIL,
    _OCI_LOB_READ_TAIL,
    _OCI_LOB_ROW_VALUE,
    _OCI_LOGOFF_STATUS,
    _OCI_OER_ENVELOPE,
    _OCI_OUTBIND_HEADER,
    _OCI_OUTBIND_TAIL,
    _OCI_STATUS_OER,
    decode_dalc,
    encode_value,
)
from seerdb.common.tns import (
    _EXEC_OPTION_BATCH_ERRORS as _EXEC_OPTION_BATCH_ERRORS,
)
from seerdb.common.tns import (
    _EXEC_OPTION_COMMIT as _EXEC_OPTION_COMMIT,
)
from seerdb.common.tns import (
    _LOBOPS_ACK_OPS as _LOBOPS_ACK_OPS,
)
from seerdb.common.tns import (
    _MARKER_LEN as _MARKER_LEN,
)
from seerdb.common.tns import (
    _OCI_LOB_CHUNK as _OCI_LOB_CHUNK,
)
from seerdb.common.tns import (
    _OCI_LOBOPS_AMOUNT_OFF as _OCI_LOBOPS_AMOUNT_OFF,
)
from seerdb.common.tns import (
    _OCI_LOBOPS_OFFSET_OFF as _OCI_LOBOPS_OFFSET_OFF,
)
from seerdb.common.tns import (
    _SERVER_VERSION_SLOT as _SERVER_VERSION_SLOT,
)
from seerdb.common.tns import (
    _TEMP_LOB_BIND_PREFIX as _TEMP_LOB_BIND_PREFIX,
)
from seerdb.common.tns import (
    _TEMP_LOB_LOCATOR_PREFIX as _TEMP_LOB_LOCATOR_PREFIX,
)

# Re-exports: codec primitives now defined in common/tns, kept importable from
# the Mirror server API (seerdb.server.query) for existing call sites.
from seerdb.common.tns import (  # noqa: E402,F401
    ColumnMeta as ColumnMeta,
)
from seerdb.common.tns import (
    ExecRequest as ExecRequest,
)
from seerdb.common.tns import (
    FetchRequest as FetchRequest,
)
from seerdb.common.tns import (
    LobOpsRequest as LobOpsRequest,
)
from seerdb.common.tns import (
    RefCursorOutBind as RefCursorOutBind,
)
from seerdb.common.tns import (
    ScalarOutBind as ScalarOutBind,
)
from seerdb.common.tns import (
    TempLobRef as TempLobRef,
)
from seerdb.common.tns import (
    _decode_bind_value as _decode_bind_value,
)
from seerdb.common.tns import (
    _decode_lobops_chunked as _decode_lobops_chunked,
)
from seerdb.common.tns import (
    _encode_refcursor_out as _encode_refcursor_out,
)
from seerdb.common.tns import (
    _lobops_locator_after_operation as _lobops_locator_after_operation,
)
from seerdb.common.tns import (
    _oci_lob_data as _oci_lob_data,
)
from seerdb.common.tns import (
    _read_bind_value as _read_bind_value,
)
from seerdb.common.tns import (
    _read_chunked_sql as _read_chunked_sql,
)
from seerdb.common.tns import (
    _scroll_terminator as _scroll_terminator,
)
from seerdb.common.tns import (
    encode_batch_errors_status as encode_batch_errors_status,
)
from seerdb.common.tns import (
    encode_create_temp_response as encode_create_temp_response,
)
from seerdb.common.tns import (
    encode_describe as encode_describe,
)
from seerdb.common.tns import (
    encode_error as encode_error,
)
from seerdb.common.tns import (
    encode_fetch_terminator_oci as encode_fetch_terminator_oci,
)
from seerdb.common.tns import (
    encode_lob_read_response_thin as encode_lob_read_response_thin,
)
from seerdb.common.tns import (
    encode_lobops_ack as encode_lobops_ack,
)
from seerdb.common.tns import (
    encode_more_rows as encode_more_rows,
)
from seerdb.common.tns import (
    encode_out_bind_response_thin as encode_out_bind_response_thin,
)
from seerdb.common.tns import (
    encode_rows as encode_rows,
)
from seerdb.common.tns import (
    encode_scroll_open_response as encode_scroll_open_response,
)
from seerdb.common.tns import (
    encode_scroll_response as encode_scroll_response,
)
from seerdb.common.tns import (
    encode_status as encode_status,
)
from seerdb.common.tns import (
    encode_version_banner_oci as encode_version_banner_oci,
)
from seerdb.common.tns import (
    is_reexecute_oci as is_reexecute_oci,
)
from seerdb.common.tns import (
    is_version_call_oci as is_version_call_oci,
)
from seerdb.common.tns import (
    mint_temp_lob_locator as mint_temp_lob_locator,
)
from seerdb.common.tns import (
    parse_exec as parse_exec,
)
from seerdb.common.tns import (
    parse_fetch as parse_fetch,
)
from seerdb.common.tns import (
    parse_lobops_read as parse_lobops_read,
)
from seerdb.common.tns import (
    parse_lobops_request as parse_lobops_request,
)
from seerdb.common.tns import (
    peek_exec_cursor as peek_exec_cursor,
)
from seerdb.common.tns import (
    scroll_start_row as scroll_start_row,
)
from seerdb.common.tns import (
    strip_oci_piggyback as strip_oci_piggyback,
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
    TTI_FUN,
    TTI_RXD,
)

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
        if payload[ind_off : ind_off + 8] != oci.OCI_INDICATOR:
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
                # The OCI (sqlplus) bind path doesn't carry a national char form;
                # decode ordinary char (csfrm 1) — no test client binds NCHAR here.
                values.append(_decode_bind_value(data_type, _CSFRM_DB, raw))
        except (IndexError, DataError):
            continue
        if len(values) == bind_count:
            return values
    return []


def _oci_ub4(n: int) -> bytes:
    return int(n).to_bytes(4, 'little')


# The very first thing sqlplus / thick OCI sends after login is a version call
# (its TTC payload leads with 0x11 0x6b); the server answers with its banner, and
# sqlplus prints "Connected to: <banner>". The reply is a TTI_RPA carrying the
# banner as a DALC (ub2 count + ub1-chunked string) plus a fixed 10-byte packed
# version/flags trailer (#265).


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
# The column count sits one byte past the marker; the client reads it to know how
# many values to expect in each row, so it is load-bearing for a multi-column
# result (verified: 1/2/3 across live 1/2/3-column describes).
_OCI_DCB_NUMCOLS_OFF = 37
# The execute return status (an OCI OER, offsets 32:65 of the status trailer):
# call status + the return marker sqlplus needs to accept the row set. Reproduced
# as a unit — the row-count fields inside are constant for the single-row replies
# handled so far; generalising it is a follow-up.
_OCI_EXEC_OER_OFF = 32
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


def encode_oci_oer(
    status: int,
    *,
    sequence: int,
    row_kind: int = oci.OCI_OER_ROW_KIND_NONE,
    error_pos: int = 0,
    error_code: int = 0,
) -> bytes:
    """Build a 136-byte OCI OER return-status token (§36). ``status`` is
    SUCCESS (0x01) or ERROR (0x05); ``row_kind`` marks a LOB/LONG-row status;
    ``error_pos`` and ``error_code`` (ub4 LE at offset 12) carry an ORA error.
    ``sequence`` is the OER's per-context internal field (carried from the live
    capture; its echo at offset 49 is ``sequence + 2``). The caller appends the
    ``ORA-…`` message DALC for the error case."""
    oer = bytearray(_OCI_OER_ENVELOPE)
    oer[1] = status
    oer[5] = sequence
    oer[8] = row_kind
    oer[20] = error_pos
    oer[49] = sequence + 2
    struct.pack_into('<I', oer, 12, error_code)
    return bytes(oer)


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
    status = encode_oci_oer(
        oci.OCI_OER_STATUS_SUCCESS, sequence=0x11, row_kind=oci.OCI_OER_ROW_KIND_LONG
    )
    return bytes(out) + status


def encode_error_oci(ora_code: int, message: str) -> bytes:
    """OCI error reply — an OER carrying ORA-<code>: <message>, connection intact.

    The deadbeef-dialect counterpart of :func:`encode_error`: a failing statement
    surfaces in sqlplus as the ORA error and the session stays usable. The error
    status (0x05) and frame differ from the end-of-fetch OER — a real error, not
    "cursor drained" — so the two must not be conflated (#265, #350).
    """
    oer = encode_oci_oer(
        oci.OCI_OER_STATUS_ERROR, sequence=0x13, error_pos=0x0E, error_code=ora_code
    )
    text = f'ORA-{ora_code:05d}: {message}\n'.encode('utf-8')
    return oer + bytes([len(text)]) + text


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


def encode_status_oci() -> bytes:
    """OCI reply for a no-row statement (PL/SQL / DDL): success, nothing to fetch."""
    status = bytearray(_OCI_ROW_STATUS_LEN)
    status[0:3] = b'\x08\x06\x00'
    status[11] = 0x01
    off = _OCI_EXEC_OER_OFF
    status[off : off + len(_OCI_STATUS_OER)] = _OCI_STATUS_OER
    return bytes(status)


# OCI execute-status reply (#348/#349). sqlplus renders the completion message
# ("N rows updated.", "Table created.") from two fields of this frame: the V$SQL
# **command type** at body offset 57, and — for DML — the affected-row **count**
# (ub4 LE) at offset 43. The rest is the fixed execute-status frame around the
# embedded OER (SCN region, cursor/rowid trailer, the 0x20f6310a marker). Rather
# than store a body per verb, generate from those two fields; validated live —
# sqlplus prints the right verb and count for insert/update/delete/create/drop
# against the Mirror. The frames below are one live 11g INSERT / CREATE reply with
# the capture-order session counters (offsets 3, 75, 186 for DML; 3, 11 for DDL)
# zeroed, since the Mirror has no such per-statement sequence.
_OCI_DML_ROWCOUNT_OFF = 43
_OCI_CMD_TYPE_OFF = 57

# The Mirror's SQL-verb → V$SQL command-type mapping — response-generation policy
# over the shared oci.OCI_CMD_* vocabulary. sqlplus renders the completion message
# purely from the command type (docs/PROTOCOL.md §36).
_OCI_DML_CMD = {
    'INSERT': oci.OCI_CMD_INSERT,
    'UPDATE': oci.OCI_CMD_UPDATE,
    'DELETE': oci.OCI_CMD_DELETE,
}

# DDL / no-row statements, keyed by (verb, object). sqlplus prints e.g. "Index
# created.", "Table altered.", "View dropped." from the command type. Verbs with
# no object (GRANT/REVOKE) map on the verb alone. Verified live against sqlplus.
_OCI_DDL_COMMAND_TYPE = {
    ('CREATE', 'TABLE'): oci.OCI_CMD_CREATE_TABLE,
    ('CREATE', 'INDEX'): oci.OCI_CMD_CREATE_INDEX,
    ('CREATE', 'SEQUENCE'): oci.OCI_CMD_CREATE_SEQUENCE,
    ('CREATE', 'SYNONYM'): oci.OCI_CMD_CREATE_SYNONYM,
    ('CREATE', 'VIEW'): oci.OCI_CMD_CREATE_VIEW,
    ('ALTER', 'INDEX'): oci.OCI_CMD_ALTER_INDEX,
    ('ALTER', 'SEQUENCE'): oci.OCI_CMD_ALTER_SEQUENCE,
    ('ALTER', 'TABLE'): oci.OCI_CMD_ALTER_TABLE,
    ('DROP', 'INDEX'): oci.OCI_CMD_DROP_INDEX,
    ('DROP', 'TABLE'): oci.OCI_CMD_DROP_TABLE,
    ('DROP', 'SEQUENCE'): oci.OCI_CMD_DROP_SEQUENCE,
    ('DROP', 'SYNONYM'): oci.OCI_CMD_DROP_SYNONYM,
    ('DROP', 'VIEW'): oci.OCI_CMD_DROP_VIEW,
    ('LOCK', 'TABLE'): oci.OCI_CMD_LOCK_TABLE,
    ('TRUNCATE', 'TABLE'): oci.OCI_CMD_TRUNCATE_TABLE,
}
# Object-less verbs, and the object each bare verb falls back to.
_OCI_DDL_VERB_COMMAND_TYPE = {'GRANT': oci.OCI_CMD_GRANT, 'REVOKE': oci.OCI_CMD_REVOKE}
_OCI_DDL_VERB_DEFAULT_OBJECT = {
    'CREATE': 'TABLE',
    'ALTER': 'TABLE',
    'DROP': 'TABLE',
    'TRUNCATE': 'TABLE',
    'LOCK': 'TABLE',
}


def ddl_command_type(sql: str) -> int | None:
    """The V$SQL command type for a DDL / session statement, or None if it is not
    one the Mirror recognises (so it falls back to the generic no-row status).
    sqlplus turns this into the completion message ("Table created.", "Index
    dropped.", "Grant succeeded.", …)."""
    parts = sql.strip().upper().split()
    if not parts:
        return None
    verb = parts[0]
    if verb in _OCI_DDL_VERB_COMMAND_TYPE:
        return _OCI_DDL_VERB_COMMAND_TYPE[verb]
    if verb not in _OCI_DDL_VERB_DEFAULT_OBJECT:
        return None
    obj = parts[1] if len(parts) > 1 else _OCI_DDL_VERB_DEFAULT_OBJECT[verb]
    return _OCI_DDL_COMMAND_TYPE.get(
        (verb, obj), _OCI_DDL_COMMAND_TYPE[(verb, _OCI_DDL_VERB_DEFAULT_OBJECT[verb])]
    )


def encode_dml_status_oci(keyword: str, rowcount: int) -> bytes:
    """OCI reply for a DML — success carrying the affected-row count so sqlplus
    prints ``N rows created/updated/deleted``. ``keyword`` (INSERT/UPDATE/DELETE)
    selects the V$SQL command type; MERGE and anything else fall back to INSERT."""
    status = bytearray(_OCI_DML_STATUS_FRAME)
    status[_OCI_DML_ROWCOUNT_OFF : _OCI_DML_ROWCOUNT_OFF + 4] = rowcount.to_bytes(
        4, 'little'
    )
    status[_OCI_CMD_TYPE_OFF] = _OCI_DML_CMD.get(keyword, oci.OCI_CMD_INSERT)
    return bytes(status)


def encode_ddl_status_oci(command_type: int) -> bytes:
    """OCI reply for a DDL / no-row statement — success so sqlplus prints the
    matching message ("Table created.", "Index dropped.", "Table truncated.", …).
    ``command_type`` is the V$SQL command type (see :func:`ddl_command_type`);
    DDL affects no rows, so nothing but that field varies."""
    status = bytearray(_OCI_DDL_STATUS_FRAME)
    status[_OCI_CMD_TYPE_OFF] = command_type
    return bytes(status)


_OCI_OUTBIND_BINDCOUNT_OFF = 4
_OCI_OUTBIND_DEFINE_MARKER = 0x10
_OCI_OUTBIND_RETCODE = b'\x00\x00'


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
        encode_value(v, 0) + _OCI_OUTBIND_RETCODE for v in values
    )
    return bytes(header) + define_markers + rxd + _OCI_OUTBIND_TAIL


def encode_commit_status_oci() -> bytes:
    """OCI reply to a bare commit / rollback — a TTI_STA acknowledgement."""
    return _OCI_COMMIT_STATUS


def encode_logoff_status_oci() -> bytes:
    """OCI reply acknowledging a client logoff (TTI_LOGOFF)."""
    return _OCI_LOGOFF_STATUS


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


_OCI_LOB_ROW_SIZE_OFF = 97  # ub4 BE content byte size inside the row locator value
_OCI_LOB_TAIL_SIZE_OFF = 93  # ub4 BE byte size in the echoed locator
_OCI_LOB_TAIL_AMOUNT_OFF = 107  # ub4 LE amount read (characters for CLOB / bytes)


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


# --- Temp-LOB WRITE flow (the Mirror's server side, #412) --------------------
#
# A programmatic client writing a LOB too large for an inline bind does
# CREATE_TEMP (allocate a temp LOB) -> WRITE (stream bytes into it) -> bind the
# temp locator on execute. The Mirror mints a locator, accumulates the WRITE
# bytes, and resolves the bound locator to those bytes for the backend. The
# request layout mirrors docs/PROTOCOL.md §14.1/§14.2 (the client encoders in
# seerdb/common/tns.py); this is the inverse.


def _encode_oci_value(value: object, col: ColumnMeta) -> bytes:
    # A row value in the OCI dialect: a LOB column emits its locator (content comes
    # later over TTI_LOBOPS, #405); a LONG / LONG RAW column streams inline via the
    # chunked form (#407); everything else is the ordinary inline DALC value.
    if col.data_type in _OCI_LOB_TYPES:
        return encode_lob_locator_oci(value, col.data_type == TNS_TYPE_CLOB)
    if col.data_type in _OCI_LONG_TYPES:
        return encode_long_value_oci(value)
    return encode_value(value, col.data_type)


# The OER status that trails a LOB locator row on the fetch — NOT the 1403
# terminator: the LOB content still has to come over TTI_LOBOPS, so the cursor is
# not drained (a following fetch after the LOBOPS reads draws the terminator,
# #405). The same OER envelope as the LONG-row status, marked LOB (§36).
_OCI_LOB_FETCH_STATUS = encode_oci_oer(
    oci.OCI_OER_STATUS_SUCCESS, sequence=0x10, row_kind=oci.OCI_OER_ROW_KIND_LOB
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
