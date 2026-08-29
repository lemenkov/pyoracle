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
    _CSFRM_DB,
    _OCI_COMMIT_STATUS,
    _OCI_DCB_MARKER,
    _OCI_DDL_STATUS_FRAME,
    _OCI_DML_STATUS_FRAME,
    _OCI_EXEC_OER,
    _OCI_FETCH_CONST,
    _OCI_FETCH_OER_HEADER,
    _OCI_LOB_DESCRIBE_STATUS,
    _OCI_LOB_DESCRIBE_TAIL,
    _OCI_LOB_READ_TAIL,
    _OCI_LOB_ROW_VALUE,
    _OCI_LOGOFF_STATUS,
    _OCI_OER_ENVELOPE,
    _OCI_OUTBIND_HEADER,
    _OCI_OUTBIND_TAIL,
    _OCI_STATUS_OER,
    _OCI_VERSION_TRAILER,
    ColumnMeta,
    ExecRequest,
    FetchRequest,
    LobOpsRequest,
    RefCursorOutBind,
    ScalarOutBind,
    TempLobRef,
    _encode_describe_body,
    _encode_oer,
    decode_dalc,
    decode_oac_fields,
    decode_ub4,
    encode_describe,
    encode_rows,
    encode_sb4,
    encode_status,
    encode_value,
)
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    TNS_BIND_DIR_OUTPUT,
    TNS_EXEC_FLAGS_SCROLLABLE,
    TNS_FETCH_ORIENTATION_FIRST,
    TNS_FETCH_ORIENTATION_LAST,
    TNS_LOB_OP_CLOSE,
    TNS_LOB_OP_FREE_TEMP,
    TNS_LOB_OP_GET_CHUNK_SIZE,
    TNS_LOB_OP_OPEN,
    TNS_LOB_OP_TRIM,
    TNS_LOB_OP_WRITE,
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
    TTI_IOV,
    TTI_LOB,
    TTI_RPA,
    TTI_RXD,
)
from seerdb.common.types import decode_value

# The 11g tail between the fixed header and the SQL: a [0, 0, 1] marker and a
# 5-byte server-version slot (empty only when the client thinks it is talking to
# 10g; an 11g-pinned Mirror always gets the 5-byte form).
_MARKER_LEN = 3
_SERVER_VERSION_SLOT = 5


# The autocommit bit in the OALL8 options word: the client sets it (0x100) when
# the connection is in autocommit mode, asking the server to commit after this
# statement (set_opts encodes it as Param * 256 into the options word).
_EXEC_OPTION_COMMIT = 0x100
# The array-DML batcherrors bit (0x80000): the client sets it to ask the server
# to apply the good rows and collect per-row failures rather than aborting (#18).
_EXEC_OPTION_BATCH_ERRORS = 0x80000


# The LOB-descriptor prefix a temp-LOB locator bind carries (shared with the
# native VECTOR / JSON binds): 01 28 28 then a ub2 locator length + locator.
_TEMP_LOB_BIND_PREFIX = b'\x01\x28\x28'


def _read_bind_value(data_type: int, csfrm: int, after: bytes) -> tuple[object, bytes]:
    # One RXD bind value and the bytes past it. A CLOB / BLOB bind is a temp-LOB
    # descriptor (#412), not a plain DALC: 01 28 28 | ub2 loclen | locator, with
    # no outer length — the server reads it by type (the descriptor's leading
    # 0x01 would otherwise be mistaken for a DALC length). Everything else is the
    # ordinary DALC value decoded by its OAC type and charset form.
    if (
        data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB)
        and after[:3] == _TEMP_LOB_BIND_PREFIX
    ):
        loclen = (after[3] << 8) | after[4]
        locator = after[5 : 5 + loclen]
        # Kept as a reference; the session swaps in the bytes streamed over
        # TTI_LOBOPS WRITE (the backend never sees a locator, only the value).
        return TempLobRef(locator, data_type == TNS_TYPE_BLOB), after[5 + loclen :]
    raw, after = decode_dalc(after)
    return _decode_bind_value(data_type, csfrm, raw), after


def _decode_bind_value(data_type: int, csfrm: int, raw: bytes | list) -> object:
    # A bind value from the RXD, decoded by its OAC type. An empty/NULL DALC
    # (reported as a list by decode_dalc) is None. csfrm selects the char
    # encoding: 2 (national) decodes an NCHAR / NVARCHAR value as UTF-16BE, 1
    # (ordinary) as AL32UTF8 — decode_value keys on it via _string_charset (#484).
    if isinstance(raw, list) or not raw:
        return None
    raw = bytes(raw)
    column = {
        'data_type': data_type,
        'data_length': 0,
        'precision': 0,
        'data_scale': 0,
        'charset': AL32UTF8_CHARSET,
        'csfrm': csfrm or _CSFRM_DB,
    }
    return decode_value(column, bytes(raw))


def peek_exec_cursor(payload: bytes) -> tuple[int, bool]:
    """The cursor id and whether SQL is present, read from an OALL8 header without
    a full parse (#80/#486). A cached re-execute (cursor set, no SQL) carries no
    OACs, so the session uses this to supply the remembered bind types to
    :func:`parse_exec`. Returns ``(0, True)`` for anything that isn't an OALL8."""
    if len(payload) < 3 or payload[0] != TTI_FUN or payload[1] != TTI_ALL8:
        return (0, True)
    rest = payload[3:]
    _options, rest = decode_ub4(rest)
    cursor, rest = decode_ub4(rest)
    query_flag = rest[0] if rest else 0
    return (cursor, bool(query_flag))


def parse_exec(payload: bytes, bind_types: list | None = None) -> ExecRequest:
    """Parse an OALL8 execute payload (the TTC message from ``read_packet``).

    Extracts the SQL text and any bind values (positional, decoded by their OAC
    type). Raises :class:`InterfaceError` if the message is not a TTI_ALL8
    execute.

    A cached-cursor re-execute (#80/#486) carries the bind values but **no** OAC
    descriptors — the server is expected to remember the bind format from the
    first parse. Pass the remembered ``bind_types`` (the ``(data_type, csfrm,
    max_size)`` list from that first parse, exposed as ``ExecRequest.bind_types``)
    so the RXD values decode without re-reading OACs.
    """
    if len(payload) < 3 or payload[0] != TTI_FUN or payload[1] != TTI_ALL8:
        raise InterfaceError('not an OALL8 execute')

    rest = payload[3:]  # skip TTI_FUN, TTI_ALL8, seq
    options, rest = decode_ub4(rest)
    autocommit = bool(options & _EXEC_OPTION_COMMIT)
    batcherrors = bool(options & _EXEC_OPTION_BATCH_ERRORS)
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

    # The al8i4 option array follows the SQL text; decode all `all8_len` sb4
    # elements so `after` lands on the OAC/RXD tokens and the scroll request
    # (al8i4[9] exec flags, [10] orientation, [11] position) is available. A
    # scroll re-execute carries no binds, so this must run unconditionally, not
    # only in the bind path (#181/#485).
    after = rest[query_len:]
    al8: list[int] = []
    for _ in range(all8_len):
        al8_elem, after = decode_ub4(after)
        al8.append(al8_elem)
    scrollable = len(al8) > 9 and bool(al8[9] & TNS_EXEC_FLAGS_SCROLLABLE)
    scroll_orientation = al8[10] if len(al8) > 10 else 0
    scroll_position = al8[11] if len(al8) > 11 else 0

    binds: list = []
    bind_rows: list = []
    bind_meta: list = []
    if bind_count > 0:
        # After the al8 array (already consumed above): one OAC (type descriptor)
        # per bind column, then one RXD row of values per array-DML iteration
        # (an ordinary single execute is just one row). A cached re-execute omits
        # the OACs, so `after` already sits on the first RXD — use the remembered
        # bind types instead of decoding OACs (#80/#486).
        if bind_types is not None:
            types = list(bind_types)
        else:
            types = []
            for _ in range(bind_count):
                (
                    data_type,
                    maxlen,
                    _scale,
                    _charset,
                    csfrm,
                    after,
                ) = decode_oac_fields(after)
                if data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
                    # A thin CLOB / BLOB bind is the temp-LOB locator form (#412),
                    # whose OAC appends a trailing oaccolid field the shared
                    # decoder stops short of — swallow it so the next OAC aligns.
                    after = after[1:]
                # csfrm distinguishes an NCHAR / NVARCHAR bind (2 → UTF-16BE) from
                # an ordinary char bind (1); maxlen is the OUT return-buffer size a
                # PL/SQL OUT bind needs (#483/#484). Both ride alongside the type.
                types.append((data_type, csfrm, maxlen))
        # Each row is a TTI_RXD token followed by one value per bind column; loop
        # until the rows run out (executemany sends N, a plain execute sends 1).
        while after and after[0] == TTI_RXD:
            after = after[1:]
            row = []
            for data_type, csfrm, _maxlen in types:
                value, after = _read_bind_value(data_type, csfrm, after)
                row.append(value)
            bind_rows.append(row)
        if bind_rows:
            binds = bind_rows[0]
        # Per-bind (tns_type, max_size) — what a PL/SQL block's OUT binds need to
        # be registered on the backend with a correctly-sized buffer (#483).
        bind_meta = [(data_type, maxlen) for data_type, _csfrm, maxlen in types]
        bind_type_list = list(types)
    else:
        bind_type_list = []

    return ExecRequest(
        sql=sql,
        cursor=cursor,
        bind_count=bind_count,
        fetch=fetch,
        binds=binds,
        bind_rows=bind_rows,
        bind_meta=bind_meta,
        bind_types=bind_type_list,
        autocommit=autocommit,
        batcherrors=batcherrors,
        scrollable=scrollable,
        scroll_orientation=scroll_orientation,
        scroll_position=scroll_position,
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


def is_reexecute_oci(payload: bytes) -> bool:
    """True if an OCI OALL8 is a re-execute of an already-described cursor — it
    carries no SQL (the SQL pointer at offset 11 is absent). sqlplus issues one
    to pull a LONG / LONG RAW row after setting up its streaming define, so the
    Mirror answers it with the row it parked on the describe (#407)."""
    return (
        len(payload) > _OCI_ALL8_IND_OFF + 8
        and payload[0] == TTI_FUN
        and payload[1] == TTI_ALL8
        and payload[_OCI_ALL8_IND_OFF : _OCI_ALL8_IND_OFF + 8] != oci.OCI_INDICATOR
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


def _oci_ub4(n: int) -> bytes:
    return int(n).to_bytes(4, 'little')


# The very first thing sqlplus / thick OCI sends after login is a version call
# (its TTC payload leads with 0x11 0x6b); the server answers with its banner, and
# sqlplus prints "Connected to: <banner>". The reply is a TTI_RPA carrying the
# banner as a DALC (ub2 count + ub1-chunked string) plus a fixed 10-byte packed
# version/flags trailer (#265).


def is_version_call_oci(payload: bytes) -> bool:
    """True if this is the sqlplus / thick-OCI post-login version request."""
    return payload[:2] == oci.OCI_VERSION_CALL


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


# The OCI end-of-fetch terminator sqlplus reads after the execute's rows: an OER
# carrying ORA-01403 ("no data found"), which the client treats as "cursor
# drained" rather than an error (the thin path keeps the same thing as its
# captured _END_OF_FETCH). Reduced to structure by live bisection (#265): a
# 24-byte OER header (call status + the 1403 code) and one instance constant,
# the rest zero, then the message computed.
_OCI_FETCH_OER_LEN = 136
_OCI_FETCH_CONST_OFF = 73
_OCI_END_OF_FETCH_MSG = b'ORA-01403: no data found\n'


def encode_fetch_terminator_oci() -> bytes:
    """The sqlplus / thick-OCI end-of-fetch reply (ORA-01403 = cursor drained)."""
    oer = bytearray(_OCI_FETCH_OER_LEN)
    oer[0 : len(_OCI_FETCH_OER_HEADER)] = _OCI_FETCH_OER_HEADER
    off = _OCI_FETCH_CONST_OFF
    oer[off : off + len(_OCI_FETCH_CONST)] = _OCI_FETCH_CONST
    return bytes(oer) + bytes([len(_OCI_END_OF_FETCH_MSG)]) + _OCI_END_OF_FETCH_MSG


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


def encode_lob_read_response_thin(content: bytes) -> bytes:
    """The thin TTI_LOBOPS READ reply (#413): the whole LOB content as LOB_DATA
    then a success OER (the client reads the content, skips to the OER, and stops).
    ``content`` is UTF-16BE for a CLOB, raw for a BLOB."""
    return _oci_lob_data(content) + _encode_oer(1, 0, 0, b'')


# --- Temp-LOB WRITE flow (the Mirror's server side, #412) --------------------
#
# A programmatic client writing a LOB too large for an inline bind does
# CREATE_TEMP (allocate a temp LOB) -> WRITE (stream bytes into it) -> bind the
# temp locator on execute. The Mirror mints a locator, accumulates the WRITE
# bytes, and resolves the bound locator to those bytes for the backend. The
# request layout mirrors docs/PROTOCOL.md §14.1/§14.2 (the client encoders in
# seerdb/common/tns.py); this is the inverse.


# CREATE_TEMP sends a fixed field block (no source locator), captured from the
# thin client: it opens 01 01 28 and CLOB / BLOB differ only in the LOB type byte
# (0x70 / 0x71). That opener is unmistakable against the WRITE / READ layout,
# whose second field is a locator length (~40-86), never 0x01.
_CREATE_TEMP_PREFIX = b'\x01\x01\x28'
_TEMP_LOB_LOCATOR_PREFIX = b'\x00seerdb-mirror-temp-lob-'


def mint_temp_lob_locator(index: int, is_blob: bool) -> bytes:
    """A unique opaque locator for the ``index``-th temp LOB of a session (#412).

    The value is echoed back verbatim on WRITE and on the bind, so it only has to
    be stable and distinct per temp LOB — the Mirror keys its buffer on it."""
    return (
        _TEMP_LOB_LOCATOR_PREFIX
        + struct.pack('>I', index)
        + (b'\x01' if is_blob else b'\x00')
    )


def _decode_lobops_chunked(data: bytes) -> bytes:
    # The WRITE payload after the 0x0E marker: a single <ub1 len><bytes> when the
    # data is <= 0xFC bytes, else a 0xFE marker then <sb4 len><chunk> repeated
    # until a zero-length terminator (§14.2). Inverse of the client encoder.
    if not data:
        return b''
    if data[0] != 0xFE:
        return data[1 : 1 + data[0]]
    rest = data[1:]
    out = bytearray()
    while rest:
        chunk_len, rest = decode_ub4(rest)
        if chunk_len == 0:
            break
        out += rest[:chunk_len]
        rest = rest[chunk_len:]
    return bytes(out)


# The opcodes the Mirror acknowledges with a content-free RPA+OER but does not
# yet act on (#417): OPEN / CLOSE bracket a write, TRIM truncates. Recognising
# them (instead of mis-routing to the READ path) is what keeps a programmatic
# client from desyncing. FREE_TEMP is handled apart (it drops the temp buffer).
# The value-returning form of GET_CHUNK_SIZE / TRIM is a #421 follow-up.
_LOBOPS_ACK_OPS = frozenset(
    {TNS_LOB_OP_OPEN, TNS_LOB_OP_CLOSE, TNS_LOB_OP_TRIM, TNS_LOB_OP_GET_CHUNK_SIZE}
)


def _lobops_locator_after_operation(rest: bytes) -> bytes:
    # From just past the operation code, walk the shared §14.1 tail to the
    # ub2-length-prefixed locator (WRITE / FREE_TEMP / OPEN / CLOSE / TRIM /
    # GET_CHUNK_SIZE all carry it identically; only what follows differs).
    rest = rest[2:]  # scn-array pointer + length
    _src_offset, rest = decode_ub4(rest)
    _dest_offset, rest = decode_ub4(rest)
    rest = rest[1:]  # amount pointer flag
    rest = rest[6:]  # three reserved ub2 array-LOB slots
    loc_len = struct.unpack('>H', rest[:2])[0]
    return rest[2 : 2 + loc_len]


def parse_lobops_request(body: bytes) -> LobOpsRequest:
    """Classify a TTI_LOBOPS message (``body`` from ``read_packet``).

    CREATE_TEMP / WRITE drive the temp-LOB write flow (#412); FREE_TEMP releases a
    temp LOB and the OPEN / CLOSE / TRIM / GET_CHUNK_SIZE state ops are
    acknowledged (#417); anything else (a READ of an emitted column locator) is
    served by the #413 read path."""
    payload = body[3:]  # skip TTI_FUN, TTI_LOBOPS, seq
    if payload[:3] == _CREATE_TEMP_PREFIX:
        # CLOB vs BLOB is the LOB type byte (0x70 / 0x71) in the fixed block.
        return LobOpsRequest(kind='create_temp', is_blob=0x71 in payload)
    # The common request layout (§14.1); walk the fields to the operation, then to
    # the ub2-prefixed locator (and, for a WRITE, the 0x0E payload).
    rest = payload[1:]  # source_pointer_flag
    _loc_len_plus2, rest = decode_ub4(rest)
    rest = rest[1:]  # dest_pointer_flag
    _dest_length, rest = decode_ub4(rest)
    _short_src_off, rest = decode_ub4(rest)
    _short_dst_off, rest = decode_ub4(rest)
    rest = rest[3:]  # charset / short-amount / null-lob pointer flags
    operation, rest = decode_ub4(rest)
    if operation == TNS_LOB_OP_WRITE:
        rest = rest[2:]  # scn-array pointer + length
        _src_offset, rest = decode_ub4(rest)
        _dest_offset, rest = decode_ub4(rest)
        rest = rest[1:]  # amount pointer flag
        rest = rest[6:]  # three reserved ub2 array-LOB slots
        loc_len = struct.unpack('>H', rest[:2])[0]
        rest = rest[2:]
        locator = rest[:loc_len]
        rest = rest[loc_len:]
        if rest and rest[0] == 0x0E:
            rest = rest[1:]
        return LobOpsRequest(
            kind='write', locator=locator, payload=_decode_lobops_chunked(rest)
        )
    if operation == TNS_LOB_OP_FREE_TEMP:
        return LobOpsRequest(
            kind='free_temp', locator=_lobops_locator_after_operation(rest)
        )
    if operation in _LOBOPS_ACK_OPS:
        return LobOpsRequest(kind='ack', locator=_lobops_locator_after_operation(rest))
    # READ (the #413 column-LOB read) and anything else fall through to the read
    # path — unchanged, so an unrecognised op behaves as before rather than worse.
    return LobOpsRequest(kind='read')


def encode_create_temp_response(locator: bytes) -> bytes:
    """The CREATE_TEMP reply (#412): a bare TTI_RPA carrying the minted locator —
    0x08, ub2 length, then the locator bytes (what the client reads back)."""
    return bytes([TTI_RPA]) + struct.pack('>H', len(locator)) + locator


def encode_lobops_ack(locator: bytes) -> bytes:
    """A content-free TTI_LOBOPS reply: a TTI_RPA echoing the (ub2-prefixed)
    locator then a success OER. The client skips the locator via its length prefix
    and walks to the OER (``decode_lobops_oer``), so no real content is carried.
    Used for WRITE (#412) and for the FREE_TEMP / OPEN / CLOSE / TRIM /
    GET_CHUNK_SIZE state ops the Mirror acknowledges (#417)."""
    rpa = bytes([TTI_RPA]) + struct.pack('>H', len(locator)) + locator
    return rpa + _encode_oer(1, 0, 0, b'')


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


def _encode_refcursor_out(bind: RefCursorOutBind) -> bytes:
    # A REF CURSOR OUT value in the IOV's RXD (#483/#84), the inverse of the
    # client's _read_refcursor_out: a 1-byte length, the inline describe body
    # (the same per-column DCB metadata a describe carries), the nested cursor
    # id, and a 1-byte present indicator.
    return (
        bytes([1])  # length prefix (skipped by the client)
        + _encode_describe_body(bind.columns)
        + encode_sb4(bind.cursor_id)
        + bytes([1])  # per-value present indicator
    )


def encode_out_bind_response_thin(
    out_binds: list[ScalarOutBind | RefCursorOutBind],
) -> bytes:
    """The thin reply returning a PL/SQL block's OUT bind values (#483): a
    TTI_IOV vector + a TTI_RXD row of the values + a success OER.

    ``out_binds`` is one entry per bind, in bind order — the Mirror can't tell IN
    from OUT (the wire has no direction), so it marks them all OUT and returns
    each value; the client keeps only the positions it bound as a ``Var``
    (``_assign_out_binds``). A scalar rides as a DALC + ub4 return code; a REF
    CURSOR rides as its inline describe + cursor id. The IOV header mirrors what
    ``_read_iov`` decodes: a flag, the bind count (num_requests + num_iters*256),
    the zeroed iter / buffer / bit-vector / rowid fields, then a direction byte
    per bind."""
    count = len(out_binds)
    num_requests, num_iters = count % 256, count // 256
    iov = (
        bytes([TTI_IOV, 0])  # token + flag
        + encode_sb4(num_requests)
        + encode_sb4(num_iters)
        + encode_sb4(1)  # num iters this time
        + encode_sb4(0)  # uac buffer length
        + encode_sb4(0)  # fast-fetch bit vector length
        + encode_sb4(0)  # rowid length
        + bytes([TNS_BIND_DIR_OUTPUT]) * count  # direction per bind
    )
    rxd = bytearray([TTI_RXD])
    for bind in out_binds:
        if isinstance(bind, RefCursorOutBind):
            rxd += _encode_refcursor_out(bind)
        else:
            rxd += encode_value(bind.value, bind.tns_type) + encode_sb4(0)
    return iov + bytes(rxd) + encode_status(0)


def scroll_start_row(orientation: int, position: int, total: int) -> int:
    """The 1-based absolute row a scroll re-execute positions on (#181/#485).

    FIRST -> row 1, LAST -> the final row. For ABSOLUTE / RELATIVE / CURRENT /
    NEXT the client resolves the request to an absolute target itself and sends
    it as ``position`` (oracledb thin's ``_post_process_scroll``), so the Mirror
    takes it verbatim. A result yields 0 (an off-the-end position) when empty.
    """
    if orientation == TNS_FETCH_ORIENTATION_FIRST:
        return 1
    if orientation == TNS_FETCH_ORIENTATION_LAST:
        return total
    return position


def _scroll_terminator(cursor_id: int, server_rowcount: int, eof: bool) -> bytes:
    # The OER that ends a scroll batch (#181/#485). It carries the cumulative
    # row number (the absolute 1-based position of the last row delivered) in the
    # rowcount field — the client reads it as ``server_rowcount`` to place its
    # buffer window — and reports ORA-01403 once the batch reaches the end so the
    # client stops pulling. The cursor id ties the opening execute's response to
    # the kept-open scrollable cursor; a re-execute carries no id (0).
    if eof:
        return _encode_oer(0, 1403, server_rowcount, b'', cursor_id=cursor_id)
    return _encode_oer(1, 0, server_rowcount, b'', cursor_id=cursor_id)


def encode_scroll_open_response(
    columns: list[ColumnMeta],
    rows: list[tuple],
    cursor_id: int,
    *,
    server_rowcount: int,
    eof: bool,
) -> bytes:
    """A scrollable open reply (#181/#485): describe + the prefetched first batch
    + a scroll terminator carrying the cursor id and cumulative row number. The
    cursor stays open (the client drives later scroll re-executes against it)."""
    return (
        encode_describe(columns)
        + encode_rows(rows, columns)
        + _scroll_terminator(cursor_id, server_rowcount, eof)
    )


def encode_scroll_response(
    columns: list[ColumnMeta],
    rows: list[tuple],
    *,
    server_rowcount: int,
    eof: bool,
) -> bytes:
    """A scroll re-execute reply (#181/#485): the repositioned batch + terminator,
    with **no** describe (the metadata was established on the open). An empty
    batch (scrolled off the end) is a bare ``ORA-01403`` terminator."""
    return encode_rows(rows, columns) + _scroll_terminator(0, server_rowcount, eof)


def parse_fetch(payload: bytes) -> FetchRequest:
    """Parse a ``TTI_FETCH`` message: ``[TTI_FUN, TTI_FETCH, seq]`` + ub4 cursor
    id + ub4 row count (the inverse of ``encode_dictionary_fetch``)."""
    if len(payload) < 3 or payload[0] != TTI_FUN or payload[1] != TTI_FETCH:
        raise InterfaceError('not a TTI_FETCH')
    rest = payload[3:]  # skip TTI_FUN, TTI_FETCH, seq
    cursor, rest = decode_ub4(rest)
    fetch, _rest = decode_ub4(rest)
    return FetchRequest(cursor=cursor, fetch=fetch)
