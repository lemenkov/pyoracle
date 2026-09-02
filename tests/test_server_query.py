# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side query-path parsing."""

from __future__ import annotations

import pytest

from seerdb.common.exceptions import DataError, InterfaceError
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    ColumnMeta,
    _decode_describe_body,
    _skip_chunked_bytes,
    decode_packet,
    encode_describe,
    encode_rows,
    parse_exec,
    parse_exec_oci,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    TNS_TYPE_NUMBER,
    TNS_TYPE_VARCHAR,
    TTI_DCB,
    TTI_LOB,
    TTI_STA,
)


@pytest.fixture(autouse=True)
def _pin_field_versions():
    # These tests build and decode 11g-format responses. BOTH the encode and the
    # decode paths pick their wire format from a field-version ContextVar
    # (_ENCODE_FIELD_VERSION / _DECODE_FIELD_VERSION), which in production is
    # established at the top of each encode/decode operation. The tests call the
    # low-level encoders (encode_rows, encode_describe) directly, so they must
    # establish those themselves — otherwise a version left behind by an earlier
    # test (e.g. a 23ai encode) flips the chunk framing and the decode fails with
    # "truncated DALC field". Pin both to 11.2 per test and restore after, so this
    # module is immune to and free of cross-test field-version leakage.
    from seerdb.common.tns import _ENCODE_FIELD_VERSION

    enc = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    dec = _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    try:
        yield
    finally:
        _ENCODE_FIELD_VERSION.reset(enc)
        _DECODE_FIELD_VERSION.reset(dec)


def _decode_describe(payload: bytes) -> list[dict]:
    # Decode a describe block with the client's own 11g decoder.
    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    assert payload[0] == TTI_DCB
    columns, rest = _decode_describe_body(_skip_chunked_bytes(payload[1:]))
    assert rest == b'', 'describe did not consume cleanly'
    return columns


def _decode_response(response: bytes) -> tuple[list, list]:
    # Decode a full describe+rows+status response with the client's decoder.
    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    done, acc = decode_packet(response, (0, [], []))
    assert done
    return acc[1], acc[2]  # columns, rows


# A real 11g OALL8 execute for `select * from dual`, captured from seerdb 11.2
# through tools/capture_proxy.py (the TTC payload after the DATA prefix).
_DUAL_EXEC = bytes.fromhex(
    '035e070280210001011201010d000004ffffffff010f047fffffff00000000000000000000'
    '0001000000000073656c656374202a2066726f6d206475616c010100000000000001010000'
    '000000'
)


def test_parse_real_dual_exec() -> None:
    req = parse_exec(_DUAL_EXEC)
    assert req.sql == 'select * from dual'
    assert req.cursor == 0
    assert req.bind_count == 0
    assert req.fetch == 15


def test_non_exec_raises() -> None:
    with pytest.raises(InterfaceError):
        parse_exec(b'\x06\x00not an exec')


def test_describe_roundtrips_to_the_dual_column() -> None:
    # The DUMMY VARCHAR2(1) column of DUAL, encoded then decoded by the client.
    payload = encode_describe(
        [
            ColumnMeta(
                name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
            )
        ]
    )
    (col,) = _decode_describe(payload)
    assert col['column_name'] == b'DUMMY'
    assert col['data_type'] == TNS_TYPE_VARCHAR
    assert col['data_length'] == 1
    assert col['max_size'] == 1
    assert col['charset'] == 873
    assert col['null_ok'] == 1


def test_multiple_columns_and_not_null_roundtrip() -> None:
    payload = encode_describe(
        [
            ColumnMeta(
                name=b'ID',
                data_type=TNS_TYPE_NUMBER,
                data_length=22,
                max_size=22,
                null_ok=0,
            ),
            ColumnMeta(
                name=b'NAME', data_type=TNS_TYPE_VARCHAR, data_length=30, max_size=30
            ),
        ]
    )
    cols = _decode_describe(payload)
    assert [c['column_name'] for c in cols] == [b'ID', b'NAME']
    assert cols[0]['data_type'] == TNS_TYPE_NUMBER
    assert cols[0]['null_ok'] == 0  # NOT NULL
    assert cols[1]['max_size'] == 30


def test_describe_carries_number_precision_and_scale() -> None:
    # A NUMBER(p, s) column's precision/scale must survive the describe so the
    # client can surface them in cursor.description (fields 4 and 5).
    payload = encode_describe(
        [
            ColumnMeta(
                name=b'AMT',
                data_type=TNS_TYPE_NUMBER,
                data_length=22,
                max_size=22,
                precision=10,
                scale=2,
            )
        ]
    )
    col = _decode_describe(payload)[0]
    assert col['precision'] == 10
    assert col['data_scale'] == 2


def test_describe_carries_negative_scale() -> None:
    # A plain NUMBER (no declared scale) reports scale -127 on 11g, encoded as a
    # signed variable-length int (0x81 0x7f). The describe must survive it — a
    # real Oracle backend hits this on every unscaled NUMBER column.
    payload = encode_describe(
        [
            ColumnMeta(
                name=b'N',
                data_type=TNS_TYPE_NUMBER,
                data_length=22,
                max_size=22,
                precision=0,
                scale=-127,
            )
        ]
    )
    col = _decode_describe(payload)[0]
    assert col['data_scale'] == -127


def test_encode_rows_dual() -> None:
    col = ColumnMeta(
        name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
    )
    response = encode_describe([col]) + encode_rows([('X',)], [col]) + bytes([TTI_STA])
    columns, rows = _decode_response(response)
    assert [c['column_name'] for c in columns] == [b'DUMMY']
    assert rows == [['X']]


def test_encode_rows_multiple_with_null() -> None:
    cols = [
        ColumnMeta(name=b'A', data_type=TNS_TYPE_VARCHAR, data_length=5, max_size=5),
        ColumnMeta(name=b'B', data_type=TNS_TYPE_VARCHAR, data_length=5, max_size=5),
    ]
    response = (
        encode_describe(cols)
        + encode_rows([('hi', 'yo'), ('lo', None)], cols)
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [['hi', 'yo'], ['lo', None]]


def test_encode_rows_large_values_chunk() -> None:
    from seerdb.common.tns_consts import TNS_TYPE_RAW

    # A VARCHAR2 / RAW value over the single-byte length (253) must chunk in the
    # 11g form so the client decodes it — the regression that surfaced as
    # "truncated DALC field" past 253 bytes.
    big_str = 'x' * 1000
    big_raw = bytes(range(256)) * 4  # 1024 bytes
    cols = [
        ColumnMeta(
            name=b'S', data_type=TNS_TYPE_VARCHAR, data_length=4000, max_size=4000
        ),
        ColumnMeta(name=b'B', data_type=TNS_TYPE_RAW, data_length=2000, max_size=2000),
    ]
    response = (
        encode_describe(cols)
        + encode_rows([(big_str, big_raw)], cols)
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [[big_str, big_raw]]


def test_row_width_mismatch_raises() -> None:
    col = ColumnMeta(
        name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
    )
    with pytest.raises(InterfaceError):
        encode_rows([('X', 'extra')], [col])


def test_unsupported_value_type_raises() -> None:
    col = ColumnMeta(name=b'N', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)
    with pytest.raises(InterfaceError):
        encode_rows([(object(),)], [col])


def test_encode_error_reports_the_ora_code_and_message() -> None:
    from seerdb.common.tns import decode_token_oer, encode_error

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    result = decode_token_oer(
        encode_error(942, 'ORA-00942: table or view does not exist'), (0, [], [])
    )
    assert result[1] == 942  # ErrCode
    assert 'ORA-00942' in result[5]  # Message


def test_more_rows_terminator_carries_cursor_id() -> None:
    from seerdb.common.tns import decode_token_oer, encode_more_rows

    # The "more rows" status: call_status 1, no error, and the cursor id — what
    # the client's _drain_cursor keys on to issue follow-up TTI_FETCH calls.
    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    result = decode_token_oer(encode_more_rows(9), (0, [], []))
    assert result[0] == 1  # CallStatus
    assert result[1] == 0  # ErrCode (not 1403 — the cursor is not drained)
    assert result[2] == 9  # CursorId


def test_end_of_fetch_is_built_from_oer_fields() -> None:
    # _END_OF_FETCH is the ORA-01403 terminator, built by _encode_oer rather than
    # stored. It must stay byte-identical to the live 11g capture and decode as the
    # 1403 "no data found" status the client keys on to stop fetching.
    from seerdb.common.tns import _END_OF_FETCH, decode_token_oer

    assert (
        _END_OF_FETCH
        == bytes.fromhex(
            '0401010104010102057b00000101010e03000000000000000000000000070001010000000019'
        )
        + b'ORA-01403: no data found\n'
    )
    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    result = decode_token_oer(_END_OF_FETCH, (0, [], []))
    assert result[0] == 1  # CallStatus
    assert result[1] == 1403  # ErrCode — cursor drained


def test_parse_fetch_extracts_cursor_and_count() -> None:
    from seerdb.common.tns import encode_dictionary_fetch, parse_fetch

    msg = encode_dictionary_fetch(
        {'seq': 4, 'field_version': 6, 'cursor': 7, 'fetch': 50}
    )
    req = parse_fetch(msg)
    assert req.cursor == 7
    assert req.fetch == 50


def test_encode_rows_number_values() -> None:
    from decimal import Decimal

    col = ColumnMeta(name=b'N', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)
    response = (
        encode_describe([col])
        + encode_rows([(1,), (-7,), (0,), (3.14,), (1000000,)], [col])
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [[1], [-7], [0], [Decimal('3.14')], [1000000]]


def test_encode_rows_binary_float_and_double() -> None:
    from seerdb.common.tns_consts import TNS_TYPE_BDOUBLE, TNS_TYPE_BFLOAT

    # A BINARY_DOUBLE / BINARY_FLOAT column carries the IEEE-754 value (Python
    # float), not a base-100 NUMBER — the client decodes it back to float.
    dcol = ColumnMeta(name=b'D', data_type=TNS_TYPE_BDOUBLE, data_length=8, max_size=8)
    fcol = ColumnMeta(name=b'F', data_type=TNS_TYPE_BFLOAT, data_length=4, max_size=4)
    response = (
        encode_describe([dcol, fcol])
        + encode_rows([(3.5, 1.5), (-2.25, -0.5)], [dcol, fcol])
        + bytes([TTI_STA])
    )
    cols, rows = _decode_response(response)
    assert rows == [[3.5, 1.5], [-2.25, -0.5]]
    assert all(isinstance(v, float) for row in rows for v in row)


def test_encode_rows_high_precision_decimal() -> None:
    from decimal import Decimal

    # A NUMBER column carrying Decimals beyond float precision: the exact
    # base-100 encoder round-trips every significant digit.
    col = ColumnMeta(name=b'N', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)
    values = [
        Decimal('1.234567890123456789'),
        Decimal('-1.234567890123456789'),
        Decimal('123456789012345678901234567890'),
        Decimal('0.00000000000000000001'),
    ]
    response = (
        encode_describe([col])
        + encode_rows([(v,) for v in values], [col])
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [[v] for v in values]


def test_encode_rows_date_values() -> None:
    import datetime

    from seerdb.common.tns_consts import TNS_TYPE_DATE

    col = ColumnMeta(name=b'D', data_type=TNS_TYPE_DATE, data_length=7, max_size=7)
    response = (
        encode_describe([col])
        + encode_rows(
            [
                (datetime.datetime(2024, 1, 15, 13, 30, 45),),
                (datetime.date(2020, 12, 31),),
            ],
            [col],
        )
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [
        [datetime.datetime(2024, 1, 15, 13, 30, 45)],
        [datetime.datetime(2020, 12, 31, 0, 0)],
    ]


def test_encode_rows_timestamp_values() -> None:
    import datetime

    from seerdb.common.tns_consts import TNS_TYPE_TIMESTAMP

    # A TIMESTAMP column is fixed at 11 bytes and keeps the sub-second part; a
    # value with no microseconds still encodes 11 bytes (nanos == 0).
    col = ColumnMeta(
        name=b'TS', data_type=TNS_TYPE_TIMESTAMP, data_length=11, max_size=11
    )
    response = (
        encode_describe([col])
        + encode_rows(
            [
                (datetime.datetime(2024, 1, 15, 13, 30, 45, 123456),),
                (datetime.datetime(2020, 12, 31, 23, 59, 59),),
            ],
            [col],
        )
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [
        [datetime.datetime(2024, 1, 15, 13, 30, 45, 123456)],
        [datetime.datetime(2020, 12, 31, 23, 59, 59)],
    ]


def test_encode_rows_timestamptz_values() -> None:
    import datetime

    from seerdb.common.tns_consts import TNS_TYPE_TIMESTAMPTZ

    # A TIMESTAMPTZ column is 13 bytes and carries the UTC offset. A naive value
    # is assumed to be UTC (a bare wall-clock in a TZ column).
    col = ColumnMeta(
        name=b'TZ', data_type=TNS_TYPE_TIMESTAMPTZ, data_length=13, max_size=13
    )
    utc = datetime.timezone.utc
    plus2 = datetime.timezone(datetime.timedelta(hours=2))
    response = (
        encode_describe([col])
        + encode_rows(
            [
                (datetime.datetime(2024, 1, 15, 13, 30, 45, 123456, tzinfo=utc),),
                (datetime.datetime(2024, 6, 1, 9, 0, 0, tzinfo=plus2),),
                (datetime.datetime(2020, 12, 31, 23, 59, 59),),  # naive → UTC
            ],
            [col],
        )
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [
        [datetime.datetime(2024, 1, 15, 13, 30, 45, 123456, tzinfo=utc)],
        [datetime.datetime(2024, 6, 1, 9, 0, 0, tzinfo=plus2)],
        [datetime.datetime(2020, 12, 31, 23, 59, 59, tzinfo=utc)],
    ]


def test_parse_exec_extracts_bind_values() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    msg = encode_dictionary_exec(
        {
            'seq': 3,
            'field_version': 6,
            'query': {
                'type': 'select',
                'auto': 0,
                'fetch': 15,
                'server_version': 186647040,
                'cursor': 0,
                'query': 'select :1, :2 from dual',
                'bind': ['hi', 42],
                'batch': [],
                'def': [],
            },
        }
    )
    req = parse_exec(msg)
    assert req.sql == 'select :1, :2 from dual'
    assert req.bind_count == 2
    assert req.binds == ['hi', 42]


def test_parse_exec_reads_the_autocommit_flag() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    def dml(auto: int):
        return encode_dictionary_exec(
            {
                'seq': 3,
                'field_version': 6,
                'query': {
                    'type': 'change',  # DML — the options word carries autocommit
                    'auto': auto,
                    'fetch': 0,
                    'server_version': 186647040,
                    'cursor': 0,
                    'query': 'insert into t values (:1)',
                    'bind': ['x'],
                    'batch': [],
                    'def': [],
                },
            }
        )

    # The client sets the commit-on-success option (0x100) in autocommit mode.
    assert parse_exec(dml(1)).autocommit is True
    assert parse_exec(dml(0)).autocommit is False


def test_parse_exec_extracts_array_dml_rows() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    # executemany: the first row is `bind`, the rest ride in `batch`. parse_exec
    # must recover every iteration's values, in order.
    msg = encode_dictionary_exec(
        {
            'seq': 3,
            'field_version': 6,
            'query': {
                'type': 'change',
                'auto': 1,
                'fetch': 0,
                'server_version': 186647040,
                'cursor': 0,
                'query': 'insert into t values (:1, :2)',
                'bind': [1, 'a'],
                'batch': [[2, 'b'], [3, 'c']],
                'def': [],
            },
        }
    )
    req = parse_exec(msg)
    assert req.bind_rows == [[1, 'a'], [2, 'b'], [3, 'c']]
    assert req.binds == [1, 'a']  # first row remains the single-execute view


# A live sqlplus 11.2 OCI (deadbeef dialect) OALL8 execute — the user's typed
# query. Captured from sqlplus 11.2 <-> XE 11.2 (#265).
_OCI_EXEC_USER = bytes.fromhex(
    '035e156180000000000000feffffffffffffff3600000000000000feffffffffffffff'
    '0d00000000000000fefffffffffffffffeffffffffffffff0000000001000000000000'
    '0000000000000000000000000000000000000000000000000000000000feffffffffff'
    'ffff0000000000000000fefffffffffffffffefffffffffffffff83514260000000000'
    '00000000000000fefffffffffffffffeffffffffffffff000000000000000000000000'
    '00000000000000000000000000000000000000001273656c65637420312066726f6d20'
    '6475616c01000000000000000000000000000000000000000000000000000000010000'
    '000000000000000000000000000000000000000000'
)
# sqlplus's own internal query (SELECT USER FROM DUAL) — NUL-terminated, unlike
# the user's typed one; the parse must strip the trailing NUL.
_OCI_EXEC_INTERNAL = bytes.fromhex(
    '035e066180000000000000feffffffffffffff4200000000000000feffffffffffffff'
    '0d00000000000000fefffffffffffffffeffffffffffffff0000000001000000000000'
    '0000000000000000000000000000000000000000000000000000000000feffffffffff'
    'ffff0000000000000000fefffffffffffffffefffffffffffffff83514260000000000'
    '00000000000000fefffffffffffffffeffffffffffffff000000000000000000000000'
    '00000000000000000000000000000000000000001653454c4543542055534552204652'
    '4f4d204455414c00010000000000000000000000000000000000000000000000000000'
    '00010000000000000000000000000000000000000000000000'
)


def test_parse_exec_oci_extracts_the_user_query() -> None:
    req = parse_exec_oci(_OCI_EXEC_USER)
    assert req.sql == 'select 1 from dual'
    assert req.cursor == 0  # a new statement


def test_parse_exec_oci_strips_the_internal_query_nul() -> None:
    # sqlplus NUL-terminates SELECT USER FROM DUAL; the trailing NUL must not
    # reach the backend.
    req = parse_exec_oci(_OCI_EXEC_INTERNAL)
    assert req.sql == 'SELECT USER FROM DUAL'
    assert '\x00' not in req.sql


def test_parse_exec_oci_rejects_a_non_oci_message() -> None:
    with pytest.raises(InterfaceError):
        parse_exec_oci(b'\x03\x5e\x06not the oci shape' + b'\x00' * 200)


def test_encode_describe_oci_roundtrips_the_meaningful_fields() -> None:
    # The thin client can't parse the OCI describe, so round-trip through the
    # codec's own reader: every meaningful field survives (#265).
    from seerdb.common.tns import _decode_describe_oci, encode_describe_oci

    cols = [
        ColumnMeta(
            name=b'DUMMY',
            data_type=TNS_TYPE_VARCHAR,
            data_length=1,
            max_size=1,
            charset=873,
            csfrm=1,
        ),
        ColumnMeta(
            name=b'1',
            data_type=TNS_TYPE_NUMBER,
            data_length=2,
            max_size=22,
            precision=0,
            scale=-127,
        ),
    ]
    back = _decode_describe_oci(encode_describe_oci(cols))
    assert [c['name'] for c in back] == [b'DUMMY', b'1']
    assert back[0]['data_type'] == TNS_TYPE_VARCHAR
    assert back[0]['charset'] == 873
    assert back[1]['data_type'] == TNS_TYPE_NUMBER
    assert back[1]['scale'] == -127  # a NUMBER literal's floating scale


def test_encode_dcb_column_oci_reproduces_the_live_column_block() -> None:
    # The whole 63-byte per-column block, byte-for-byte against the real 11g
    # describe for `select 1 from dual` (the NUMBER '1' column). This is ground
    # truth from the wire, not a hand-derived fixture — an earlier hand-typed
    # fixture hid a one-byte field shift that a live sqlplus caught (#265).
    from seerdb.common.tns import _encode_dcb_column_oci

    captured = bytes.fromhex(
        '51010200008102000000000000000000000000000000000000000000000000'
        '0000000000000000000000010101000000013100000000000000000000000000'
    )
    mine = _encode_dcb_column_oci(
        ColumnMeta(
            name=b'1',
            data_type=TNS_TYPE_NUMBER,
            data_length=2,
            max_size=0,
            precision=0,
            scale=-127,
        ),
        position=1,
        first=True,
    )
    assert mine == captured


def test_encode_describe_oci_maxrowsize_is_nonzero() -> None:
    # The thick/OCI client allocates a row buffer of the DCB max-row-size; a zero
    # there overflows and segfaults sqlplus, so it must sum the column widths
    # (the thin client ignores the field) (#265).
    import struct

    from seerdb.common.tns import _OCI_DCB_PREAMBLE_LEN, encode_describe_oci

    col = ColumnMeta(name=b'1', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)
    payload = encode_describe_oci([col])
    off = 1 + 4 + _OCI_DCB_PREAMBLE_LEN  # token + preamble-len + preamble
    assert struct.unpack('<I', payload[off : off + 4])[0] == 22


def test_encode_version_banner_oci_matches_the_captured_reply() -> None:
    # The sqlplus / thick-OCI version reply (TTI_RPA + banner DALC + packed
    # version trailer), byte-for-byte against a live 11.2 capture (#265).
    from seerdb.common.tns import encode_version_banner_oci, is_version_call_oci

    banner = (
        b'Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production'
    )
    captured = bytes.fromhex(
        '084900494f7261636c65204461746162617365203131672045787072657373'
        '2045646974696f6e2052656c656173652031312e322e302e322e30202d2036'
        '346269742050726f64756374696f6e0002200b09010000000300'
    )
    assert encode_version_banner_oci(banner) == captured
    # and the request recogniser keys on the 0x11 0x6b lead
    assert is_version_call_oci(b'\x11\x6b\x04\x3b\x00') is True
    assert is_version_call_oci(b'\x03\x5e\x06') is False


def test_encode_query_response_oci_structure() -> None:
    # The OCI execute response: describe + DCB tail + RXD row + status, computed
    # (not a captured blob). Renders live in sqlplus 11.2 (validated by replay
    # substitution); here we check the structure holds together offline (#265).
    from seerdb.common.tns import _decode_describe_oci, encode_query_response_oci

    col = ColumnMeta(
        name=b'1', data_type=TNS_TYPE_NUMBER, data_length=2, max_size=0, scale=-127
    )
    resp = encode_query_response_oci([col], [(1,)])
    assert _decode_describe_oci(resp)[0]['name'] == b'1'  # describe decodes back
    assert b'\x07\x02\xc1\x02' in resp  # the RXD row: NUMBER 1 = c1 02


def test_oci_trailers_are_computed_mostly_zero() -> None:
    # The two trailers are computed as mostly-zero with a few load-bearing
    # structural constants — not replayed capture bytes (#265).
    from seerdb.common.tns import _oci_dcb_tail, _oci_row_status

    tail = _oci_dcb_tail(1)
    status = _oci_row_status()
    assert len(tail) == 83 and tail.count(0) > 70
    assert len(status) == 171 and status.count(0) > 120


def test_encode_fetch_terminator_oci_signals_end_of_fetch() -> None:
    # The OCI end-of-fetch reply: an OER carrying ORA-01403, which sqlplus reads
    # as "cursor drained". Computed (mostly-zero OER + the message), not a blob;
    # renders live when the execute already returned the rows (#265).
    from seerdb.common.tns import encode_fetch_terminator_oci

    term = encode_fetch_terminator_oci()
    assert len(term) == 162
    assert term[0] == 0x04  # OER token
    assert term.endswith(b'ORA-01403: no data found\n')


def test_strip_oci_piggyback_unwraps_the_execute() -> None:
    # sqlplus wraps every statement past the first in an OCCA close-cursors
    # piggyback (0x11 0x69 + fixed prefix + cursor entries), then the execute.
    from seerdb.common.tns import strip_oci_piggyback

    # a real 1169 prefix (count=1 -> 23-byte header) + a stub execute
    wrapped = (
        bytes.fromhex('116908feffffffffffffff010000000000000002000000')
        + b'\x03\x5e\x06rest'
    )
    assert strip_oci_piggyback(wrapped) == b'\x03\x5e\x06rest'
    # a bare execute (no piggyback) is returned unchanged
    assert strip_oci_piggyback(b'\x03\x5e\x06bare') == b'\x03\x5e\x06bare'


def test_encode_status_oci_and_commit_shapes() -> None:
    # The no-row reply (PL/SQL / DDL) is the 0x08 0x06 status; commit is a small
    # TTI_STA acknowledgement (#265).
    from seerdb.common.tns import encode_commit_status_oci, encode_status_oci

    status = encode_status_oci()
    assert status[:3] == b'\x08\x06\x00' and len(status) == 171
    assert encode_commit_status_oci()[0] == 0x09  # TTI_STA


def test_encode_long_value_oci_matches_the_captured_wire() -> None:
    # A LONG value streams inline as 0xFE-chunked bytes + a zero trailing ub4,
    # reproduced byte-for-byte from a live 11g LONG SELECT (#407).
    from seerdb.common.tns import encode_long_value_oci

    got = encode_long_value_oci('LONG-value-inline-0123456789-abcdefghij')
    assert got == bytes.fromhex(
        'fe274c4f4e472d76616c75652d696e6c696e652d3031323334353637383'
        '92d6162636465666768696a0000000000'
    )
    # NULL is an empty value still followed by the trailing indicator.
    assert encode_long_value_oci(None) == b'\x00\x00\x00\x00\x00'
    # LONG RAW carries raw bytes; a value over one chunk (0xFC) splits.
    big = bytes(range(256)) * 2  # 512 bytes -> chunks 0xFC, 0xFC, 0x08
    raw = encode_long_value_oci(big)
    assert raw[0] == 0xFE and raw[-4:] == b'\x00\x00\x00\x00'
    assert raw[1] == 0xFC  # first chunk length
    # The chunks reassemble to the original content.
    body, pos, acc = raw[1:], 0, bytearray()
    while body[pos] != 0:
        length = body[pos]
        acc += body[pos + 1 : pos + 1 + length]
        pos += 1 + length
    assert bytes(acc) == big


def test_encode_describe_oci_long_column_is_streamed() -> None:
    # A LONG column describes as a character type (charset + 0x80 flag) with its
    # sizes zero — the value is streamed inline, not fixed-width (#407).
    from seerdb.common.tns import ColumnMeta, encode_describe_oci
    from seerdb.common.tns_consts import TNS_TYPE_LONG, TNS_TYPE_LONGRAW

    long_col = ColumnMeta(name=b'V', data_type=TNS_TYPE_LONG, data_length=0, max_size=0)
    body = encode_describe_oci([long_col])
    col = body[36:]  # column block, after preamble + max-row-size + column count
    assert col[2] == TNS_TYPE_LONG and col[3] == 0x80  # char flag
    assert int.from_bytes(col[34:38], 'little') == 0  # max size zeroed
    # A LONG contributes nothing to the max-row-size (offset 28, ub4 LE).
    assert int.from_bytes(body[28:32], 'little') == 0
    # LONG RAW is binary — no char flag.
    raw_col = ColumnMeta(
        name=b'R', data_type=TNS_TYPE_LONGRAW, data_length=0, max_size=0
    )
    assert encode_describe_oci([raw_col])[36:][3] == 0x00


def test_is_reexecute_oci_detects_the_sql_less_reexecute() -> None:
    # A fresh OCI execute carries the SQL pointer indicator at offset 11; a
    # re-execute (the LONG fetch step) omits it (#407).
    from seerdb.common.oci import OCI_INDICATOR
    from seerdb.common.tns import is_reexecute_oci

    fresh = bytes([0x03, 0x5E, 0x01]) + b'\x00' * 8 + OCI_INDICATOR + b'\x00' * 240
    reexec = bytes([0x03, 0x5E, 0x01]) + b'\x00' * 8 + b'\x00' * 8 + b'\x00' * 240
    assert is_reexecute_oci(reexec) is True
    assert is_reexecute_oci(fresh) is False


def test_long_row_replies_carry_the_right_status() -> None:
    # The re-execute reply ends with the execute row-status (0x08 0x06); a
    # fetch-delivered LONG row ends with the "more rows" OER status (#407).
    from seerdb.common.tns import (
        ColumnMeta,
        encode_long_fetch_row_oci,
        encode_reexec_row_oci,
    )
    from seerdb.common.tns_consts import TNS_TYPE_LONG

    col = ColumnMeta(name=b'V', data_type=TNS_TYPE_LONG, data_length=0, max_size=0)
    reexec = encode_reexec_row_oci([col], [('hi',)], more=True)
    assert reexec[0] == 0x06  # TTI_RXH
    assert b'\x08\x06\x00' in reexec  # execute row-status
    fetch = encode_long_fetch_row_oci([col], ('hi',))
    assert fetch[0] == 0x06  # TTI_RXH
    assert fetch[-136:][:2] == b'\x04\x01'  # OER "more rows" status, no 1403 body


def test_lob_locator_carries_the_content_byte_size() -> None:
    # The row locator's size field is the content BYTE count (big-endian): a CLOB
    # is UTF-16 (2 bytes per char), a BLOB is its raw bytes. NULL is a lone 0x00
    # (no read). This unit is what makes sqlplus accept the locator (#405).
    from seerdb.common.tns import (
        _OCI_LOB_ROW_SIZE_OFF,
        encode_lob_locator_oci,
    )

    off = _OCI_LOB_ROW_SIZE_OFF
    clob = encode_lob_locator_oci('A' * 2000, is_clob=True)
    assert int.from_bytes(clob[off : off + 4], 'big') == 4000  # 2000 chars * 2
    blob = encode_lob_locator_oci(b'\x00' * 2500, is_clob=False)
    assert int.from_bytes(blob[off : off + 4], 'big') == 2500  # raw bytes
    assert encode_lob_locator_oci(None, is_clob=True) == b'\x00'
    # CLOB and BLOB use different locator templates: the type bytes and the charset
    # differ (a CLOB is AL32UTF8 characters, a BLOB is binary) so sqlplus does not
    # decode a BLOB's raw bytes as text (#406).
    assert clob[9] == 0x02 and blob[9] == 0x01  # LOB type byte
    assert clob[37] == 0x03 and blob[37] == 0x00  # charset (873 vs binary 0)


def test_lob_read_response_selects_clob_or_blob_locator() -> None:
    # The READ reply echoes the character (CLOB) or binary (BLOB) locator template,
    # matching the row locator so sqlplus renders the content correctly (#406).
    from seerdb.common.tns import encode_lob_read_response_oci

    clob_reply = encode_lob_read_response_oci(b'\x00A', 1, 2, is_clob=True)
    blob_reply = encode_lob_read_response_oci(b'\xca\xfe', 2, 2, is_clob=False)
    # The echoed locator carries the same type/charset split as the row locator.
    assert bytes.fromhex('0001020c88') in clob_reply  # CLOB locator signature
    assert bytes.fromhex('0001010c08') in blob_reply  # BLOB locator signature
    assert bytes.fromhex('0001020c88') not in blob_reply


def test_parse_lobops_read_extracts_offset_and_amount() -> None:
    # sqlplus's TTI_LOBOPS READ carries a 1-based source offset (ub8-LE @91) and an
    # amount (ub8-LE @269); the Mirror serves exactly that slice so the read loop
    # terminates (#405). A short/garbled request falls back to read-all.
    from seerdb.common.tns import (
        _OCI_LOBOPS_AMOUNT_OFF,
        _OCI_LOBOPS_OFFSET_OFF,
        parse_lobops_read,
    )

    body = bytearray(300)
    body[_OCI_LOBOPS_OFFSET_OFF : _OCI_LOBOPS_OFFSET_OFF + 8] = (501).to_bytes(
        8, 'little'
    )
    body[_OCI_LOBOPS_AMOUNT_OFF : _OCI_LOBOPS_AMOUNT_OFF + 8] = (500).to_bytes(
        8, 'little'
    )
    assert parse_lobops_read(bytes(body)) == (501, 500)
    # A zero offset normalises to 1 (1-based).
    body[_OCI_LOBOPS_OFFSET_OFF : _OCI_LOBOPS_OFFSET_OFF + 8] = (0).to_bytes(
        8, 'little'
    )
    assert parse_lobops_read(bytes(body))[0] == 1
    # Too short → read the whole LOB from the start.
    assert parse_lobops_read(b'\x03\x60\x01') == (1, 2**31)


def test_encode_lob_describe_oci_omits_the_dcb_tail() -> None:
    # The LOB execute reply is a describe with a distinct 33-byte tail + LOB status,
    # NOT the ordinary inline-row DCB tail (which carries the 0x06 0x01 0x22 marker)
    # — this is what makes sqlplus accept the locator row (#405).
    from seerdb.common.tns import ColumnMeta, encode_lob_describe_oci
    from seerdb.common.tns_consts import TNS_TYPE_CLOB

    col = ColumnMeta(name=b'C', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0)
    reply = encode_lob_describe_oci([col])
    assert reply[0] == TTI_DCB
    assert bytes.fromhex('060122') not in reply  # no DCB-tail marker
    assert b'\x08\x06\x00' in reply  # LOB execute status present


def test_oci_lob_describe_tail_is_built_from_fields() -> None:
    # The 33-byte LOB describe tail (#405) is built field-by-field, not stored:
    # the describe-time DALC head (ub4 char-length 7 + byte-length 7) + one carried
    # ub4 at offset 17. It must stay byte-identical to the live 11g capture.
    from seerdb.common.tns import (
        _OCI_LOB_DESCRIBE_SIZE_OFF,
        _OCI_LOB_DESCRIBE_TAIL,
        _oci_lob_describe_tail,
    )

    assert _OCI_LOB_DESCRIBE_TAIL == bytes.fromhex(
        '0007000000070000000000000000000000e81f0000000000000000000000000000'
    )
    assert _oci_lob_describe_tail() == _OCI_LOB_DESCRIBE_TAIL
    off = _OCI_LOB_DESCRIBE_SIZE_OFF
    assert int.from_bytes(_OCI_LOB_DESCRIBE_TAIL[off : off + 4], 'little') == 8168


def test_encode_lob_read_response_slices_and_reports_totals() -> None:
    # The READ reply carries the requested slice as LOB_DATA and reports the whole
    # LOB's byte size in the echoed locator plus this read's amount (#405).
    from seerdb.common.tns import (
        _OCI_LOB_TAIL_AMOUNT_OFF,
        _OCI_LOB_TAIL_SIZE_OFF,
        encode_lob_read_response_oci,
    )

    content = 'Hello'.encode('utf-16-be')  # a 5-char slice, 10 bytes
    reply = encode_lob_read_response_oci(content, amount=5, total_bytes=4000)
    assert reply[0] == TTI_LOB
    tail = reply[-251:]
    assert (
        int.from_bytes(tail[_OCI_LOB_TAIL_SIZE_OFF : _OCI_LOB_TAIL_SIZE_OFF + 4], 'big')
        == 4000
    )
    assert (
        int.from_bytes(
            tail[_OCI_LOB_TAIL_AMOUNT_OFF : _OCI_LOB_TAIL_AMOUNT_OFF + 4], 'little'
        )
        == 5
    )


def test_oci_lob_contents_reports_type_and_wire_bytes() -> None:
    # Each non-NULL LOB cell yields (wire-content, is_clob): CLOB is UTF-16BE, BLOB
    # is raw; NULL LOBs are skipped (they draw no read) (#405).
    from seerdb.common.tns import ColumnMeta, oci_lob_contents
    from seerdb.common.tns_consts import TNS_TYPE_BLOB, TNS_TYPE_CLOB

    cols = [
        ColumnMeta(name=b'C', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0),
        ColumnMeta(name=b'B', data_type=TNS_TYPE_BLOB, data_length=4000, max_size=0),
    ]
    got = oci_lob_contents(cols, [('hi', b'\xca\xfe'), (None, None)])
    assert got == [('hi'.encode('utf-16-be'), True), (b'\xca\xfe', False)]


def test_encode_value_emits_a_thin_lob_locator_for_lob_columns() -> None:
    # A thin (oracledb/seerdb) client's LOB column carries a minted opaque locator
    # inline; the content follows over TTI_LOBOPS. NULL is a bare 0x00 (#413).
    from seerdb.common.tns import (
        _THIN_LOB_LOCATOR,
        encode_lob_locator_thin,
        encode_value,
    )
    from seerdb.common.tns_consts import TNS_TYPE_BLOB, TNS_TYPE_CLOB

    for lob_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
        locator = encode_value('anything', lob_type)
        assert locator == encode_lob_locator_thin()
        # sb4 length prefix, then the length-led locator bytes the client keeps.
        assert _THIN_LOB_LOCATOR in locator
        assert encode_value(None, lob_type) == b'\x00'


def test_encode_lob_read_response_thin_carries_content_then_a_success_oer() -> None:
    # The thin READ reply is the whole LOB as LOB_DATA followed by a success OER:
    # the client reads the content, scans to the 04 01 XX OER, and stops (#413).
    from seerdb.common.tns import (
        _oci_lob_data,
        encode_lob_read_response_thin,
    )

    content = 'grüße'.encode('utf-16-be')
    reply = encode_lob_read_response_thin(content)
    assert reply[0] == TTI_LOB
    assert reply.startswith(_oci_lob_data(content))
    # The trailing success OER the client scans for (04 01 <status>).
    assert reply[len(_oci_lob_data(content)) :].startswith(b'\x04\x01')
    assert encode_lob_read_response_thin(b'').startswith(_oci_lob_data(b''))


def test_parse_lobops_request_classifies_create_temp() -> None:
    # CREATE_TEMP drives the temp-LOB write flow (#412): the Mirror recognises the
    # client's fixed block and the CLOB / BLOB type byte in it.
    from seerdb.common.tns import encode_dictionary_lobops, parse_lobops_request

    for is_blob in (False, True):
        body = encode_dictionary_lobops(
            {'seq': 1, 'create_temp': True, 'is_blob': is_blob}
        )
        req = parse_lobops_request(body)
        assert req.kind == 'create_temp'
        assert req.is_blob is is_blob


def test_parse_lobops_request_extracts_the_write_locator_and_payload() -> None:
    # WRITE carries the ub2-prefixed locator and a 0x0E chunked payload; the Mirror
    # pulls both out to append to the temp LOB (#412). Cover both the single-chunk
    # (<= 0xFC) and the multi-chunk (0xFE-marked) payload forms.
    from seerdb.common.tns import encode_dictionary_lobops, parse_lobops_request
    from seerdb.common.tns_consts import TNS_LOB_OP_WRITE

    locator = b'\x00seerdb-mirror-temp-lob-\x00\x00\x00\x00\x00'
    for payload in (b'short-payload', bytes(range(256)) * 200):  # 51200 B multi-chunk
        body = encode_dictionary_lobops(
            {
                'seq': 1,
                'operation': TNS_LOB_OP_WRITE,
                'locator': locator,
                'data': payload,
            }
        )
        req = parse_lobops_request(body)
        assert req.kind == 'write'
        assert req.locator == locator
        assert req.payload == payload


def test_temp_lob_responses_round_trip_through_the_client_decoders() -> None:
    # The Mirror's CREATE_TEMP / WRITE replies must parse with the client's own
    # readers: CREATE_TEMP returns the minted locator in a bare RPA, the content-
    # free ack an RPA (skipped by its ub2 length) then a success OER (#412).
    from seerdb.common.tns import (
        decode_lobops_oer,
        encode_create_temp_response,
        encode_lobops_ack,
        mint_temp_lob_locator,
    )

    locator = mint_temp_lob_locator(3, is_blob=True)
    create = encode_create_temp_response(locator)
    # The client reads: 0x08, ub2 length, then the locator bytes.
    assert create[0] == 0x08  # TTI_RPA
    assert int.from_bytes(create[1:3], 'big') == len(locator)
    assert create[3:] == locator

    ack = encode_lobops_ack(locator)
    err_code, _msg = decode_lobops_oer(ack, 6)
    assert err_code in (0, 1403)  # a success OER, not a real error


def _lobops_op_request(operation: int, locator: bytes, *, seq: int = 1) -> bytes:
    # A TTI_LOBOPS request for a state op (FREE_TEMP / OPEN / CLOSE / TRIM /
    # GET_CHUNK_SIZE), built in the shared §14.1 layout with the ub2-prefixed
    # locator — the same field block the client's WRITE / FILE_OPEN encoders use.
    import struct

    from seerdb.common.tns import _fun_header, encode_sb4
    from seerdb.common.tns_consts import FIELD_VERSION_11_2, TTI_LOBOPS

    body = _fun_header(TTI_LOBOPS, seq, FIELD_VERSION_11_2)
    body += bytes([1])  # source pointer present
    body += encode_sb4(len(locator) + 2)  # source locator length (+ub2)
    body += bytes([0])  # dest pointer absent
    body += encode_sb4(0)  # dest_length
    body += encode_sb4(0)  # short source offset
    body += encode_sb4(0)  # short dest offset
    body += bytes([0, 0, 0])  # charset / short-amount / null-lob pointer flags
    body += encode_sb4(operation)  # operation code
    body += bytes([0, 0])  # scn-array pointer + length
    body += encode_sb4(0)  # source offset (ub8)
    body += encode_sb4(0)  # dest offset (ub8)
    body += bytes([0])  # amount pointer flag
    body += struct.pack('>HHH', 0, 0, 0)  # three reserved ub2 array-LOB slots
    body += struct.pack('>H', len(locator)) + locator  # ub2-prefixed locator
    return body


def test_parse_lobops_request_classifies_the_state_opcodes() -> None:
    # FREE_TEMP releases a temp LOB (its own kind, so the session drops the
    # buffer); OPEN / CLOSE / TRIM / GET_CHUNK_SIZE are acknowledged; each carries
    # the locator so the reply can echo it (#417).
    from seerdb.common.tns import parse_lobops_request
    from seerdb.common.tns_consts import (
        TNS_LOB_OP_CLOSE,
        TNS_LOB_OP_FREE_TEMP,
        TNS_LOB_OP_GET_CHUNK_SIZE,
        TNS_LOB_OP_OPEN,
        TNS_LOB_OP_TRIM,
    )

    locator = b'\x00seerdb-mirror-temp-lob-\x00\x00\x00\x00\x01'
    req = parse_lobops_request(_lobops_op_request(TNS_LOB_OP_FREE_TEMP, locator))
    assert req.kind == 'free_temp'
    assert req.locator == locator
    for op in (
        TNS_LOB_OP_OPEN,
        TNS_LOB_OP_CLOSE,
        TNS_LOB_OP_TRIM,
        TNS_LOB_OP_GET_CHUNK_SIZE,
    ):
        req = parse_lobops_request(_lobops_op_request(op, locator))
        assert req.kind == 'ack', op
        assert req.locator == locator, op


def test_parse_exec_decodes_a_temp_lob_bind_as_a_reference() -> None:
    # A CLOB / BLOB bind is the temp-LOB descriptor 01 28 28 | ub2 len | locator,
    # not a plain DALC — parse_exec keeps it as a TempLobRef for the session to
    # resolve (#412). Built with the client's own execute encoder.
    from seerdb.common.datatypes import TempLob
    from seerdb.common.tns import TempLobRef, encode_dictionary_exec, parse_exec

    locator = b'\x00seerdb-mirror-temp-lob-\x00\x00\x00\x00\x01'
    payload = encode_dictionary_exec(
        {
            'seq': 4,
            'field_version': 6,
            'query': {
                'type': 'select',
                'auto': 0,
                'fetch': 0,
                'server_version': 186647040,
                'cursor': 0,
                'query': 'insert into t values (:1, :2)',
                'bind': [7, TempLob(locator, True, 4096)],
                'batch': [],
                'def': [],
            },
        }
    )
    request = parse_exec(payload)
    assert request.binds[0] == 7
    ref = request.binds[1]
    assert isinstance(ref, TempLobRef)
    assert ref.locator == locator
    assert ref.is_blob is True


def test_encode_dml_status_oci_carries_the_verb_and_rowcount() -> None:
    # Each DML verb has its own captured template (sqlplus reads the verb from the
    # statement-type fields), and the affected-row count is injected as a ub4-LE at
    # offset 43 of the body so sqlplus prints "N rows created/updated/deleted".
    from seerdb.common.tns import _OCI_DML_ROWCOUNT_OFF, encode_dml_status_oci

    off = _OCI_DML_ROWCOUNT_OFF
    for keyword in ('INSERT', 'UPDATE', 'DELETE'):
        status = encode_dml_status_oci(keyword, 7)
        assert status[:3] == b'\x08\x06\x00'
        assert len(status) == 187
        assert int.from_bytes(status[off : off + 4], 'little') == 7

    # The verb templates are distinct — the command-code byte differs per verb.
    codes = {kw: encode_dml_status_oci(kw, 1) for kw in ('INSERT', 'UPDATE', 'DELETE')}
    assert codes['INSERT'] != codes['UPDATE'] != codes['DELETE']

    # An unknown verb (e.g. MERGE) falls back to the INSERT template.
    assert encode_dml_status_oci('MERGE', 3) == encode_dml_status_oci('INSERT', 3)

    # Zero rows is representable (DML matching no rows).
    assert (
        int.from_bytes(encode_dml_status_oci('DELETE', 0)[off : off + 4], 'little') == 0
    )


def test_oci_dml_frame_trailer_is_derived_from_the_rowid() -> None:
    # The 16-byte DML status trailer is not stored independently: it splices two of
    # the rowid's 2-byte words back in byte-swapped, inside a fixed frame. It must
    # stay byte-identical to the capture and track the rowid.
    from seerdb.common.tns import (
        _OCI_DML_FRAME_TRAILER,
        _OCI_DML_ROWID,
        _oci_dml_frame_trailer,
    )

    assert _OCI_DML_FRAME_TRAILER.hex() == '0d000d010001b57f00010000b4b10000'
    assert _oci_dml_frame_trailer(_OCI_DML_ROWID) == _OCI_DML_FRAME_TRAILER
    # The two byte-swapped rowid words really do come from the rowid.
    assert _OCI_DML_FRAME_TRAILER[6:8] == _OCI_DML_ROWID[1:3][::-1]
    assert _OCI_DML_FRAME_TRAILER[12:14] == _OCI_DML_ROWID[9:11][::-1]


def test_encode_ddl_status_oci_carries_the_command_type() -> None:
    # One frame carries the V$SQL command code at offset 57; sqlplus renders it as
    # "Table created." (1) / "Table dropped." (12) / "Index created." (9) etc. DDL
    # affects no rows — nothing but that field varies.
    from seerdb.common.tns import ddl_command_type, encode_ddl_status_oci

    create = encode_ddl_status_oci(1)
    drop = encode_ddl_status_oci(12)
    for body in (create, drop):
        assert body[:3] == b'\x08\x06\x00'
        assert len(body) == 171
    assert create[57] == 0x01  # CREATE TABLE
    assert drop[57] == 0x0C  # DROP TABLE
    assert create != drop

    # The resolver maps (verb, object) -> V$SQL command type.
    assert ddl_command_type('create table t (x number)') == 1
    assert ddl_command_type('CREATE INDEX ix ON t (x)') == 9
    assert ddl_command_type('drop view v') == 22
    assert ddl_command_type('truncate table t') == 85
    assert ddl_command_type('grant select on t to bob') == 17
    # a bare verb defaults to its TABLE variant; a non-DDL verb is None.
    assert ddl_command_type('alter something') == 15
    assert ddl_command_type('begin null; end;') is None


def test_oci_status_frame_prefixes_share_one_builder() -> None:
    # The describe/outbind, DDL and DML exec-status frames all begin with the same
    # 35-byte `08 06` preamble, built by _oci_status_frame_prefix from a cursor id
    # and two statement-kind markers. Each must stay byte-identical to its capture.
    from seerdb.common.tns import (
        _OCI_DDL_FRAME_PREFIX,
        _OCI_DML_FRAME_PREFIX,
        _OCI_STATUS_FRAME_PREFIX,
        _oci_status_frame_prefix,
    )

    assert (
        _OCI_STATUS_FRAME_PREFIX.hex()
        == '0806000000000000000000020000000000000000000000000000000000000000000000'
    )
    assert (
        _OCI_DDL_FRAME_PREFIX.hex()
        == '08060000eb5b0000000000000000000000000000000000000000000000000000000000'
    )
    assert (
        _OCI_DML_FRAME_PREFIX.hex()
        == '08060000e85b0000000000020000000100000000000000000000000000000000000000'
    )
    # Reproduced from the named fields.
    assert _oci_status_frame_prefix(row_producing=True) == _OCI_STATUS_FRAME_PREFIX
    assert _oci_status_frame_prefix(0x5BEB) == _OCI_DDL_FRAME_PREFIX
    assert (
        _oci_status_frame_prefix(0x5BE8, row_producing=True, dml=True)
        == _OCI_DML_FRAME_PREFIX
    )


def test_read_chunked_sql_reassembles_the_chunks() -> None:
    # Long OCI SQL is chunked: 0xFE marker, then <ub1 len><chunk> runs. The reader
    # reassembles them up to the declared total (#265).
    from seerdb.common.tns import _read_chunked_sql

    data = b'\xfe\x03abc\x02de\x00tail'
    assert _read_chunked_sql(data, 5) == b'abcde'


def test_encode_error_oci_matches_the_captured_ora_error() -> None:
    # Byte-for-byte against a real 11g OCI error reply (ORA-00942): the OER frame
    # with call-status 0x05, the code at offset 12, and the message (#265, #350).
    from seerdb.common.tns import encode_error_oci

    captured = bytes.fromhex(
        '040500000013000100000000ae030000000002000e0003000000000000000000'
        '0000000000000000000000000000000000150000010000003601000000000000'
        '000000000000000020f6310a0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000284f52412d30303934323a207461626c65206f7220766965'
        '7720646f6573206e6f742065786973740a'
    )
    assert encode_error_oci(942, 'table or view does not exist') == captured


def test_oci_dcb_tail_is_column_aware() -> None:
    # The DCB tail carries the column count; the client reads it to parse each
    # row, so it is load-bearing for a multi-column result (#265, #346).
    from seerdb.common.tns import (
        _OCI_DCB_MARKER_OFF,
        _OCI_DCB_NUMCOLS_OFF,
        _oci_dcb_tail,
    )

    assert _oci_dcb_tail(3)[_OCI_DCB_NUMCOLS_OFF] == 3
    assert _oci_dcb_tail(1)[_OCI_DCB_NUMCOLS_OFF] == 1
    off = _OCI_DCB_MARKER_OFF
    assert _oci_dcb_tail(2)[off : off + 3] == bytes.fromhex('060122')


def test_encode_query_response_oci_signals_more_rows() -> None:
    # more=True flips the status byte sqlplus reads as "fetch for the rest" (#351).
    from seerdb.common.tns import (
        _OCI_MORE_ROWS_OFF,
        _OCI_ROW_STATUS_LEN,
        encode_query_response_oci,
    )

    col = ColumnMeta(
        name=b'N', data_type=TNS_TYPE_NUMBER, data_length=2, max_size=0, scale=-127
    )
    done = encode_query_response_oci([col], [(1,)], more=False)
    more = encode_query_response_oci([col], [(1,)], more=True)
    i = len(done) - _OCI_ROW_STATUS_LEN + _OCI_MORE_ROWS_OFF
    assert more[i] == 0x1E and done[i] == 0x00


def test_encode_fetch_batch_oci_carries_rows_and_terminator() -> None:
    # A fetch batch: RXH + one RXD per remaining row + the end-of-fetch OER (#351).
    from seerdb.common.tns import encode_fetch_batch_oci

    col = ColumnMeta(
        name=b'N', data_type=TNS_TYPE_NUMBER, data_length=2, max_size=0, scale=-127
    )
    batch = encode_fetch_batch_oci([col], [(1,), (2,)])
    assert batch[0] == 0x06  # TTI_RXH token
    assert batch.count(b'\x07\x02\xc1') == 2  # two RXD rows (07 + NUMBER DALC)
    assert batch.endswith(b'ORA-01403: no data found\n')


def test_parse_exec_oci_extracts_bind_values() -> None:
    # A live sqlplus bound execute — SELECT :n, :s FROM dual with :n=42 (NUMBER),
    # :s='hello' (VARCHAR). The bind count is in the header; the OAC markers give
    # each type and the RXD row carries the values (#265, #347).
    bound = bytes.fromhex(
        '035e176980000000000000feffffffffffffff4500000000000000feffffffffffffff'
        '0d00000000000000fefffffffffffffffeffffffffffffff0000000001000000000000'
        '0000000000feffffffffffffff02000000000000000000000000000000feffffffffff'
        'ffff0000000000000000fefffffffffffffffefffffffffffffff815aa0f0000000000'
        '00000000000000fefffffffffffffffeffffffffffffff000000000000000000000000'
        '00000000000000000000000000000000000000001753454c454354203a6e2c203a7320'
        '46524f4d206475616c0100000000000000000000000000000000000000000000000000'
        '0000010000000000000000000000000000000000000000000000010203000016000000'
        '0000000000000000000000000000000000000000000000000000000000000000010103'
        '00001e0000000000000000000000000000000000000000000000690301000000000000'
        '0000000702c12b0568656c6c6f'
    )
    req = parse_exec_oci(bound)
    assert req.sql == 'SELECT :n, :s FROM dual'
    assert req.bind_count == 2
    assert req.binds == [42, 'hello']


def test_encode_out_bind_response_oci_matches_captured_11g_reply() -> None:
    # The sqlplus `EXEC :n := 7` OUT-bind reply, captured live from 11g and
    # normalised (the server pointer, SCN and an internal sequence counter, which
    # are instance-specific, zeroed). The encoder reproduces it byte-for-byte: a
    # ttc=0b01 body with the bind count at offset 4, one 0x10 define marker, an
    # RXD row (07 + NUMBER 7 DALC + a 2-byte return code) and the fixed tail (#347).
    from seerdb.common.tns import encode_out_bind_response_oci

    captured_n7 = bytes.fromhex(
        '0b0105cc010000000000010000000000000000000000000000000000e80700000000000000'
        '00000000000000000000000000100702c10800000806000000000000000000020000000000'
        '00000000000000000000000000000000000004010000000000010100000000000000000002'
        '0000002f000000000000000000000000000000000000000000000000000000000001000000'
        '3601000000000000000000000000000020f6310a0000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000000000'
        '000000000000'
    )
    assert encode_out_bind_response_oci([7]) == captured_n7


def test_encode_out_bind_response_oci_marshals_each_bind() -> None:
    # Bind count (offset 4) and one 0x10 define marker per OUT value; the RXD row
    # carries each value as a DALC followed by a 2-byte per-bind return code. A
    # VARCHAR OUT bind rides the same frame as a NUMBER one (#347).
    from seerdb.common.tns import encode_out_bind_response_oci
    from seerdb.common.tns_consts import TTI_RXD

    two = encode_out_bind_response_oci([7, 9])
    assert two[4] == 2  # bind count
    assert two[50:52] == b'\x10\x10'  # one define marker per bind
    rxd = two[52:]
    assert rxd[0] == TTI_RXD
    # 07 | 02 c1 08 (NUMBER 7) 00 00 | 02 c1 0a (NUMBER 9) 00 00
    assert rxd[:11] == bytes.fromhex('0702c108000002c10a0000')

    text = encode_out_bind_response_oci(['hi'])
    assert text[4] == 1
    assert text[51:].startswith(bytes.fromhex('0702686900'))  # 07 + 'hi' DALC


# --- Server-side scrollable cursors (#181/#485) ---------------------------------


def _scroll_exec(cursor: int, orientation: int, position: int, fetch: int) -> bytes:
    # Build a SCROLLABLE OALL8 the way the thin client marshals a scroll
    # re-execute (an open cursor, empty query, the orientation/position in the
    # al8i4 array). field_version 6 is the Mirror's advertised 11.2 layout.
    from seerdb.common.tns import encode_dictionary_exec
    from seerdb.common.tns_consts import FIELD_VERSION_11_2

    return encode_dictionary_exec(
        {
            'seq': 3,
            'field_version': FIELD_VERSION_11_2,
            'query': {
                'type': 'select',
                'auto': 0,
                'fetch': fetch,
                'server_version': 186647040,
                'cursor': cursor,
                'query': '',
                'bind': [],
                'batch': [],
                'def': [],
                'scrollable': True,
                'scroll': (orientation, position),
            },
        }
    )


def test_parse_exec_reads_scroll_request() -> None:
    from seerdb.common.tns_consts import (
        TNS_FETCH_ORIENTATION_ABSOLUTE,
        TNS_FETCH_ORIENTATION_LAST,
    )

    # A scroll re-execute: the SCROLLABLE flag plus orientation + 1-based position
    # ride the al8i4 array (indices 9/10/11), which parse_exec now decodes even
    # though the message carries no binds.
    req = parse_exec(_scroll_exec(7, TNS_FETCH_ORIENTATION_ABSOLUTE, 5, 3))
    assert req.scrollable is True
    assert req.cursor == 7
    assert req.scroll_orientation == TNS_FETCH_ORIENTATION_ABSOLUTE
    assert req.scroll_position == 5

    last = parse_exec(_scroll_exec(7, TNS_FETCH_ORIENTATION_LAST, 0, 3))
    assert last.scroll_orientation == TNS_FETCH_ORIENTATION_LAST

    # A plain (non-scrollable) execute leaves the flag clear.
    from seerdb.common.tns import encode_dictionary_exec

    plain = encode_dictionary_exec(
        {
            'seq': 3,
            'field_version': 6,
            'query': {
                'type': 'select',
                'auto': 0,
                'fetch': 15,
                'server_version': 186647040,
                'cursor': 0,
                'query': 'select 1 from dual',
                'bind': [],
                'batch': [],
                'def': [],
            },
        }
    )
    assert parse_exec(plain).scrollable is False


def test_scroll_start_row_maps_orientation() -> None:
    from seerdb.common.tns import scroll_start_row
    from seerdb.common.tns_consts import (
        TNS_FETCH_ORIENTATION_ABSOLUTE,
        TNS_FETCH_ORIENTATION_FIRST,
        TNS_FETCH_ORIENTATION_LAST,
    )

    assert scroll_start_row(TNS_FETCH_ORIENTATION_FIRST, 0, 10) == 1
    assert scroll_start_row(TNS_FETCH_ORIENTATION_LAST, 0, 10) == 10
    # ABSOLUTE / RELATIVE / CURRENT take the client's already-absolute position.
    assert scroll_start_row(TNS_FETCH_ORIENTATION_ABSOLUTE, 4, 10) == 4
    # An empty result set has no last row.
    assert scroll_start_row(TNS_FETCH_ORIENTATION_LAST, 0, 0) == 0


def test_scroll_terminator_carries_rowcount_and_eof() -> None:
    from seerdb.common.tns import _scroll_terminator, decode_token_oer

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)

    # Mid-stream: the OER carries the cumulative row number (absolute position of
    # the last row delivered) and no ORA-01403, so the client keeps scrolling.
    more = decode_token_oer(
        _scroll_terminator(0, server_rowcount=6, eof=False), (0, [], [])
    )
    assert more[1] == 0  # not end-of-fetch
    assert more[3][0] == 6  # cumulative row number

    # A batch that reaches the end terminates with ORA-01403 (still carrying the
    # cumulative row number).
    end = decode_token_oer(
        _scroll_terminator(0, server_rowcount=6, eof=True), (0, [], [])
    )
    assert end[1] == 1403
    assert end[3][0] == 6

    # The opening execute's terminator ties in the kept-open cursor id.
    opened = decode_token_oer(
        _scroll_terminator(9, server_rowcount=2, eof=False), (0, [], [])
    )
    assert opened[2] == 9


def test_scroll_response_bodies_frame_rows_and_describe() -> None:
    from seerdb.common.tns import (
        _scroll_terminator,
        encode_rows,
        encode_scroll_open_response,
        encode_scroll_response,
    )
    from seerdb.common.tns_consts import TTI_DCB, TTI_RXH

    col = ColumnMeta(name=b'ID', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)

    # The open leads with a describe (DCB); the re-execute leads with the row
    # header (RXH) and omits the describe. Both end with the scroll terminator.
    opened = encode_scroll_open_response(
        [col], [(1,), (2,)], cursor_id=9, server_rowcount=2, eof=False
    )
    assert opened[0] == TTI_DCB
    assert encode_rows([(1,), (2,)], [col]) in opened  # the prefetched batch
    assert opened.endswith(_scroll_terminator(9, server_rowcount=2, eof=False))

    reexec = encode_scroll_response([col], [(6,)], server_rowcount=6, eof=True)
    assert reexec[0] == TTI_RXH  # no describe on a reposition
    assert reexec.endswith(_scroll_terminator(0, server_rowcount=6, eof=True))

    # Scrolled off the end: an empty batch (header only) ending in ORA-01403.
    off = encode_scroll_response([], [], server_rowcount=0, eof=True)
    assert off == encode_rows([], []) + _scroll_terminator(
        0, server_rowcount=0, eof=True
    )


# --- INTERVAL DAY TO SECOND / YEAR TO MONTH (#484) -----------------------------


def test_encode_value_dispatches_interval_columns() -> None:
    import datetime

    from seerdb.common.datatypes import IntervalYM
    from seerdb.common.tns import (
        encode_token_interval_ds,
        encode_token_interval_ym,
        encode_value,
    )
    from seerdb.common.tns_consts import TNS_TYPE_INTERVALDS, TNS_TYPE_INTERVALYM

    # The scalar-value encoder must route an INTERVAL column's Python value
    # (timedelta / IntervalYM) to the interval encoder, DALC-wrapped — otherwise
    # it falls through to the isinstance chain and raises, dropping the wire.
    td = datetime.timedelta(days=1, hours=2)
    assert encode_value(td, TNS_TYPE_INTERVALDS) == bytes(
        [11]
    ) + encode_token_interval_ds(td)
    iy = IntervalYM(1, 2)
    assert encode_value(iy, TNS_TYPE_INTERVALYM) == bytes(
        [5]
    ) + encode_token_interval_ym(iy)
    # NULL stays the empty DALC regardless of type.
    assert encode_value(None, TNS_TYPE_INTERVALDS) == bytes([0])


# --- LONG / LONG RAW inline column values (#484) -------------------------------


def test_encode_long_value_thin_roundtrips_via_client_reader() -> None:
    from seerdb.common.tns import (
        _DECODE_FIELD_VERSION,
        _read_long_column,
        encode_long_value_thin,
    )

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)  # 11g single-byte chunk form
    for content in (
        b'hello',
        b'x' * 700,  # multi-chunk
        b'',
        ('café — 日本').encode('utf-8'),
    ):
        # A trailing sentinel proves the two ub4 indicators are consumed and the
        # reader stops exactly at the value's end (no desync into the next token).
        val, rest = _read_long_column(encode_long_value_thin(content) + b'\xaa\xbb')
        assert val == content
        assert rest == b'\xaa\xbb'

    # A NULL LONG still carries the trailing indicators, so the reader realigns.
    val, rest = _read_long_column(encode_long_value_thin(None) + b'\xaa\xbb')
    assert val is None
    assert rest == b'\xaa\xbb'


def test_encode_value_routes_long_columns_and_null_carries_trailers() -> None:
    from seerdb.common.tns import encode_long_value_thin, encode_value
    from seerdb.common.tns_consts import TNS_TYPE_LONG, TNS_TYPE_LONGRAW

    # A LONG / LONG RAW column must use the inline streaming form, not a DALC —
    # and a NULL LONG must still carry the two trailing indicators (the bare-0x00
    # DALC NULL would desync the client's _read_long_column).
    assert encode_value('abc', TNS_TYPE_LONG) == encode_long_value_thin('abc')
    assert encode_value(b'\x00\x01', TNS_TYPE_LONGRAW) == encode_long_value_thin(
        b'\x00\x01'
    )
    assert encode_value(None, TNS_TYPE_LONG) == encode_long_value_thin(None)
    assert encode_value(None, TNS_TYPE_LONG) != bytes([0])  # not the DALC NULL


# --- ROWID / UROWID column values (#484) ---------------------------------------


def test_string_to_rowid_inverts_rowid_to_string() -> None:
    from seerdb.common.types import rowid_to_string, string_to_rowid

    for text in ('AAAAB0AABAAAAOhAAA', 'AAAK6JAAEAAACGPAAA'):
        obj, file, block, slot = string_to_rowid(text)
        assert rowid_to_string(obj, file, block, slot) == text


def test_encode_rowid_value_roundtrips_via_client_reader() -> None:
    from seerdb.common.tns import _read_rowid_column, encode_rowid_value

    for text in ('AAAAB0AABAAAAOhAAA', 'AAAK6JAAEAAACGPAAA'):
        val, rest = _read_rowid_column(encode_rowid_value(text) + b'\xaa')
        assert val == text
        assert rest == b'\xaa'
    # A NULL rowid is a bare present-indicator the reader reports as None.
    val, rest = _read_rowid_column(encode_rowid_value(None) + b'\xaa')
    assert val is None
    assert rest == b'\xaa'


def test_encode_urowid_value_roundtrips_via_client_reader() -> None:
    from seerdb.common.tns import _read_urowid_column, encode_urowid_value

    for text in ('*BAEALAMCwQL+', '*BAEAGYMCwQL+'):
        val, rest = _read_urowid_column(encode_urowid_value(text) + b'\xaa')
        assert val == text
        assert rest == b'\xaa'
    val, rest = _read_urowid_column(encode_urowid_value(None) + b'\xaa')
    assert val is None
    assert rest == b'\xaa'


def test_encode_value_routes_rowid_columns() -> None:
    from seerdb.common.tns import (
        encode_rowid_value,
        encode_urowid_value,
        encode_value,
    )
    from seerdb.common.tns_consts import TNS_TYPE_RID, TNS_TYPE_UROWID

    assert encode_value('AAAAB0AABAAAAOhAAA', TNS_TYPE_RID) == encode_rowid_value(
        'AAAAB0AABAAAAOhAAA'
    )
    assert encode_value('*BAEALAMCwQL+', TNS_TYPE_UROWID) == encode_urowid_value(
        '*BAEALAMCwQL+'
    )


# --- National char (NCHAR / NVARCHAR) bind decode (#484) ------------------------


def test_decode_oac_fields_exposes_csfrm() -> None:
    from seerdb.common.tns import decode_oac_fields, decode_token_oac, encode_tokens_oac

    # Build the OAC bytes the client sends for one VARCHAR bind, then confirm the
    # new decoder surfaces the charset-form byte the 5-tuple form drops.
    oac = encode_tokens_oac(['hi'], b'')
    dtype, maxlen, scale, charset, csfrm, rest = decode_oac_fields(oac)
    assert csfrm == 1  # an ordinary (DB) char bind
    # The 5-tuple form stays byte-compatible (same fields minus csfrm).
    assert (dtype, maxlen, scale, charset, rest) == decode_token_oac(oac, ())


def test_decode_bind_value_honours_national_csfrm() -> None:
    from seerdb.common.tns import _decode_bind_value
    from seerdb.common.tns_consts import TNS_TYPE_VARCHAR

    text = 'café—Ω—日本'
    raw = text.encode('utf-16-be')  # how an NCHAR / NVARCHAR bind arrives
    # csfrm 2 (national) decodes UTF-16BE; csfrm 1 (ordinary) mojibakes it.
    assert _decode_bind_value(TNS_TYPE_VARCHAR, 2, raw) == text
    assert _decode_bind_value(TNS_TYPE_VARCHAR, 1, raw) != text
    # A NULL bind stays None regardless of form.
    assert _decode_bind_value(TNS_TYPE_VARCHAR, 2, b'') is None


# --- PL/SQL OUT binds: thin IOV response (#483) --------------------------------


def test_encode_out_bind_response_thin_roundtrips_via_client() -> None:
    from seerdb.client.cursor import _assign_out_binds
    from seerdb.common.datatypes import NUMBER, STRING, Var
    from seerdb.common.tns import (
        ScalarOutBind,
        decode_packet,
        encode_out_bind_response_thin,
    )
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    # callproc([21, out NUMBER, io VARCHAR]) — the Mirror marks every bind OUT and
    # returns each value; the client keeps only the positions it bound as a Var.
    resp = encode_out_bind_response_thin(
        [
            ScalarOutBind(21, TNS_TYPE_NUMBER),
            ScalarOutBind(42, TNS_TYPE_NUMBER),
            ScalarOutBind('hi!', TNS_TYPE_VARCHAR),
        ]
    )
    v_out, v_io = Var(NUMBER), Var(STRING, 100)
    bind = [21, v_out, v_io]
    result = decode_packet(resp, (0, [], [], bind))
    assert result[1] == 0  # success OER
    record = result[4][0]
    assert record['out_positions'] == [0, 1, 2]
    assert record['directions'] == [16, 16, 16]  # all OUT
    # The client assigns only its Var positions; the plain IN value 0 is skipped.
    assert _assign_out_binds(bind, result) == []
    assert v_out.getvalue() == 42
    assert v_io.getvalue() == 'hi!'


def test_parse_exec_exposes_bind_meta() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    # bind_meta carries (tns_type, max_size) per bind — the type + OUT buffer size
    # a PL/SQL block's OUT binds need registered on the backend.
    msg = encode_dictionary_exec(
        {
            'seq': 3,
            'field_version': 6,
            'query': {
                'type': 'block',
                'auto': 0,
                'fetch': 0,
                'server_version': 186647040,
                'cursor': 0,
                'query': 'BEGIN p(:1, :2); END;',
                'bind': [7, 'hi'],
                'batch': [],
                'def': [],
            },
        }
    )
    req = parse_exec(msg)
    assert len(req.bind_meta) == 2
    assert req.bind_meta[0][0] == TNS_TYPE_NUMBER  # a NUMBER bind's type
    assert all(size >= 0 for _t, size in req.bind_meta)


def test_encode_out_bind_response_thin_refcursor_entry() -> None:
    from seerdb.common.datatypes import CURSOR, Var
    from seerdb.common.tns import (
        RefCursorOutBind,
        decode_packet,
        encode_out_bind_response_thin,
    )

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    cols = [
        ColumnMeta(name=b'A', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22),
        ColumnMeta(name=b'B', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1),
    ]
    # A REF CURSOR OUT bind: the client decodes an inline-describe marker carrying
    # the parked cursor id + row format (which it then drains with TTI_FETCH).
    resp = encode_out_bind_response_thin([RefCursorOutBind(columns=cols, cursor_id=7)])
    result = decode_packet(resp, (0, [], [], [Var(CURSOR)]))
    assert result[1] == 0  # success OER
    value = result[4][0]['out_values'][0]
    assert value['_refcursor'] is True
    assert value['cursor_id'] == 7
    assert [c['column_name'] for c in value['row_format']] == [b'A', b'B']


# --- Array-DML batcherrors (#18/#486) ------------------------------------------


def test_encode_batch_errors_status_roundtrips_via_client() -> None:
    from seerdb.common.tns import decode_token_oer, encode_batch_errors_status

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    # Two rows of a 5-row executemany violated the PK (offsets 2 and 4); the
    # client reads ORA-24381 + the per-row (offset, code, message) arrays.
    body = encode_batch_errors_status(
        3,
        [
            (2, 1, 'ORA-00001: unique constraint violated'),
            (4, 1, 'ORA-00001: unique constraint violated'),
        ],
    )
    result = decode_token_oer(body, (0, [], []))
    assert result[1] == 24381  # the array-DML summary code (non-fatal)
    assert result[3][0] == 3  # affected-row count (the applied rows)
    errs = result[7]
    assert [(e['offset'], e['code']) for e in errs] == [(2, 1), (4, 1)]
    assert 'ORA-00001' in errs[0]['message']
    # No batch errors → the three arrays stay empty (a plain status is unchanged).
    plain = decode_token_oer(encode_batch_errors_status(0, []), (0, [], []))
    assert plain[7] == []


def test_parse_exec_reads_batcherrors_flag() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    def dml(batcherrors: bool) -> bytes:
        return encode_dictionary_exec(
            {
                'seq': 3,
                'field_version': 6,
                'query': {
                    'type': 'change',
                    'auto': 0,
                    'fetch': 0,
                    'server_version': 186647040,
                    'cursor': 0,
                    'query': 'INSERT INTO t VALUES (:1, :2)',
                    'bind': [1, 'a'],
                    'batch': [[2, 'b']],
                    'def': [],
                    'batcherrors': batcherrors,
                },
            }
        )

    assert parse_exec(dml(True)).batcherrors is True
    assert parse_exec(dml(False)).batcherrors is False


# --- Cursor cache: cached re-execute without OACs (#80/#486) --------------------


def test_peek_exec_cursor_reads_cursor_and_query_presence() -> None:
    from seerdb.common.tns import encode_dictionary_exec, peek_exec_cursor

    def msg(cursor: int, query: str) -> bytes:
        return encode_dictionary_exec(
            {
                'seq': 3,
                'field_version': 6,
                'query': {
                    'type': 'change',
                    'auto': 0,
                    'fetch': 0,
                    'server_version': 186647040,
                    'cursor': cursor,
                    'query': query,
                    'bind': [1, 'a'],
                    'batch': [],
                    'def': [],
                },
            }
        )

    # A fresh parse carries SQL; a cached re-execute has a cursor id and no SQL.
    assert peek_exec_cursor(msg(0, 'INSERT INTO t VALUES (:1, :2)')) == (0, True)
    assert peek_exec_cursor(msg(5, '')) == (5, False)
    assert peek_exec_cursor(b'\x03\x05not an exec') == (0, True)


def test_parse_exec_cached_reexecute_decodes_binds_without_oacs() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    def msg(cursor: int, query: str, binds: list) -> bytes:
        return encode_dictionary_exec(
            {
                'seq': 3,
                'field_version': 6,
                'query': {
                    'type': 'change',
                    'auto': 0,
                    'fetch': 0,
                    'server_version': 186647040,
                    'cursor': cursor,
                    'query': query,
                    'bind': binds,
                    'batch': [],
                    'def': [],
                },
            }
        )

    # First parse remembers the bind format (bind_types); the re-execute omits the
    # OACs, so parsing it needs those remembered types or its RXD mis-decodes.
    first = parse_exec(msg(0, 'INSERT INTO t VALUES (:1, :2)', [1, 'a']))
    assert first.binds == [1, 'a']
    assert len(first.bind_types) == 2

    reexec = msg(5, '', [2, 'b'])
    # Parsing the OAC-less re-execute without the remembered types mis-reads the
    # RXD (the session never does this — it always supplies the types).
    with pytest.raises((InterfaceError, IndexError, DataError)):
        parse_exec(reexec)
    # With the remembered types the new bind values decode correctly.
    assert parse_exec(reexec, bind_types=first.bind_types).binds == [2, 'b']


# --- Object REF column describe + value (#494) ---------------------------------


def test_ref_column_describe_and_value_roundtrip() -> None:
    from seerdb.common.dbobject import DbRef
    from seerdb.common.tns import encode_describe, encode_rows
    from seerdb.common.tns_consts import TNS_TYPE_REF, TTI_STA

    # A REF column carries the referenced type's identity in the describe and the
    # opaque locator bytes in the row; the client rebuilds a typed DbRef.
    col = ColumnMeta(
        name=b'R',
        data_type=TNS_TYPE_REF,
        data_length=4000,
        max_size=4000,
        type_name=b'PERSON',
        type_schema=b'PYO',
        type_oid=b'\x01' * 16,
    )
    ref = DbRef(b'\x00\x28\x02\x09', 'PERSON', 'PYO', b'\x01' * 16)
    response = encode_describe([col]) + encode_rows([(ref,)], [col]) + bytes([TTI_STA])
    columns, rows = _decode_response(response)
    # The describe carried the type identity (what surfaces as ref.type_name).
    assert columns[0]['type_name'] == 'PERSON'
    assert columns[0]['type_schema'] == 'PYO'
    assert columns[0]['type_oid'] == b'\x01' * 16
    # The value decoded back to a DbRef with that identity and its locator bytes.
    got = rows[0][0]
    assert got.type_name == 'PERSON'
    assert got.bytes == b'\x00\x28\x02\x09'
