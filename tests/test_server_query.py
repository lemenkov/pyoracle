# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side query-path parsing."""

from __future__ import annotations

import pytest

from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    _decode_describe_body,
    _skip_chunked_bytes,
    decode_packet,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    TNS_TYPE_NUMBER,
    TNS_TYPE_VARCHAR,
    TTI_DCB,
    TTI_STA,
)
from seerdb.server.query import (
    ColumnMeta,
    encode_describe,
    encode_rows,
    parse_exec,
    parse_exec_oci,
)


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
    from seerdb.common.tns import decode_token_oer
    from seerdb.server.query import encode_error

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    result = decode_token_oer(
        encode_error(942, 'ORA-00942: table or view does not exist'), (0, [], [])
    )
    assert result[1] == 942  # ErrCode
    assert 'ORA-00942' in result[5]  # Message


def test_more_rows_terminator_carries_cursor_id() -> None:
    from seerdb.common.tns import decode_token_oer
    from seerdb.server.query import encode_more_rows

    # The "more rows" status: call_status 1, no error, and the cursor id — what
    # the client's _drain_cursor keys on to issue follow-up TTI_FETCH calls.
    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    result = decode_token_oer(encode_more_rows(9), (0, [], []))
    assert result[0] == 1  # CallStatus
    assert result[1] == 0  # ErrCode (not 1403 — the cursor is not drained)
    assert result[2] == 9  # CursorId


def test_parse_fetch_extracts_cursor_and_count() -> None:
    from seerdb.common.tns import encode_dictionary_fetch
    from seerdb.server.query import parse_fetch

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
    from seerdb.server.query import _decode_describe_oci, encode_describe_oci

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
    from seerdb.server.query import _encode_dcb_column_oci

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

    from seerdb.server.query import _OCI_DCB_PREAMBLE_LEN, encode_describe_oci

    col = ColumnMeta(name=b'1', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)
    payload = encode_describe_oci([col])
    off = 1 + 4 + _OCI_DCB_PREAMBLE_LEN  # token + preamble-len + preamble
    assert struct.unpack('<I', payload[off : off + 4])[0] == 22


def test_encode_version_banner_oci_matches_the_captured_reply() -> None:
    # The sqlplus / thick-OCI version reply (TTI_RPA + banner DALC + packed
    # version trailer), byte-for-byte against a live 11.2 capture (#265).
    from seerdb.server.query import encode_version_banner_oci, is_version_call_oci

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
