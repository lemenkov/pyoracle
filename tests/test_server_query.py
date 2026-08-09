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
from seerdb.server.query import ColumnMeta, encode_describe, encode_rows, parse_exec


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
