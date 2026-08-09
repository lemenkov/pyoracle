# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the Arrow / DataFrame bulk fetch (#162): build_table
reshapes buffered rows + a PEP 249 description into a pyarrow.Table."""

import datetime
import unittest
from decimal import Decimal

import pyarrow as pa

from seerdb.dataframe import _explicit_type, build_table
from seerdb.tns_consts import (
    TNS_TYPE_BFLOAT,
    TNS_TYPE_DATE,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
)


def _desc(name, type_code, scale=None, precision=None):
    # (name, type_code, display_size, internal_size, precision, scale, null_ok)
    return (name, type_code, None, None, precision, scale, True)


class TestBuildTable(unittest.TestCase):
    def test_column_major_and_types(self):
        desc = [
            _desc('ID', TNS_TYPE_NUMBER, 0),
            _desc('PRICE', TNS_TYPE_NUMBER, 2),
            _desc('NAME', TNS_TYPE_VARCHAR),
            _desc('DT', TNS_TYPE_DATE),
        ]
        rows = [
            [1, Decimal('1.50'), 'a', datetime.datetime(2026, 1, 1)],
            [2, Decimal('2.25'), 'b', datetime.datetime(2026, 1, 2)],
        ]
        t = build_table(rows, desc)
        self.assertEqual(t.num_rows, 2)
        self.assertEqual(t.column_names, ['ID', 'PRICE', 'NAME', 'DT'])
        self.assertEqual(t.column('ID').to_pylist(), [1, 2])
        self.assertEqual(t.column('NAME').to_pylist(), ['a', 'b'])
        self.assertTrue(pa.types.is_integer(t.schema.field('ID').type))
        self.assertTrue(pa.types.is_timestamp(t.schema.field('DT').type))

    def test_empty_result_keeps_schema(self):
        desc = [
            _desc('ID', TNS_TYPE_NUMBER, 0),
            _desc('NAME', TNS_TYPE_VARCHAR),
            _desc('DATA', TNS_TYPE_RAW),
        ]
        t = build_table([], desc)
        self.assertEqual(t.num_rows, 0)
        self.assertEqual(t.column_names, ['ID', 'NAME', 'DATA'])
        self.assertTrue(pa.types.is_integer(t.schema.field('ID').type))
        self.assertTrue(pa.types.is_string(t.schema.field('NAME').type))
        self.assertTrue(pa.types.is_binary(t.schema.field('DATA').type))

    def test_all_null_column_uses_fallback_type(self):
        desc = [_desc('N', TNS_TYPE_VARCHAR)]
        t = build_table([[None], [None]], desc)
        self.assertEqual(t.num_rows, 2)
        self.assertEqual(t.column('N').to_pylist(), [None, None])
        self.assertTrue(pa.types.is_string(t.schema.field('N').type))

    def test_mixed_int_and_decimal_number_column(self):
        # Oracle NUMBER decodes integer values to int and fractional to Decimal;
        # pyarrow unifies the column to decimal128.
        desc = [_desc('V', TNS_TYPE_NUMBER, 2)]
        t = build_table([[1], [Decimal('2.5')], [3]], desc)
        self.assertEqual(
            [v for v in t.column('V').to_pylist()],
            [Decimal('1.0'), Decimal('2.5'), Decimal('3.0')],
        )

    def test_explicit_type_mapping(self):
        # The exact Arrow type derived from the describe metadata (#190).
        self.assertEqual(
            _explicit_type(TNS_TYPE_NUMBER, 10, 2), pa.decimal128(10, 2)
        )  # NUMBER(10,2) -> Decimal
        self.assertEqual(_explicit_type(TNS_TYPE_NUMBER, 8, 0), pa.int64())
        self.assertEqual(_explicit_type(TNS_TYPE_BFLOAT, None, None), pa.float32())
        self.assertEqual(_explicit_type(TNS_TYPE_VARCHAR, None, None), pa.string())
        self.assertEqual(_explicit_type(TNS_TYPE_RAW, None, None), pa.binary())
        self.assertEqual(_explicit_type(TNS_TYPE_DATE, None, None), pa.timestamp('us'))
        # Unconstrained NUMBER (no precision / -127 scale marker), a >18-digit
        # integer, and TZ-aware timestamps stay on inference (None).
        self.assertIsNone(_explicit_type(TNS_TYPE_NUMBER, None, None))
        self.assertIsNone(_explicit_type(TNS_TYPE_NUMBER, 0, -127))
        self.assertIsNone(_explicit_type(TNS_TYPE_NUMBER, 20, 0))
        self.assertIsNone(_explicit_type(TNS_TYPE_TIMESTAMPTZ, None, None))

    def test_constrained_number_uses_explicit_decimal128(self):
        # NUMBER(10,2) -> decimal128(10,2) directly (skips inference), with
        # NULLs and Decimals of varying stored scale rescaled to fit.
        desc = [_desc('P', TNS_TYPE_NUMBER, 2, 10)]
        t = build_table(
            [[Decimal('5')], [Decimal('1380.5')], [None], [Decimal('-7.25')]], desc
        )
        self.assertEqual(t.schema.field('P').type, pa.decimal128(10, 2))
        self.assertEqual(
            t.column('P').to_pylist(),
            [Decimal('5.00'), Decimal('1380.50'), None, Decimal('-7.25')],
        )

    def test_constrained_integer_uses_int64(self):
        desc = [_desc('I', TNS_TYPE_NUMBER, 0, 8)]
        t = build_table([[5], [-7], [None]], desc)
        self.assertEqual(t.schema.field('I').type, pa.int64())
        self.assertEqual(t.column('I').to_pylist(), [5, -7, None])


if __name__ == '__main__':
    unittest.main()
