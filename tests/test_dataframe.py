# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the Arrow / DataFrame bulk fetch (#162): build_table
reshapes buffered rows + a PEP 249 description into a pyarrow.Table."""

import datetime
import unittest
from decimal import Decimal

import pyarrow as pa

from oracle.dataframe import build_table
from oracle.tns_consts import (
    TNS_TYPE_DATE, TNS_TYPE_NUMBER, TNS_TYPE_RAW, TNS_TYPE_VARCHAR,
)


def _desc(name, type_code, scale=None):
    # (name, type_code, display_size, internal_size, precision, scale, null_ok)
    return (name, type_code, None, None, None, scale, True)


class TestBuildTable(unittest.TestCase):
    def test_column_major_and_types(self):
        desc = [_desc("ID", TNS_TYPE_NUMBER, 0),
                _desc("PRICE", TNS_TYPE_NUMBER, 2),
                _desc("NAME", TNS_TYPE_VARCHAR),
                _desc("DT", TNS_TYPE_DATE)]
        rows = [
            [1, Decimal("1.50"), "a", datetime.datetime(2026, 1, 1)],
            [2, Decimal("2.25"), "b", datetime.datetime(2026, 1, 2)],
        ]
        t = build_table(rows, desc)
        self.assertEqual(t.num_rows, 2)
        self.assertEqual(t.column_names, ["ID", "PRICE", "NAME", "DT"])
        self.assertEqual(t.column("ID").to_pylist(), [1, 2])
        self.assertEqual(t.column("NAME").to_pylist(), ["a", "b"])
        self.assertTrue(pa.types.is_integer(t.schema.field("ID").type))
        self.assertTrue(pa.types.is_timestamp(t.schema.field("DT").type))

    def test_empty_result_keeps_schema(self):
        desc = [_desc("ID", TNS_TYPE_NUMBER, 0),
                _desc("NAME", TNS_TYPE_VARCHAR),
                _desc("DATA", TNS_TYPE_RAW)]
        t = build_table([], desc)
        self.assertEqual(t.num_rows, 0)
        self.assertEqual(t.column_names, ["ID", "NAME", "DATA"])
        self.assertTrue(pa.types.is_integer(t.schema.field("ID").type))
        self.assertTrue(pa.types.is_string(t.schema.field("NAME").type))
        self.assertTrue(pa.types.is_binary(t.schema.field("DATA").type))

    def test_all_null_column_uses_fallback_type(self):
        desc = [_desc("N", TNS_TYPE_VARCHAR)]
        t = build_table([[None], [None]], desc)
        self.assertEqual(t.num_rows, 2)
        self.assertEqual(t.column("N").to_pylist(), [None, None])
        self.assertTrue(pa.types.is_string(t.schema.field("N").type))

    def test_mixed_int_and_decimal_number_column(self):
        # Oracle NUMBER decodes integer values to int and fractional to Decimal;
        # pyarrow unifies the column to decimal128.
        desc = [_desc("V", TNS_TYPE_NUMBER, 2)]
        t = build_table([[1], [Decimal("2.5")], [3]], desc)
        self.assertEqual([v for v in t.column("V").to_pylist()],
                         [Decimal("1.0"), Decimal("2.5"), Decimal("3.0")])


if __name__ == "__main__":
    unittest.main()
