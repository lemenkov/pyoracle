# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""#305: cursor.description is byte-for-byte oracledb-compatible.

_column_description turns a decoded DCB column dict into the PEP-249 7-tuple
  (name, type_code, display_size, internal_size, precision, scale, null_ok)
following python-oracledb's FetchInfo exactly. These cases pin the mapping with
synthetic Col dicts (the fields the DCB decode produces); the shapes were all
verified live against oracledb on 21c/23ai.
"""

from __future__ import annotations

import unittest

import seerdb
from seerdb.client.cursor import _column_description


def col(**kw) -> dict:
    base = {
        'column_name': 'C',
        'data_type': 2,
        'data_length': 0,
        'data_scale': 0,
        'precision': 0,
        'max_size': 0,
        'csfrm': 1,
        'null_ok': 1,
    }
    base.update(kw)
    return base


class TestColumnDescription(unittest.TestCase):
    def d(self, **kw):
        return _column_description(col(**kw))

    def test_type_code_is_the_dbtype_object(self):
        # PEP-249 §type_code: compares equal to the module's type objects.
        self.assertEqual(self.d(data_type=2)[1], seerdb.DB_TYPE_NUMBER)
        self.assertIs(self.d(data_type=2)[1], seerdb.DB_TYPE_NUMBER)

    def test_national_types_split_on_csfrm(self):
        self.assertEqual(self.d(data_type=1, csfrm=1)[1], seerdb.DB_TYPE_VARCHAR)
        self.assertEqual(self.d(data_type=1, csfrm=2)[1], seerdb.DB_TYPE_NVARCHAR)
        self.assertEqual(self.d(data_type=96, csfrm=1)[1], seerdb.DB_TYPE_CHAR)
        self.assertEqual(self.d(data_type=96, csfrm=2)[1], seerdb.DB_TYPE_NCHAR)
        self.assertEqual(self.d(data_type=112, csfrm=1)[1], seerdb.DB_TYPE_CLOB)
        self.assertEqual(self.d(data_type=112, csfrm=2)[1], seerdb.DB_TYPE_NCLOB)

    def test_number_precision_scale_and_display(self):
        # NUMBER(10,2): precision/scale reported; display = p + 1 + (scale + 1).
        self.assertEqual(
            self.d(data_type=2, precision=10, data_scale=2, data_length=22),
            ('C', seerdb.DB_TYPE_NUMBER, 14, None, 10, 2, True),
        )
        # NUMBER(10): scale 0 -> display = p + 1.
        self.assertEqual(
            self.d(data_type=2, precision=10, data_length=22)[2:6], (11, None, 10, 0)
        )
        # NUMBER(5,-2): negative scale is still "set" -> reported; display p + 1.
        self.assertEqual(
            self.d(data_type=2, precision=5, data_scale=-2)[2:6], (6, None, 5, -2)
        )
        # Unconstrained NUMBER: precision/scale None, display 127.
        self.assertEqual(
            self.d(data_type=2, data_length=22)[2:6], (127, None, None, None)
        )

    def test_char_and_raw_sizes(self):
        # VARCHAR2(10): display = internal = 10.
        self.assertEqual(
            self.d(data_type=1, max_size=10, data_length=10)[2:4], (10, 10)
        )
        # VARCHAR2(10 CHAR) on AL32UTF8: display 10 chars, internal 40 bytes.
        self.assertEqual(
            self.d(data_type=1, max_size=10, data_length=40)[2:4], (10, 40)
        )
        # RAW(100): size lives in the buffer (max_size 0) -> display/internal 100.
        self.assertEqual(
            self.d(data_type=23, max_size=0, data_length=100)[2:4], (100, 100)
        )

    def test_date_and_timestamp_display_is_23(self):
        for dt in (12, 180, 181, 231):
            with self.subTest(dt=dt):
                self.assertEqual(self.d(data_type=dt)[2:4], (23, None))

    def test_binary_float_display_is_127(self):
        self.assertEqual(self.d(data_type=100)[2:6], (127, None, None, None))
        self.assertEqual(self.d(data_type=101)[2:6], (127, None, None, None))

    def test_lob_rowid_have_no_sizes(self):
        # LOB / ROWID: no display or internal size, no precision/scale.
        for dt in (112, 113, 11):
            with self.subTest(dt=dt):
                self.assertEqual(
                    self.d(data_type=dt, data_length=4000)[2:6],
                    (None, None, None, None),
                )

    def test_null_ok_and_name_decoding(self):
        self.assertFalse(self.d(null_ok=0)[6])
        self.assertTrue(self.d(null_ok=1)[6])
        self.assertEqual(self.d(column_name=b'ID')[0], 'ID')


if __name__ == '__main__':
    unittest.main()
