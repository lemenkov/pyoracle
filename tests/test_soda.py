# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the SODA layer (#163, #199): the pure helpers and the
18c+ gate. The live collection round-trips are in test_integration.py."""

import unittest

from oracle.exceptions import NotSupportedError
from oracle.soda import (_check_soda_supported, _names_query, _norm_metadata)


class _FakeConn:
    def __init__(self, major):
        self.server_version = major << 24


class TestSodaHelpers(unittest.TestCase):
    def test_norm_metadata(self):
        self.assertIsNone(_norm_metadata(None))
        self.assertEqual(_norm_metadata('{"a":1}'), '{"a":1}')   # str passthrough
        self.assertEqual(_norm_metadata({"a": 1}), '{"a": 1}')   # dict -> JSON

    def test_names_query_variants(self):
        sql, binds = _names_query(None, 0)
        self.assertNotIn("WHERE", sql)
        self.assertNotIn("FETCH", sql)
        self.assertEqual(binds, [])

        sql, binds = _names_query("abc", 0)
        self.assertIn("uri_name >= :start_name", sql)
        self.assertEqual(binds, ["abc"])

        sql, binds = _names_query(None, 5)
        self.assertIn("FETCH FIRST 5 ROWS ONLY", sql)
        self.assertEqual(binds, [])

        sql, _ = _names_query("abc", 3)
        self.assertIn("uri_name >= :start_name", sql)
        self.assertIn("FETCH FIRST 3 ROWS ONLY", sql)
        # ordered, and ':start' (reserved word) is never used as a bind name
        self.assertIn("ORDER BY uri_name", sql)
        self.assertNotIn(":start ", sql)

    def test_soda_gate(self):
        # SODA needs an 18c+ server (DBMS_SODA).
        for major in (9, 10, 11, 12):
            with self.assertRaises(NotSupportedError):
                _check_soda_supported(_FakeConn(major))
        for major in (18, 19, 21, 23):
            _check_soda_supported(_FakeConn(major))   # no raise


if __name__ == "__main__":
    unittest.main()
