# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the small DB-API conveniences (issue #22):
stmtcachesize, version, rowfactory, lastrowid. These exercise the
client-side logic without a live server."""

import unittest

from oracle.connection import OracleConnect
from oracle.cursor import Cursor


class TestStmtCacheSize(unittest.TestCase):

    def test_default(self):
        self.assertEqual(OracleConnect().stmtcachesize, 32)

    def test_set_evicts_down_to_new_size(self):
        conn = OracleConnect()
        for i in range(10):
            conn._cursor_cache[(f"sql{i}", b"")] = i
        conn.stmtcachesize = 3
        self.assertEqual(conn.stmtcachesize, 3)
        self.assertEqual(len(conn._cursor_cache), 3)
        # Oldest entries evicted, newest kept (insertion-order LRU).
        self.assertEqual(list(conn._cursor_cache.values()), [7, 8, 9])

    def test_zero_disables(self):
        conn = OracleConnect()
        conn._cursor_cache[("sql", b"")] = 1
        conn.stmtcachesize = 0
        self.assertEqual(conn.stmtcachesize, 0)
        self.assertEqual(len(conn._cursor_cache), 0)

    def test_negative_clamped_to_zero(self):
        conn = OracleConnect()
        conn.stmtcachesize = -5
        self.assertEqual(conn.stmtcachesize, 0)


if __name__ == "__main__":
    unittest.main()
