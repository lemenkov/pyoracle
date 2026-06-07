# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the small DB-API conveniences (issue #22):
stmtcachesize, version, rowfactory, lastrowid. These exercise the
client-side logic without a live server."""

import types
import unittest

from oracle.connection import OracleConnect
from oracle.cursor import Cursor


def _stub_cursor(rows, description=None):
    # A Cursor whose _check_open() passes without a live socket, pre-loaded
    # with already-fetched rows.
    cur = Cursor(types.SimpleNamespace(sock=object()))
    cur._rows = rows
    cur._description = description or [("X", None, None, None, None, None, True)]
    cur._row_index = 0
    return cur


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


class TestRowFactory(unittest.TestCase):

    def test_default_is_tuple(self):
        cur = _stub_cursor([[1, "a"]])
        self.assertEqual(cur.fetchone(), (1, "a"))

    def test_called_with_positional_columns(self):
        cur = _stub_cursor([[1, "a"], [2, "b"]],
                           description=[("ID", None, None, None, None, None, True),
                                        ("NAME", None, None, None, None, None, True)])
        cur.rowfactory = lambda i, n: {"id": i, "name": n}
        self.assertEqual(cur.fetchall(),
                         [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}])

    def test_applies_through_iteration(self):
        cur = _stub_cursor([[1], [2], [3]])
        cur.rowfactory = lambda x: x * 10
        self.assertEqual(list(cur), [10, 20, 30])


class _StubConn:
    # Minimal stand-in for OracleConnect: _run only needs .sock (for
    # _check_open) and .execute returning a wire-shaped result tuple.
    sock = object()

    def __init__(self, result):
        self._result = result

    def execute(self, operation, Bind=None, Batch=None):
        return self._result


class TestLastRowid(unittest.TestCase):
    # Wire result tuple shape: (call_status, ora_code, cursor_id,
    # (rowcount, col_meta), rows, message, lastrowid)

    def test_dml_sets_rowid(self):
        dml = (0, 0, 1, (1, None), [], None, "AAAB12AAEAAAAGPAAA")
        cur = Cursor(_StubConn(dml))
        cur.execute("INSERT INTO t VALUES (1)")
        self.assertEqual(cur.lastrowid, "AAAB12AAEAAAAGPAAA")

    def test_select_clears_rowid(self):
        cur = Cursor(_StubConn((0, 0, 1, (1, None), [], None, "AAAB12AAEAAAAGPAAA")))
        cur.execute("INSERT INTO t VALUES (1)")
        self.assertIsNotNone(cur.lastrowid)
        # A subsequent SELECT (result set) must clear it.
        cur._connection = _StubConn(
            (0, 0, 1, (0, [{"column_name": "ID"}]), [[1]], None, None))
        cur.execute("SELECT id FROM t")
        self.assertIsNone(cur.lastrowid)

    def test_ddl_no_rowid(self):
        ddl = (0, 0, 1, (0, None), [], None, None)
        cur = Cursor(_StubConn(ddl))
        cur.execute("CREATE TABLE t (id NUMBER)")
        self.assertIsNone(cur.lastrowid)


class TestVersion(unittest.TestCase):

    def test_none_before_auth(self):
        self.assertIsNone(OracleConnect().version)

    def test_decodes_xe_11g(self):
        conn = OracleConnect()
        conn.server_version = 0x0b200200   # 186647040, as XE 11.2.0.2.0 sends
        self.assertEqual(conn.version, "11.2.0.2.0")


if __name__ == "__main__":
    unittest.main()
