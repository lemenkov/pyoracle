# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for DML RETURNING ... INTO (#120): the return-bind detection,
# the out-bind return-data decode, and the per-Var assignment.
#
# The wire bytes mirror what a live server sends (TTI_RXD carrying, per return
# bind, a ub4 row count then each row's length-prefixed value + an sb4
# truncation length), verified against 10g/11g/21c/23ai.

import unittest

from seerdb.cursor import (
    _assign_return_binds,
    _returning_bind_positions,
)
from seerdb.datatypes import Var
from seerdb.tns import decode_token_rxd, set_decode_return_binds
from seerdb.tns_consts import TTI_STA


class TestReturningDetection(unittest.TestCase):
    def test_insert_returning_into(self):
        sql = 'INSERT INTO t VALUES (:1, :2) RETURNING id INTO :3'
        self.assertEqual(_returning_bind_positions(sql, 3), frozenset({2}))

    def test_multiple_return_binds(self):
        sql = 'UPDATE t SET n=:1 WHERE id=:2 RETURNING id, n INTO :3, :4'
        self.assertEqual(_returning_bind_positions(sql, 4), frozenset({2, 3}))

    def test_all_return_no_input(self):
        sql = "INSERT INTO t VALUES (1, 'x') RETURNING name INTO :1"
        self.assertEqual(_returning_bind_positions(sql, 1), frozenset({0}))

    def test_not_returning(self):
        self.assertEqual(
            _returning_bind_positions('INSERT INTO t VALUES (:1)', 1), frozenset()
        )
        # the INSERT's own INTO must not be mistaken for a RETURNING INTO
        self.assertEqual(
            _returning_bind_positions('INSERT INTO t (a) VALUES (:1)', 1), frozenset()
        )

    def test_returning_in_string_literal_ignored(self):
        sql = "UPDATE t SET note = 'returning into x' WHERE id = :1"
        self.assertEqual(_returning_bind_positions(sql, 1), frozenset())


# A TTI_RXD (0x07) carrying return data for two binds: NUMBER 42 and VARCHAR
# 'hi', one row each, then a TTI_STA to end the response.
_RXD_TWO = (
    bytes([7])
    + bytes.fromhex('0101')
    + bytes.fromhex('02')
    + bytes.fromhex('c12b')
    + bytes.fromhex('00')
    + bytes.fromhex('0101')
    + bytes.fromhex('02')
    + b'hi'
    + bytes.fromhex('00')
    + bytes([TTI_STA])
)

# One NUMBER bind, two rows (multi-row DML RETURNING): 42 then 43.
_RXD_MULTI = (
    bytes([7])
    + bytes.fromhex('0102')  # num_rows = 2
    + bytes.fromhex('02')
    + bytes.fromhex('c12b')
    + bytes.fromhex('00')
    + bytes.fromhex('02')
    + bytes.fromhex('c12c')
    + bytes.fromhex('00')
    + bytes([TTI_STA])
)


class TestReturningDecode(unittest.TestCase):
    def tearDown(self):
        set_decode_return_binds(None)

    def _decode(self, data, positions):
        set_decode_return_binds(positions)
        (Done, Acc) = decode_token_rxd(data, (None, None, []))
        self.assertTrue(Done)
        return Acc[2][0]  # the return record

    def test_two_binds_single_row(self):
        rec = self._decode(_RXD_TWO, [0, 1])
        self.assertEqual(rec['return_positions'], [0, 1])
        self.assertEqual(rec['return_values'][0], [b'\xc1\x2b'])
        self.assertEqual(rec['return_values'][1], [b'hi'])

    def test_multi_row(self):
        rec = self._decode(_RXD_MULTI, [0])
        self.assertEqual(rec['return_values'][0], [b'\xc1\x2b', b'\xc1\x2c'])

    def test_assign_decodes_by_var_type(self):
        rec = self._decode(_RXD_TWO, [1, 2])  # binds at positions 1 and 2
        result = (None, None, None, None, [rec])
        bind = ['input', Var(int), Var(str)]
        _assign_return_binds(bind, result)
        self.assertEqual(bind[1].getvalue(), [42])
        self.assertEqual(bind[2].getvalue(), ['hi'])


if __name__ == '__main__':
    unittest.main()
