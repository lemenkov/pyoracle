# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for implicit result sets (#121, DBMS_SQL.RETURN_RESULT).
#
# The token-27 message bytes were captured from a live 21c (fv16) block
#   DECLARE c SYS_REFCURSOR;
#   BEGIN OPEN c FOR SELECT id, name FROM t; DBMS_SQL.RETURN_RESULT(c); END;
# It carries one implicit result (columns ID, NAME) plus the block's trailing
# RPA/OER.

import unittest

from oracle.cursor import _extract_implicit_results
from oracle.tns import _DECODE_FIELD_VERSION, decode_packet

# A full token-27 (0x1b) response: num_results=1, the ID/NAME describe, a
# cursor id, then the block's RPA + OER (ORA-0).
_TOK27 = bytes.fromhex(
    '1b010100012a01025c0200008101160000000000000000010201020249440000000001'
    '800000011400000000020369010114023ffe01040104044e414d450000010100010707'
    '601075ef8d7f000101021fe80000000107080106033b1a650001040102000000000004'
    '010502f05201010000000104002f000000000003013f71010c00023d560000000b0001'
    '0100000000000101012f00'
)


class TestImplicitDecode(unittest.TestCase):
    def tearDown(self):
        # decode_packet sets the decode field-version ContextVar; restore the
        # module default so the value (16, here) can't leak into later tests.
        _DECODE_FIELD_VERSION.set(6)

    def test_decode_token_27(self):
        # fv16 (12c+ column layout) routed via decode_packet.
        Result = decode_packet(_TOK27, (None, None, []), 16)
        sets = _extract_implicit_results(Result)
        self.assertEqual(len(sets), 1)
        (row_format, cursor_id) = sets[0]
        self.assertEqual([c['column_name'] for c in row_format], [b'ID', b'NAME'])
        self.assertGreater(cursor_id, 0)


class TestExtractImplicitResults(unittest.TestCase):
    def test_extracts_record(self):
        rec = {
            'implicit_results': [
                {'cursor_id': 5, 'row_format': [{'column_name': b'A'}]},
                {'cursor_id': 6, 'row_format': [{'column_name': b'B'}]},
            ]
        }
        result = (None, None, None, None, [rec])
        sets = _extract_implicit_results(result)
        self.assertEqual(
            [(rf[0]['column_name'], cid) for rf, cid in sets], [(b'A', 5), (b'B', 6)]
        )

    def test_no_implicit_results(self):
        self.assertEqual(_extract_implicit_results((0, 0, 1, None, [])), [])
        self.assertEqual(_extract_implicit_results((0, 0, 1, None, [[1, 2]])), [])


if __name__ == '__main__':
    unittest.main()
