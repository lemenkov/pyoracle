# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for native BFILE TTI_LOBOPS encoding (#46).

A BFILE is read natively over TTI_LOBOPS — FILE_OPEN -> READ -> FILE_CLOSE —
rather than through a PL/SQL helper. These pin the request bytes reverse-
engineered from python-oracledb on 21c (docs/PROTOCOL.md §14); no server needed.
"""

import unittest

from seerdb.tns import encode_dictionary_lobops
from seerdb.tns_consts import (
    TNS_LOB_OP_FILE_CLOSE,
    TNS_LOB_OP_FILE_OPEN,
    TNS_LOB_OP_READ,
)

# The 54-byte BFILE locator body (no leading ub2 length) captured on 21c for
# DIRECTORY "PYO_BFILE_DIR" / file "pyoracle_bfile_test.txt".
LOC = bytes.fromhex(
    '0001080800000001000000000000000d50594f5f4246494c455f4449'
    '52001770796f7261636c655f6266696c655f746573742e747874'
)


class BfileLobopsEncode(unittest.TestCase):
    def test_file_open(self):
        # op 0x0100; amount pointer set with the read-only mode (sb4 0x0B);
        # source offset 0; ub2-prefixed locator (declared length + 2).
        Out = encode_dictionary_lobops(
            {'seq': 6, 'operation': TNS_LOB_OP_FILE_OPEN, 'locator': LOC}
        )
        self.assertEqual(
            Out.hex(),
            '0360060101380000000000000002010000000000010000000000000036'
            + LOC.hex()
            + '010b',
        )

    def test_file_close(self):
        # op 0x0200; no amount, no trailing data.
        Out = encode_dictionary_lobops(
            {'seq': 8, 'operation': TNS_LOB_OP_FILE_CLOSE, 'locator': LOC}
        )
        self.assertEqual(
            Out.hex(),
            '0360080101380000000000000002020000000000000000000000000036' + LOC.hex(),
        )

    def test_read_prefixed(self):
        # The READ of an opened BFILE reuses the READ opcode with the
        # ub2-prefixed locator form (source offset 1, amount 0xFFFFFFFF).
        Out = encode_dictionary_lobops(
            {
                'seq': 7,
                'operation': TNS_LOB_OP_READ,
                'locator': LOC,
                'locator_prefixed': True,
                'amount': 0xFFFFFFFF,
            }
        )
        self.assertEqual(
            Out.hex(),
            '0360070101380000000000000001020000010100010000000000000036'
            + LOC.hex()
            + '04ffffffff',
        )


if __name__ == '__main__':
    unittest.main()
