# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Golden test: the OCI OER return-status trailers are now GENERATED from named
fields (seerdb.server.query.encode_oci_oer) rather than stored as three
near-identical 136-byte blobs. The captures below (live 11g via sqlplus) pin the
generator byte-for-byte so the Mirror stays wire-identical to the real server.

The OER field map was reverse-engineered by controlled capture (docs/PROTOCOL.md
§36): connecting sqlplus through a logging proxy to 11g and varying one thing at
a time (rowcount, error, command type) to locate each field.
"""

import unittest

from seerdb.server.query import (
    _OCI_OER_ROW_KIND_LOB,
    _OCI_OER_ROW_KIND_LONG,
    _OCI_OER_STATUS_ERROR,
    _OCI_OER_STATUS_SUCCESS,
    encode_error_oci,
    encode_oci_oer,
)

# --- captured golden OER records (live 11g) ---
ERROR_OER = bytes.fromhex(
    '04050000001300010000000000000000000002000e00030000000000000000000000'
    '00000000000000000000000000000015000001000000360100000000000000000000'
    '0000000020f6310a0000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000'
)
LONG_FETCH_STATUS = bytes.fromhex(
    '04010000001100010200000000000000000002000000030000000000000000000000'
    '00000000000000000000000000000013000001000000360100000000000000000000'
    '0000000020f6310a0000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000'
)
LOB_FETCH_STATUS = bytes.fromhex(
    '04010000001000010100000000000000000002000000030000000000000000000000'
    '00000000000000000000000000000012000001000000360100000000000000000000'
    '0000000020f6310a0000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000'
)


class TestOciOerGeneration(unittest.TestCase):
    def test_long_fetch_status(self):
        self.assertEqual(
            encode_oci_oer(
                _OCI_OER_STATUS_SUCCESS, sequence=0x11, row_kind=_OCI_OER_ROW_KIND_LONG
            ),
            LONG_FETCH_STATUS,
        )

    def test_lob_fetch_status(self):
        self.assertEqual(
            encode_oci_oer(
                _OCI_OER_STATUS_SUCCESS, sequence=0x10, row_kind=_OCI_OER_ROW_KIND_LOB
            ),
            LOB_FETCH_STATUS,
        )

    def test_error_oer_envelope(self):
        # the error path builds the same envelope with the code patched in at
        # offset 12 (ub4 LE), then appends the ORA-… message DALC.
        expected = bytearray(ERROR_OER)
        expected[12:16] = (942).to_bytes(4, 'little')
        got = encode_error_oci(942, 'table or view does not exist')
        self.assertEqual(got[:136], bytes(expected))

    def test_error_oer_status_and_code(self):
        oer = encode_oci_oer(
            _OCI_OER_STATUS_ERROR, sequence=0x13, error_pos=0x0E, error_code=1017
        )
        self.assertEqual(oer[1], _OCI_OER_STATUS_ERROR)
        self.assertEqual(int.from_bytes(oer[12:16], 'little'), 1017)
        self.assertEqual(len(oer), 136)

    def test_error_message_appended(self):
        got = encode_error_oci(942, 'table or view does not exist')
        self.assertEqual(
            got[136:], bytes([40]) + b'ORA-00942: table or view does not exist\n'
        )

    def test_sequence_echo_is_plus_two(self):
        # offset 49 echoes the sequence field + 2 (a derived internal field).
        oer = encode_oci_oer(_OCI_OER_STATUS_SUCCESS, sequence=0x20)
        self.assertEqual(oer[5], 0x20)
        self.assertEqual(oer[49], 0x22)


if __name__ == '__main__':
    unittest.main()
