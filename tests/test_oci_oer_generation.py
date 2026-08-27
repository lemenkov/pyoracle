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
    _OCI_CMD_TYPE_OFF,
    _OCI_DML_ROWCOUNT_OFF,
    _OCI_OER_ROW_KIND_LOB,
    _OCI_OER_ROW_KIND_LONG,
    _OCI_OER_STATUS_ERROR,
    _OCI_OER_STATUS_SUCCESS,
    encode_ddl_status_oci,
    encode_dml_status_oci,
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


class TestExecuteStatusGeneration(unittest.TestCase):
    """The DML/DDL execute-status replies are generated from one frame each,
    varying only the V$SQL command type (offset 57) and — for DML — the rowcount
    (offset 43). Validated live against sqlplus (see PROTOCOL.md §36)."""

    def test_dml_verbs_share_frame_and_carry_command_type(self):
        codes = {'INSERT': 2, 'UPDATE': 6, 'DELETE': 7}
        bodies = {kw: encode_dml_status_oci(kw, 5) for kw in codes}
        for kw, code in codes.items():
            self.assertEqual(bodies[kw][_OCI_CMD_TYPE_OFF], code)
            self.assertEqual(
                int.from_bytes(
                    bodies[kw][_OCI_DML_ROWCOUNT_OFF : _OCI_DML_ROWCOUNT_OFF + 4],
                    'little',
                ),
                5,
            )
        # all three differ only at the command-type and rowcount offsets
        ins = bodies['INSERT']
        for kw in ('UPDATE', 'DELETE'):
            diffs = [i for i in range(len(ins)) if ins[i] != bodies[kw][i]]
            self.assertEqual(diffs, [_OCI_CMD_TYPE_OFF])

    def test_dml_rowcount(self):
        body = encode_dml_status_oci('UPDATE', 42)
        self.assertEqual(
            int.from_bytes(
                body[_OCI_DML_ROWCOUNT_OFF : _OCI_DML_ROWCOUNT_OFF + 4], 'little'
            ),
            42,
        )

    def test_dml_unknown_verb_falls_back_to_insert(self):
        self.assertEqual(
            encode_dml_status_oci('MERGE', 3), encode_dml_status_oci('INSERT', 3)
        )

    def test_ddl_verbs_share_frame_and_carry_command_type(self):
        create = encode_ddl_status_oci(1)  # CREATE TABLE
        drop = encode_ddl_status_oci(12)  # DROP TABLE
        self.assertEqual(create[_OCI_CMD_TYPE_OFF], 1)
        self.assertEqual(drop[_OCI_CMD_TYPE_OFF], 12)
        diffs = [i for i in range(len(create)) if create[i] != drop[i]]
        self.assertEqual(diffs, [_OCI_CMD_TYPE_OFF])


if __name__ == '__main__':
    unittest.main()
