# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Golden test: the OCI OER return-status trailers are now GENERATED from named
fields (seerdb.common.tns.encode_oci_oer) rather than stored as three
near-identical 136-byte blobs. The captures below (live 11g via sqlplus) pin the
generator byte-for-byte so the Mirror stays wire-identical to the real server.

The OER field map was reverse-engineered by controlled capture (docs/PROTOCOL.md
§36): connecting sqlplus through a logging proxy to 11g and varying one thing at
a time (rowcount, error, command type) to locate each field.
"""

import unittest

from seerdb.common.oci import (
    OCI_OER_ROW_KIND_LOB,
    OCI_OER_ROW_KIND_LONG,
    OCI_OER_STATUS_ERROR,
    OCI_OER_STATUS_SUCCESS,
)
from seerdb.common.tns import (
    _OCI_CMD_TYPE_OFF,
    _OCI_DML_ROWCOUNT_OFF,
    encode_changepassword_status_oci,
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
                OCI_OER_STATUS_SUCCESS, sequence=0x11, row_kind=OCI_OER_ROW_KIND_LONG
            ),
            LONG_FETCH_STATUS,
        )

    def test_lob_fetch_status(self):
        self.assertEqual(
            encode_oci_oer(
                OCI_OER_STATUS_SUCCESS, sequence=0x10, row_kind=OCI_OER_ROW_KIND_LOB
            ),
            LOB_FETCH_STATUS,
        )

    def test_error_oer_envelope(self):
        # the error path builds the same envelope with the code patched in at
        # offset 12 (ub4 LE), then appends the ORA-… message DALC.
        expected = bytearray(ERROR_OER)
        expected[12:16] = (942).to_bytes(4, 'little')
        # sequence=0x13 is the value the golden capture carried; passing it
        # reproduces the live 11g error reply byte-for-byte.
        got = encode_error_oci(942, 'table or view does not exist', sequence=0x13)
        self.assertEqual(got[:136], bytes(expected))

    def test_error_oer_status_and_code(self):
        oer = encode_oci_oer(
            OCI_OER_STATUS_ERROR, sequence=0x13, error_pos=0x0E, error_code=1017
        )
        self.assertEqual(oer[1], OCI_OER_STATUS_ERROR)
        self.assertEqual(int.from_bytes(oer[12:16], 'little'), 1017)
        self.assertEqual(len(oer), 136)

    def test_error_message_appended(self):
        got = encode_error_oci(942, 'table or view does not exist', sequence=0x13)
        self.assertEqual(
            got[136:], bytes([40]) + b'ORA-00942: table or view does not exist\n'
        )

    def test_sequence_echo_is_plus_two(self):
        # offset 49 echoes the sequence field + 2 (a derived internal field).
        oer = encode_oci_oer(OCI_OER_STATUS_SUCCESS, sequence=0x20)
        self.assertEqual(oer[5], 0x20)
        self.assertEqual(oer[49], 0x22)


class TestExecuteStatusGeneration(unittest.TestCase):
    """The DML/DDL execute-status replies are generated from one frame each,
    varying only the V$SQL command type (offset 57) and — for DML — the rowcount
    (offset 43). Validated live against sqlplus (see PROTOCOL.md §36)."""

    def test_dml_verbs_share_frame_and_carry_command_type(self):
        codes = {'INSERT': 2, 'UPDATE': 6, 'DELETE': 7}
        # sequence=19 is the captured DML value; a fixed sequence keeps the three
        # verbs' frames identical bar the command type.
        bodies = {kw: encode_dml_status_oci(kw, 5, sequence=19) for kw in codes}
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
        body = encode_dml_status_oci('UPDATE', 42, sequence=19)
        self.assertEqual(
            int.from_bytes(
                body[_OCI_DML_ROWCOUNT_OFF : _OCI_DML_ROWCOUNT_OFF + 4], 'little'
            ),
            42,
        )

    def test_dml_unknown_verb_falls_back_to_insert(self):
        self.assertEqual(
            encode_dml_status_oci('MERGE', 3, sequence=19),
            encode_dml_status_oci('INSERT', 3, sequence=19),
        )

    def test_ddl_verbs_share_frame_and_carry_command_type(self):
        create = encode_ddl_status_oci(1, sequence=17)  # CREATE TABLE
        drop = encode_ddl_status_oci(12, sequence=17)  # DROP TABLE
        self.assertEqual(create[_OCI_CMD_TYPE_OFF], 1)
        self.assertEqual(drop[_OCI_CMD_TYPE_OFF], 12)
        diffs = [i for i in range(len(create)) if create[i] != drop[i]]
        self.assertEqual(diffs, [_OCI_CMD_TYPE_OFF])

    def test_status_replies_carry_the_live_sequence(self):
        # The OER sequence is now a per-session counter threaded in, not a frozen
        # capture constant: a different sequence changes offset 5 (and its +2 echo
        # at offset 49) of the OER while the rest of the frame is unchanged. Tested
        # on the bare-OER error reply, whose OER starts at offset 0.
        a = encode_error_oci(942, 'x', sequence=0x13)[:136]
        b = encode_error_oci(942, 'x', sequence=0x14)[:136]
        self.assertEqual(a[5], 0x13)
        self.assertEqual(b[5], 0x14)
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        self.assertEqual(diffs, [5, 49])


class ChangePasswordStatusGolden(unittest.TestCase):
    # The OCIPasswordChange ("Password changed") reply, captured live from 11g
    # via sqlplus through a logging proxy — byte-identical across four separate
    # password changes in independent sessions, so the whole reply is a fixed
    # constant with no per-session counter (docs/PROTOCOL.md § 4.1.3 / §36.1).
    _CAPTURE = bytes.fromhex(
        '08000004050000001300010100000000000000000000000000000000000000000000000000000000000000000000000000000000160000010000003601000000000000000000000000000020f6310a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    )

    def test_matches_the_live_capture(self):
        self.assertEqual(encode_changepassword_status_oci(), self._CAPTURE)

    def test_is_the_shared_oer_envelope_plus_an_empty_rpa(self):
        # The reply is an empty RPA return envelope (08 00 00) + the shared OER
        # envelope: only six fixed bytes of the 136-byte OER body differ from it.
        from seerdb.common.tns import _OCI_OER_ENVELOPE

        reply = encode_changepassword_status_oci()
        self.assertEqual(reply[:3], bytes([8, 0, 0]))
        body = reply[3:]
        self.assertEqual(len(body), len(_OCI_OER_ENVELOPE))
        diffs = [i for i in range(len(body)) if body[i] != _OCI_OER_ENVELOPE[i]]
        self.assertEqual(diffs, [1, 5, 8, 18, 22, 49])


if __name__ == '__main__':
    unittest.main()
