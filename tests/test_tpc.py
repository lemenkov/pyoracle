# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for two-phase commit / XA (#131): the Xid, the switch /
# change-state request encoders, and the response decoders. The full
# begin/prepare/commit/rollback flow is covered live on 21c/23ai.

import unittest

from oracle.connection import Xid, _decode_tpc_context, _decode_tpc_state
from oracle.tns import (
    _ENCODE_FIELD_VERSION, encode_tpc_switch, encode_tpc_change_state,
)
from oracle.tns_consts import (
    TTI_FUN, TNS_FUNC_TPC_TXN_SWITCH, TNS_FUNC_TPC_TXN_CHANGE_STATE,
    TNS_TPC_TXN_START, TNS_TPC_TXN_PREPARE,
)


class TestXid(unittest.TestCase):
    def test_namedtuple(self):
        x = Xid(100, b"gtrid", b"bqual")
        self.assertEqual((x.format_id, x[1], x[2]), (100, b"gtrid", b"bqual"))


class TestEncode(unittest.TestCase):
    def setUp(self):
        _ENCODE_FIELD_VERSION.set(16)

    def tearDown(self):
        _ENCODE_FIELD_VERSION.set(6)

    def test_switch_header_and_xid_padding(self):
        out = encode_tpc_switch(5, 16, TNS_TPC_TXN_START,
                                Xid(100, b"gtrid", b"bqual"), 1, 0, None)
        self.assertEqual(out[0], TTI_FUN)
        self.assertEqual(out[1], TNS_FUNC_TPC_TXN_SWITCH)   # 103
        # the xid (gtrid+bqual) zero-padded to 128 bytes is present
        self.assertIn(b"gtridbqual" + bytes(128 - 10), out)

    def test_change_state_header(self):
        out = encode_tpc_change_state(6, 16, TNS_TPC_TXN_PREPARE, 0,
                                      Xid(100, b"g", b"b"), 0, b"ctx")
        self.assertEqual(out[0], TTI_FUN)
        self.assertEqual(out[1], TNS_FUNC_TPC_TXN_CHANGE_STATE)  # 104
        self.assertIn(b"ctx", out)                          # context replayed


class TestDecode(unittest.TestCase):
    # Shape of a live tpc_begin response (21c/11g identical): RPA token (08),
    # application value (ub4 0), context length (ub2 0xa8 = 168), 168 context
    # bytes (carrying the xid "g1b1"), then the STATUS tail.
    _CTX = bytes(32) + b"g1b1" + bytes(168 - 36)
    _BEGIN = bytes([0x08, 0x00, 0x01, 0xa8]) + _CTX + bytes.fromhex("0901030104")

    def test_decode_context(self):
        ctx = _decode_tpc_context(self._BEGIN)
        self.assertEqual(len(ctx), 168)
        self.assertIn(b"g1b1", ctx)

    def test_decode_state(self):
        # RPA (08) + ub4 state. State 1 -> "01 01".
        self.assertEqual(_decode_tpc_state(bytes.fromhex("080101")), 1)
        self.assertEqual(_decode_tpc_state(bytes.fromhex("080104")), 4)


if __name__ == "__main__":
    unittest.main()
