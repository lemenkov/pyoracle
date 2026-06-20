# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for request pipelining (#132). The wire fixtures are from a real
# 23ai (23.26) capture of python-oracledb running an async pipeline through the
# logging proxy. The live pipeline flow is covered on 23ai (and the serial
# fallback on older tiers) in the integration suite.

import unittest

from oracle.tns import _fun_header, encode_pipeline_begin, encode_pipeline_end
from oracle.tns_consts import (
    TNS_PIPELINE_MODE_ABORT_ON_ERROR, TNS_PIPELINE_MODE_CONTINUE_ON_ERROR,
)


class TestTokenFraming(unittest.TestCase):
    def test_token_zero_unchanged(self):
        # An ordinary (non-pipelined) call carries token 0 — the historical
        # single zero byte after the sequence number at fv24.
        self.assertEqual(_fun_header(0x5e, 8, 24, 0),
                         bytes([3, 0x5e, 8, 0]))

    def test_token_zero_default(self):
        self.assertEqual(_fun_header(0x5e, 8, 24), bytes([3, 0x5e, 8, 0]))

    def test_pipelined_token(self):
        # A pipelined call numbers itself 1..N (encode_sb4 form).
        self.assertEqual(_fun_header(0x5e, 8, 24, 1).hex(), "035e080101")
        self.assertEqual(_fun_header(0x5e, 9, 24, 2).hex(), "035e090102")

    def test_pre23ai_has_no_token(self):
        self.assertEqual(_fun_header(0x5e, 8, 6, 1), bytes([3, 0x5e, 8]))


class TestPipelineEncoders(unittest.TestCase):
    def test_begin_matches_capture(self):
        # C2S begin-pipeline piggyback: seq 0x07, token 1, ABORT mode (2).
        self.assertEqual(
            encode_pipeline_begin(0x07, 24, 1,
                                  TNS_PIPELINE_MODE_ABORT_ON_ERROR).hex(),
            "11c7070101000002")

    def test_begin_continue_mode(self):
        out = encode_pipeline_begin(0x07, 24, 1,
                                    TNS_PIPELINE_MODE_CONTINUE_ON_ERROR)
        self.assertEqual(out[-1], TNS_PIPELINE_MODE_CONTINUE_ON_ERROR)

    def test_end_matches_capture(self):
        # C2S PIPELINE_END (func 200), seq 0x0c.
        self.assertEqual(encode_pipeline_end(0x0c, 24).hex(), "03c80c0000")


if __name__ == "__main__":
    unittest.main()
