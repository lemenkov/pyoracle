# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for request pipelining (#132). The wire fixtures are from a real
# 23ai (23.26) capture of python-oracledb running an async pipeline through the
# logging proxy. The live pipeline flow is covered on 23ai (and the serial
# fallback on older tiers) in the integration suite.

import unittest

import oracle
from oracle.pipeline import Pipeline, PipelineOpType, create_pipeline
from oracle.tns import _fun_header, encode_pipeline_begin, encode_pipeline_end
from oracle.tns_consts import (
    TNS_PIPELINE_MODE_ABORT_ON_ERROR, TNS_PIPELINE_MODE_CONTINUE_ON_ERROR,
)


class TestPipelineApi(unittest.TestCase):
    def test_create_and_add(self):
        p = create_pipeline()
        self.assertIsInstance(p, Pipeline)
        p.add_execute("insert into t values (1)")
        p.add_executemany("insert into t values (:1)", [(1,), (2,)])
        p.add_fetchone("select 1 from dual")
        p.add_fetchmany("select * from t", num_rows=5)
        p.add_fetchall("select * from t")
        p.add_commit()
        p.add_callproc("myproc", [1, 2])
        p.add_callfunc("myfunc", oracle.NUMBER, [3])
        types = [op.op_type for op in p.operations]
        self.assertEqual(types, [
            PipelineOpType.EXECUTE, PipelineOpType.EXECUTE_MANY,
            PipelineOpType.FETCH_ONE, PipelineOpType.FETCH_MANY,
            PipelineOpType.FETCH_ALL, PipelineOpType.COMMIT,
            PipelineOpType.CALL_PROC, PipelineOpType.CALL_FUNC])

    def test_op_carries_fields(self):
        p = create_pipeline()
        op = p.add_fetchmany("select x from t", [42], num_rows=7)
        self.assertEqual(op.statement, "select x from t")
        self.assertEqual(op.parameters, [42])
        self.assertEqual(op.num_rows, 7)

    def test_exported_from_package(self):
        self.assertIs(oracle.create_pipeline, create_pipeline)
        self.assertTrue(hasattr(oracle, "Pipeline"))
        self.assertTrue(hasattr(oracle, "PipelineOpResult"))


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
