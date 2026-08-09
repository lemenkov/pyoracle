# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for request pipelining (#132). The wire fixtures are from a real
# 23ai (23.26) capture of python-oracledb running an async pipeline through the
# logging proxy. The live pipeline flow is covered on 23ai (and the serial
# fallback on older tiers) in the integration suite.

import unittest

import seerdb
from seerdb.client.pipeline import Pipeline, PipelineOpType, create_pipeline
from seerdb.common.tns import (
    _fun_header,
    encode_data_packet,
    encode_dictionary,
    encode_pipeline_begin,
    encode_pipeline_end,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_23_4,
    TNS_DATA,
    TNS_DATA_FLAGS_BEGIN_PIPELINE,
    TNS_DATA_FLAGS_END_OF_REQUEST,
    TNS_PIPELINE_MODE_ABORT_ON_ERROR,
    TNS_PIPELINE_MODE_CONTINUE_ON_ERROR,
    DictionaryType,
)


def _exec_bytes(token_num, seq=0x0B, fv=FIELD_VERSION_23_4):
    # Build one pipelined execute's request bytes (no cursor cache), as
    # OracleConnect._encode_pipeline_op does for op number `token_num`.
    Dict = {
        'type': DictionaryType.exec,
        'seq': seq,
        'field_version': fv,
        'env': {'user': 'pyo'},
        'token_num': token_num,
        'query': {
            'type': 'change',
            'auto': 1,
            'fetch': 15,
            'server_version': 0,
            'cursor': 0,
            'query': 'INSERT INTO t VALUES (1)',
            'bind': [],
            'batch': [],
            'def': [],
            'batcherrors': False,
            'arraydmlrowcounts': False,
            'return_binds': None,
        },
    }
    return encode_dictionary(Dict)


class TestPipelineApi(unittest.TestCase):
    def test_create_and_add(self):
        p = create_pipeline()
        self.assertIsInstance(p, Pipeline)
        p.add_execute('insert into t values (1)')
        p.add_executemany('insert into t values (:1)', [(1,), (2,)])
        p.add_fetchone('select 1 from dual')
        p.add_fetchmany('select * from t', num_rows=5)
        p.add_fetchall('select * from t')
        p.add_commit()
        p.add_callproc('myproc', [1, 2])
        p.add_callfunc('myfunc', seerdb.NUMBER, [3])
        types = [op.op_type for op in p.operations]
        self.assertEqual(
            types,
            [
                PipelineOpType.EXECUTE,
                PipelineOpType.EXECUTE_MANY,
                PipelineOpType.FETCH_ONE,
                PipelineOpType.FETCH_MANY,
                PipelineOpType.FETCH_ALL,
                PipelineOpType.COMMIT,
                PipelineOpType.CALL_PROC,
                PipelineOpType.CALL_FUNC,
            ],
        )

    def test_op_carries_fields(self):
        p = create_pipeline()
        op = p.add_fetchmany('select x from t', [42], num_rows=7)
        self.assertEqual(op.statement, 'select x from t')
        self.assertEqual(op.parameters, [42])
        self.assertEqual(op.num_rows, 7)

    def test_exported_from_package(self):
        self.assertIs(seerdb.create_pipeline, create_pipeline)
        self.assertTrue(hasattr(seerdb, 'Pipeline'))
        self.assertTrue(hasattr(seerdb, 'PipelineOpResult'))


class TestTokenFraming(unittest.TestCase):
    def test_token_zero_unchanged(self):
        # An ordinary (non-pipelined) call carries token 0 — the historical
        # single zero byte after the sequence number at fv24.
        self.assertEqual(_fun_header(0x5E, 8, 24, 0), bytes([3, 0x5E, 8, 0]))

    def test_token_zero_default(self):
        self.assertEqual(_fun_header(0x5E, 8, 24), bytes([3, 0x5E, 8, 0]))

    def test_pipelined_token(self):
        # A pipelined call numbers itself 1..N (encode_sb4 form).
        self.assertEqual(_fun_header(0x5E, 8, 24, 1).hex(), '035e080101')
        self.assertEqual(_fun_header(0x5E, 9, 24, 2).hex(), '035e090102')

    def test_pre23ai_has_no_token(self):
        self.assertEqual(_fun_header(0x5E, 8, 6, 1), bytes([3, 0x5E, 8]))


class TestTokenDecode(unittest.TestCase):
    def test_token_marker_consumed(self):
        # A pipelined op response is prefixed with TOKEN (33) + ub8 token; the
        # decoder consumes it and decodes the body (here STATUS + EOR). The
        # marker decode is field-version-independent, so don't perturb the
        # shared _DECODE_FIELD_VERSION context (it would leak into later tests).
        from seerdb.common.tns import decode_packet

        data = bytes.fromhex('210101') + bytes.fromhex('0903010005024be9') + bytes([29])
        self.assertEqual(
            decode_packet(data, (None, None, [])), (True, (None, None, []))
        )


class TestPipelineEncoders(unittest.TestCase):
    def test_begin_matches_capture(self):
        # C2S begin-pipeline piggyback: seq 0x07, token 1, ABORT mode (2).
        self.assertEqual(
            encode_pipeline_begin(0x07, 24, 1, TNS_PIPELINE_MODE_ABORT_ON_ERROR).hex(),
            '11c7070101000002',
        )

    def test_begin_continue_mode(self):
        out = encode_pipeline_begin(0x07, 24, 1, TNS_PIPELINE_MODE_CONTINUE_ON_ERROR)
        self.assertEqual(out[-1], TNS_PIPELINE_MODE_CONTINUE_ON_ERROR)

    def test_end_matches_capture(self):
        # C2S PIPELINE_END (func 200), seq 0x0c.
        self.assertEqual(encode_pipeline_end(0x0C, 24).hex(), '03c80c0000')


class TestExecTokenThreading(unittest.TestCase):
    def test_token_num_only_changes_token_field(self):
        # Threading token_num through encode_dictionary_exec (#158) must touch
        # only the ub8 token in the function header — nothing else moves.
        # _fun_header at fv24: TTI_FUN(03) ALL8(5e) seq(0b) then encode_sb4(tok).
        zero = _exec_bytes(0)  # encode_sb4(0) == b"\x00" (1 byte)
        one = _exec_bytes(1)  # encode_sb4(1) == b"\x01\x01" (2 bytes)
        two = _exec_bytes(2)  # encode_sb4(2) == b"\x01\x02"
        self.assertEqual(zero[:3], one[:3])
        self.assertEqual(zero[3], 0x00)
        self.assertEqual(zero[4:], one[5:])  # bodies identical past token
        # token 1 vs 2 are equal length and differ only in the final token byte.
        self.assertEqual(len(one), len(two))
        self.assertEqual(one[:4], two[:4])
        self.assertEqual(one[4], 0x01)
        self.assertEqual(two[4], 0x02)
        self.assertEqual(one[5:], two[5:])


class TestDataPacketEncoder(unittest.TestCase):
    def test_data_flags_in_header(self):
        # A pipelined first packet carries BEGIN_PIPELINE | END_OF_REQUEST in
        # the 2-byte data-flags field after the 10-byte large-SDU header.
        body = bytes.fromhex('11c70a0101000001')
        flags = TNS_DATA_FLAGS_BEGIN_PIPELINE | TNS_DATA_FLAGS_END_OF_REQUEST
        pkt = encode_data_packet(body, flags, Large=True)
        # large header: ub4 length, type, flags, 2-byte cksum, then dataflags.
        self.assertEqual(int.from_bytes(pkt[0:4], 'big'), len(body) + 10)
        self.assertEqual(pkt[4], TNS_DATA)
        self.assertEqual(int.from_bytes(pkt[8:10], 'big'), 0x1800)
        self.assertEqual(pkt[10:], body)

    def test_end_of_request_flag(self):
        pkt = encode_data_packet(
            b'\x03\x5e\x0c', TNS_DATA_FLAGS_END_OF_REQUEST, Large=True
        )
        self.assertEqual(int.from_bytes(pkt[8:10], 'big'), 0x0800)


if __name__ == '__main__':
    unittest.main()
