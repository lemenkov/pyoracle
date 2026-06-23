# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

from functools import reduce
from oracle.tns import capability_arrays
from oracle.tns import encode_dictionary
from oracle.tns import encode_dictionary_auth
from oracle.tns import encode_dictionary_close
from oracle.tns import encode_dictionary_description
from oracle.tns import encode_dictionary_dty
from oracle.tns import encode_dictionary_exec
from oracle.tns import encode_dictionary_login
from oracle.tns import encode_dictionary_pig
from oracle.tns import encode_dictionary_sess
from oracle.tns import encode_dictionary_tran
from oracle.tns import encode_packet
from oracle.tns_consts import DictionaryType, TNS_CONNECT, TNS_DATA
from unittest.mock import patch
import unittest

class TestTnsCommandEncoders(unittest.TestCase):

    def test_tns_encode_packet_connect(self):
        Type = TNS_CONNECT
        Data = bytes([1,57,1,44,0,0,32,0,255,255,79,152,0,0,0,1,0,144,0,58,0,0,0,0,132,132,0,
       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,40,68,69,83,67,82,73,80,
       84,73,79,78,61,40,67,79,78,78,69,67,84,95,68,65,84,65,61,40,83,73,68,61,
       88,69,41,40,67,73,68,61,40,80,82,79,71,82,65,77,61,106,97,109,100,98,
       116,101,115,116,41,40,72,79,83,84,61,69,120,97,109,112,108,101,72,111,
       115,116,41,40,85,83,69,82,61,115,121,115,116,101,109,41,41,41,40,65,68,
       68,82,69,83,83,61,40,80,82,79,84,79,67,79,76,61,84,67,80,41,40,72,79,83,
       84,61,108,111,99,97,108,104,111,115,116,41,40,80,79,82,84,61,49,53,50,
       49,41,41,41])
        Sdu = 8192
        Ret = bytes([0,202,0,0,1,0,0,0,1,57,1,44,0,0,32,0,255,255,79,152,0,0,0,1,0,144,0,58,0,0,
   0,0,132,132,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,40,68,69,83,67,
   82,73,80,84,73,79,78,61,40,67,79,78,78,69,67,84,95,68,65,84,65,61,40,83,73,
   68,61,88,69,41,40,67,73,68,61,40,80,82,79,71,82,65,77,61,106,97,109,100,98,
   116,101,115,116,41,40,72,79,83,84,61,69,120,97,109,112,108,101,72,111,115,
   116,41,40,85,83,69,82,61,115,121,115,116,101,109,41,41,41,40,65,68,68,82,69,
   83,83,61,40,80,82,79,84,79,67,79,76,61,84,67,80,41,40,72,79,83,84,61,108,
   111,99,97,108,104,111,115,116,41,40,80,79,82,84,61,49,53,50,49,41,41,41])
        self.assertEqual(encode_packet(Type, Data, Sdu), (Ret, None))

    def test_tns_encode_packet_data(self):
        Type = TNS_DATA
        Data = bytes([2,103,3,103,3,1,38,6,1,0,0,106,1,1,6,1,1,1,1,1,1,0,41,144,3,7,3,0,1,
           0,79,1,55,4,0,0,0,0,12,0,0,6,0,1,1,7,2,0,0,0,0,0,0,1,1,1,0,2,2,1,0,
           4,4,1,0,5,5,1,0,6,6,1,0,7,7,1,0,8,8,1,0,9,9,1,0,10,10,1,0,11,11,1,0,
           12,12,1,0,13,13,1,0,14,14,1,0,15,15,1,0,16,16,1,0,17,17,1,0,18,18,1,
           0,19,19,1,0,20,20,1,0,21,21,1,0,22,22,1,0,23,23,1,0,24,24,1,0,25,25,
           1,0,26,26,1,0,27,27,1,0,28,28,1,0,29,29,1,0,30,30,1,0,31,31,1,0,32,
           32,1,0,33,33,1,0,34,34,1,0,35,35,1,0,36,36,1,0,37,37,1,0,38,38,1,0,
           40,40,1,0,41,41,1,0,42,42,1,0,43,43,1,0,44,44,1,0,45,45,1,0,46,46,1,
           0,47,47,1,0,48,48,1,0,49,49,1,0,50,50,1,0,51,51,1,0,52,52,1,0,53,53,
           1,0,54,54,1,0,55,55,1,0,56,56,1,0,57,57,1,0,59,59,1,0,60,60,1,0,61,
           61,1,0,62,62,1,0,63,63,1,0,64,64,1,0,65,65,1,0,66,66,1,0,67,67,1,0,
           68,68,1,0,69,69,1,0,70,70,1,0,71,71,1,0,72,72,1,0,73,73,1,0,75,75,1,
           0,77,77,1,0,78,78,1,0,79,79,1,0,80,80,1,0,81,81,1,0,82,82,1,0,83,83,
           1,0,84,84,1,0,85,85,1,0,86,86,1,0,87,87,1,0,88,88,1,0,89,89,1,0,90,
           90,1,0,92,92,1,0,93,93,1,0,98,98,1,0,99,99,1,0,100,100,1,0,101,101,
           1,0,102,102,1,0,103,103,1,0,106,106,1,0,107,107,1,0,109,109,1,0,111,
           111,1,0,112,112,1,0,113,113,1,0,114,114,1,0,115,115,1,0,117,117,1,0,
           120,120,1,0,124,124,1,0,125,125,1,0,126,126,1,0,127,127,1,0,128,128,
           1,0,129,129,1,0,130,130,1,0,131,131,1,0,132,132,1,0,133,133,1,0,134,
           134,1,0,135,135,1,0,137,137,1,0,138,138,1,0,139,139,1,0,140,140,1,0,
           141,141,1,0,142,142,1,0,143,143,1,0,144,144,1,0,145,145,1,0,148,148,
           1,0,149,149,1,0,150,150,1,0,151,151,1,0,157,157,1,0,158,158,1,0,159,
           159,1,0,160,160,1,0,161,161,1,0,162,162,1,0,163,163,1,0,164,164,1,0,
           165,165,1,0,166,166,1,0,167,167,1,0,168,168,1,0,169,169,1,0,170,170,
           1,0,171,171,1,0,173,173,1,0,174,174,1,0,175,175,1,0,176,176,1,0,177,
           177,1,0,178,178,1,0,179,179,1,0,180,180,1,0,181,181,1,0,182,182,1,0,
           183,183,1,0,193,193,1,0,194,194,1,0,208,208,1,0,231,231,1,0,233,233,
           1,0,245,245,1,0,2,2,10,0,3,2,10,0,4,2,10,0,5,1,1,0,6,2,10,0,7,2,10,
           0,9,1,1,0,12,12,10,0,13,0,14,0,15,23,1,0,16,0,17,0,18,0,19,0,20,0,
           21,0,22,0,39,120,1,0,58,0,68,2,10,0,69,0,70,0,74,0,76,0,91,2,10,0,
           94,1,1,0,95,23,1,0,96,96,1,0,97,96,1,0,104,11,1,0,105,0,108,109,1,0,
           110,111,1,0,116,102,1,0,118,0,119,0,121,0,122,0,123,0,136,0,146,146,
           1,0,147,0,152,2,10,0,153,2,10,0,154,2,10,0,155,1,1,0,156,12,10,0,
           172,2,10,0,209,0,3,0,0])
        Sdu = 8192
        Ret = bytes([3,92,0,0,6,0,0,0,0,0,2,103,3,103,3,1,38,6,1,0,0,106,1,1,6,1,1,1,1,1,1,0,41,
   144,3,7,3,0,1,0,79,1,55,4,0,0,0,0,12,0,0,6,0,1,1,7,2,0,0,0,0,0,0,1,1,1,0,2,
   2,1,0,4,4,1,0,5,5,1,0,6,6,1,0,7,7,1,0,8,8,1,0,9,9,1,0,10,10,1,0,11,11,1,0,
   12,12,1,0,13,13,1,0,14,14,1,0,15,15,1,0,16,16,1,0,17,17,1,0,18,18,1,0,19,19,
   1,0,20,20,1,0,21,21,1,0,22,22,1,0,23,23,1,0,24,24,1,0,25,25,1,0,26,26,1,0,
   27,27,1,0,28,28,1,0,29,29,1,0,30,30,1,0,31,31,1,0,32,32,1,0,33,33,1,0,34,34,
   1,0,35,35,1,0,36,36,1,0,37,37,1,0,38,38,1,0,40,40,1,0,41,41,1,0,42,42,1,0,
   43,43,1,0,44,44,1,0,45,45,1,0,46,46,1,0,47,47,1,0,48,48,1,0,49,49,1,0,50,50,
   1,0,51,51,1,0,52,52,1,0,53,53,1,0,54,54,1,0,55,55,1,0,56,56,1,0,57,57,1,0,
   59,59,1,0,60,60,1,0,61,61,1,0,62,62,1,0,63,63,1,0,64,64,1,0,65,65,1,0,66,66,
   1,0,67,67,1,0,68,68,1,0,69,69,1,0,70,70,1,0,71,71,1,0,72,72,1,0,73,73,1,0,
   75,75,1,0,77,77,1,0,78,78,1,0,79,79,1,0,80,80,1,0,81,81,1,0,82,82,1,0,83,83,
   1,0,84,84,1,0,85,85,1,0,86,86,1,0,87,87,1,0,88,88,1,0,89,89,1,0,90,90,1,0,
   92,92,1,0,93,93,1,0,98,98,1,0,99,99,1,0,100,100,1,0,101,101,1,0,102,102,1,0,
   103,103,1,0,106,106,1,0,107,107,1,0,109,109,1,0,111,111,1,0,112,112,1,0,113,
   113,1,0,114,114,1,0,115,115,1,0,117,117,1,0,120,120,1,0,124,124,1,0,125,125,
   1,0,126,126,1,0,127,127,1,0,128,128,1,0,129,129,1,0,130,130,1,0,131,131,1,0,
   132,132,1,0,133,133,1,0,134,134,1,0,135,135,1,0,137,137,1,0,138,138,1,0,139,
   139,1,0,140,140,1,0,141,141,1,0,142,142,1,0,143,143,1,0,144,144,1,0,145,145,
   1,0,148,148,1,0,149,149,1,0,150,150,1,0,151,151,1,0,157,157,1,0,158,158,1,0,
   159,159,1,0,160,160,1,0,161,161,1,0,162,162,1,0,163,163,1,0,164,164,1,0,165,
   165,1,0,166,166,1,0,167,167,1,0,168,168,1,0,169,169,1,0,170,170,1,0,171,171,
   1,0,173,173,1,0,174,174,1,0,175,175,1,0,176,176,1,0,177,177,1,0,178,178,1,0,
   179,179,1,0,180,180,1,0,181,181,1,0,182,182,1,0,183,183,1,0,193,193,1,0,194,
   194,1,0,208,208,1,0,231,231,1,0,233,233,1,0,245,245,1,0,2,2,10,0,3,2,10,0,4,
   2,10,0,5,1,1,0,6,2,10,0,7,2,10,0,9,1,1,0,12,12,10,0,13,0,14,0,15,23,1,0,16,
   0,17,0,18,0,19,0,20,0,21,0,22,0,39,120,1,0,58,0,68,2,10,0,69,0,70,0,74,0,76,
   0,91,2,10,0,94,1,1,0,95,23,1,0,96,96,1,0,97,96,1,0,104,11,1,0,105,0,108,109,
   1,0,110,111,1,0,116,102,1,0,118,0,119,0,121,0,122,0,123,0,136,0,146,146,1,0,
   147,0,152,2,10,0,153,2,10,0,154,2,10,0,155,1,1,0,156,12,10,0,172,2,10,0,209,
   0,3,0,0])
        self.assertEqual(encode_packet(Type, Data, Sdu), (Ret, None))

class TestTnsCommandEncodersDict(unittest.TestCase):

    def test_tns_close_0(self):
        Dict = {'type' : DictionaryType.close, 'seq' : 7}
        self.assertEqual(encode_dictionary(Dict), bytes([3, 9, 7]))

    def test_tns_close_1(self):
        Dict = {'type' : DictionaryType.close, 'seq' : 7}
        self.assertEqual(encode_dictionary_close(Dict), bytes([3, 9, 7]))

    def test_tns_pig_0(self):
        Dict = {'type' : DictionaryType.pig, 'req' : 105, 'cursor' : [1], 'seq' : 13}
        self.assertEqual(encode_dictionary(Dict), bytes([17,105,13,1,1,1,1,1]))

    def test_tns_pig_1(self):
        Dict = {'type' : DictionaryType.pig, 'req' : 105, 'cursor' : [1], 'seq' : 13}
        self.assertEqual(encode_dictionary_pig(Dict), bytes([17,105,13,1,1,1,1,1]))

    def test_tns_dty_0(self):
        Dict = {'type' : DictionaryType.dty, 'req' : 'utf-8'}
        Wtf0 = bytes([38,6,1,0,0,106,1,1,6,1,1,1,1,1,1,0,41,144,3,7,3,0,1,0,79,1,55,4,0,0,0,0,12,0,0,6,0,1,1])
        Wtf1 = bytes([7,2,0,0,0,0,0,0])
        Wtf2 = bytes(reduce(lambda y, z: y + z, [[]] + [ [x, x, 1, 0] for x in range(1,246)]))
        Wtf3 = bytes([
                2,2,10,0,3,2,10,0,4,2,10,0,5,1,1,0,6,2,10,0,7,2,10,0,9,1,1,0,12,12,10,0,13,0,14,0,15,
                23,1,0,16,0,17,0,18,0,19,0,20,0,21,0,22,0,39,120,1,0,58,0,68,2,10,0,69,0,70,0,74,0,
                6,0,91,2,10,0,94,1,1,0,95,23,1,0,96,96,1,0,97,96,1,0,104,11,1,0,105,0,108,109,1,0,
                110,111,1,0,116,102,1,0,118,0,119,0,121,0,122,0,123,0,136,0,146,146,1,0,147,0,
                152,2,10,0,153,2,10,0,154,2,10,0,155,1,1,0,156,12,10,0,172,2,10,0,209,0,3,0,0
        ])
        # AL32UTF8 (873) little-endian — pyoracle advertises real UTF-8, not
        # Oracle's legacy "UTF8" (871) which is CESU-8 and mangles supplementary
        # characters (emoji etc.). See encode_dictionary_dty.
        Charset = bytes([105,3])
        self.assertEqual(encode_dictionary(Dict), bytes([2]) + Charset + Charset + bytes([1]) + Wtf0 + Wtf1 + Wtf2 + Wtf3)

    def test_tns_dty_1(self):
        Dict = {'type' : DictionaryType.dty, 'req' : 'utf-8'}
        Wtf0 = bytes([38,6,1,0,0,106,1,1,6,1,1,1,1,1,1,0,41,144,3,7,3,0,1,0,79,1,55,4,0,0,0,0,12,0,0,6,0,1,1])
        Wtf1 = bytes([7,2,0,0,0,0,0,0])
        Wtf2 = bytes(reduce(lambda y, z: y + z, [[]] + [ [x, x, 1, 0] for x in range(1,246)]))
        Wtf3 = bytes([
                2,2,10,0,3,2,10,0,4,2,10,0,5,1,1,0,6,2,10,0,7,2,10,0,9,1,1,0,12,12,10,0,13,0,14,0,15,
                23,1,0,16,0,17,0,18,0,19,0,20,0,21,0,22,0,39,120,1,0,58,0,68,2,10,0,69,0,70,0,74,0,
                6,0,91,2,10,0,94,1,1,0,95,23,1,0,96,96,1,0,97,96,1,0,104,11,1,0,105,0,108,109,1,0,
                110,111,1,0,116,102,1,0,118,0,119,0,121,0,122,0,123,0,136,0,146,146,1,0,147,0,
                152,2,10,0,153,2,10,0,154,2,10,0,155,1,1,0,156,12,10,0,172,2,10,0,209,0,3,0,0
        ])
        Charset = bytes([105,3])               # AL32UTF8 (873) LE; see test_tns_dty_0
        self.assertEqual(encode_dictionary_dty(Dict), bytes([2]) + Charset + Charset + bytes([1]) + Wtf0 + Wtf1 + Wtf2 + Wtf3)

    def test_capability_arrays_11_2(self):
        # The default (11.2) capability vectors must stay byte-identical to the
        # historical pyoracle 11g handshake (this is what test_tns_dty_* pin).
        from oracle.tns import FIELD_VERSION_11_2
        cc, rc = capability_arrays()
        self.assertEqual(cc, bytes([
            6,1,0,0,106,1,1,6,1,1,1,1,1,1,0,41,144,3,7,3,0,1,0,79,1,55,4,0,0,0,0,
            12,0,0,6,0,1,1]))
        self.assertEqual(rc, bytes([2,0,0,0,0,0,0]))
        self.assertEqual(capability_arrays(FIELD_VERSION_11_2), (cc, rc))

    def test_capability_arrays_21_1(self):
        # The 21.1 vectors must match python-oracledb 4.0.1 captured against
        # Oracle 21c XE (issue #27 Phase 0 reference bytes).
        from oracle.tns import FIELD_VERSION_21_1
        cc, rc = capability_arrays(FIELD_VERSION_21_1)
        self.assertEqual(cc.hex(),
            "06000000ea180010010100000000002990030703000100cf00"
            "0004010000001000000c2000b80008440005003e0200000000000003")
        self.assertEqual(rc.hex(), "0200000000000500000000")
        # field version lands at the documented slot
        self.assertEqual(cc[7], FIELD_VERSION_21_1)

    def test_capability_arrays_intermediate(self):
        # An intermediate 12c+ version (e.g. 19.1 = 12) renders the 21.1 base
        # vector with the field-version byte patched in, so the client can
        # negotiate down to any 12c+ server.
        from oracle.tns import FIELD_VERSION_19_1, FIELD_VERSION_21_1
        cc19, _ = capability_arrays(FIELD_VERSION_19_1)
        cc21, _ = capability_arrays(FIELD_VERSION_21_1)
        self.assertEqual(cc19[7], FIELD_VERSION_19_1)
        self.assertEqual(len(cc19), len(cc21))            # same 53-byte base
        self.assertEqual(cc19[:7], cc21[:7])
        self.assertEqual(cc19[8:], cc21[8:])              # only byte 7 differs
        with self.assertRaises(ValueError):
            capability_arrays(999)

    @patch('os.getpid')
    @patch('socket.gethostname')
    def test_tns_sess_12c(self, mock_gethostname, mock_getpid):
        # 12c+ OSESSKEY: 5 key/value pairs led by AUTH_TERMINAL, and the
        # username is length-prefixed (3, "pyo") rather than raw.
        from oracle.tns import FIELD_VERSION_21_1
        mock_getpid.return_value = 18967
        mock_gethostname.return_value = "ExampleHost"
        Env = {'host': "localhost", 'port': 1521, 'user': "pyo",
               'password': "p", 'sid': "XE", 'app_name': "oratest"}
        Dict = {'type': DictionaryType.sess, 'env': Env, 'seq': 3,
                'field_version': FIELD_VERSION_21_1}
        Ret = bytes([3,118,3,1,1,3,1,1,1,1,5,1,1,3,112,121,111,
            1,13,13,65,85,84,72,95,84,69,82,77,73,78,65,76,1,7,7,117,110,107,
            110,111,119,110,0,1,15,15,65,85,84,72,95,80,82,79,71,82,65,77,95,
            78,77,1,7,7,111,114,97,116,101,115,116,0,1,12,12,65,85,84,72,95,77,
            65,67,72,73,78,69,1,11,11,69,120,97,109,112,108,101,72,111,115,116,
            0,1,8,8,65,85,84,72,95,80,73,68,1,5,5,49,56,57,54,55,0,1,8,8,65,85,
            84,72,95,83,73,68,1,3,3,112,121,111,0])
        self.assertEqual(encode_dictionary(Dict), Ret)

    def test_bind_oac_12c(self):
        # The 12c+ bind OAC (encode_token_raw) follows oracledb's
        # _write_column_metadata: flag byte 1, ub8 cont-flag, OID/version, the
        # bind charset as a ub2 (AL32UTF8 for char), csfrm, LOB-prefetch length,
        # and a trailing oaccolid. 11g uses a different, shorter layout. Run in
        # a copied context so the encode field-version ContextVar doesn't leak.
        import contextvars
        from oracle.tns import (encode_token_raw, _ENCODE_FIELD_VERSION,
                                FIELD_VERSION_21_1, FIELD_VERSION_11_2)
        from oracle.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
        UTF8 = 871
        def gen(fv, *a):
            ctx = contextvars.copy_context()
            def run():
                _ENCODE_FIELD_VERSION.set(fv)
                return encode_token_raw(*a)
            return ctx.run(run)
        # 11g unchanged
        self.assertEqual(gen(FIELD_VERSION_11_2, TNS_TYPE_NUMBER, 22, 0, 0, 0).hex(),
                         "02030000011600000000000100")
        # 12c NUMBER and VARCHAR layouts
        self.assertEqual(gen(FIELD_VERSION_21_1, TNS_TYPE_NUMBER, 22, 0, 0, 0).hex(),
                         "0201000001160000000000000000")
        self.assertEqual(gen(FIELD_VERSION_21_1, TNS_TYPE_VARCHAR, 20, 16, UTF8, 0).hex(),
                         "01010000011400000000020369010000")

    def test_dty_table_12c(self):
        # The 12c+ datatype table must stay byte-identical to python-oracledb
        # 4.0.1's DATA_TYPES table captured against 21c (sha256 of the rendered
        # bytes), with 321 uniform UB2x4 entries and a UB2 0 terminator.
        import hashlib, struct
        from oracle.tns import _datatype_table_12c
        Table = _datatype_table_12c()
        self.assertEqual(len(Table), 2570)
        self.assertEqual((len(Table) - 2) // 8, 321)
        self.assertEqual(Table[-2:], bytes([0, 0]))
        self.assertEqual(struct.unpack(">HHHH", Table[8:16])[:3], (2, 2, 10))  # NUMBER
        self.assertEqual(
            hashlib.sha256(Table).hexdigest(),
            "11c8d115ab493105252bbf8927f7d4b62dc864b358bfa0cf700af1b7d76aa492")

    def test_dty_12c_message_shape(self):
        # field_version 21.1 selects the 2-byte table and encoding flag 3
        # (oracledb's MULTI_BYTE|CONV_LENGTH); 11.2 keeps flag 1.
        from oracle.tns import FIELD_VERSION_21_1
        Dict = {'type': DictionaryType.dty, 'req': 'utf-8'}
        self.assertEqual(encode_dictionary_dty(Dict)[5], 1)
        Dict21 = dict(Dict, field_version=FIELD_VERSION_21_1)
        self.assertEqual(encode_dictionary_dty(Dict21)[5], 3)

    def test_exec_select_fv24_vs_legacy(self):
        # Full execute message for `SELECT 1 FROM dual` (no binds). The fv24 form
        # was captured byte-for-byte from a live 23ai server (and the server
        # accepts it). It differs from the legacy 12c+ form in exactly the four
        # fv24 spots (#89): the extra pointer byte after the seq, options
        # 0x8021->0x8061, the prefetch-buffer-size 0xffffffff->0, and
        # al8i4[9] 0->0x8000.
        from oracle.tns_consts import FIELD_VERSION_21_1, FIELD_VERSION_23_4

        def gen(fv):
            Dict = {'type': DictionaryType.exec, 'seq': 7, 'field_version': fv,
                    'env': {'user': 'pyo'},
                    'query': {'type': 'select', 'auto': 0, 'fetch': 15,
                              'server_version': 0, 'cursor': 0,
                              'query': 'SELECT 1 FROM dual', 'bind': [],
                              'batch': [], 'def': [], 'batcherrors': False,
                              'arraydmlrowcounts': False}}
            return encode_dictionary(Dict)

        Fv24 = "035e07000280610001011201010d000000010f047fffffff0000000000000000000000010000000000000000000000000000001253454c45435420312046524f4d206475616c0101000000000000010100028000000000"
        Fv16 = "035e070280210001011201010d000004ffffffff010f047fffffff0000000000000000000000010000000000000000000000000000001253454c45435420312046524f4d206475616c010100000000000001010000000000"
        self.assertEqual(gen(FIELD_VERSION_23_4).hex(), Fv24)
        self.assertEqual(gen(FIELD_VERSION_21_1).hex(), Fv16)
        # fv24 inserts the pointer byte (0) right after the sequence number;
        # legacy has the options word there instead.
        self.assertEqual(gen(FIELD_VERSION_23_4)[3], 0)
        self.assertNotEqual(gen(FIELD_VERSION_21_1)[3], 0)

    def test_fun_header_fv24_extra_pointer(self):
        # 23ai (fv > 17, #89) appends one extra pointer byte after the sequence
        # number on every function message; the legacy form (fv <= 17) does not.
        from oracle.tns import (_fun_header, FIELD_VERSION_23_1,
                                FIELD_VERSION_11_2, TTI_FUN)
        from oracle.tns_consts import (FIELD_VERSION_23_4, TTI_ALL8, TTI_FETCH,
                                       TTI_COMMIT)
        for Token in (TTI_ALL8, TTI_FETCH, TTI_COMMIT):
            self.assertEqual(_fun_header(Token, 5, FIELD_VERSION_11_2),
                             bytes([TTI_FUN, Token, 5]))
            self.assertEqual(_fun_header(Token, 5, FIELD_VERSION_23_1),
                             bytes([TTI_FUN, Token, 5]))
            self.assertEqual(_fun_header(Token, 5, FIELD_VERSION_23_4),
                             bytes([TTI_FUN, Token, 5, 0]))

    def _scroll_query(self, **over):
        Q = {'type': 'select', 'auto': 0, 'fetch': 2, 'server_version': 0,
             'cursor': 0, 'query': '', 'bind': [], 'batch': [], 'def': [],
             'batcherrors': False, 'arraydmlrowcounts': False,
             'return_binds': None, 'scrollable': False, 'scroll': None}
        Q.update(over)
        return Q

    def _scroll_exec(self, query, seq=7):
        from oracle.tns_consts import FIELD_VERSION_23_4
        return encode_dictionary({'type': DictionaryType.exec, 'seq': seq,
                                  'field_version': FIELD_VERSION_23_4,
                                  'env': {'user': 'pyo'},
                                  'query': query}).hex()

    def test_exec_scrollable_open(self):
        # Server-side scrollable open (#181): cursor 0 + SQL + scroll CURRENT/1.
        # Keeps the fv24 query options 0x8061 (NOT_PLSQL|FETCH|EXECUTE|PARSE) and
        # carries the scroll request in the al8i4 tail: al8i4[9]=0x8082
        # (0x8000 fv24 flag | NO_CANCEL_ON_EOF 0x80 | SCROLLABLE 0x02),
        # al8i4[10]=orientation CURRENT (0x01), al8i4[11]=position 1. Byte-for-byte
        # against a live 23ai oracledb-thin capture.
        from oracle.tns_consts import TNS_FETCH_ORIENTATION_CURRENT
        Hex = self._scroll_exec(self._scroll_query(
            query='SELECT id FROM scroll_demo ORDER BY id',
            scrollable=True, scroll=(TNS_FETCH_ORIENTATION_CURRENT, 1)))
        self.assertEqual(Hex,
            "035e07000280610001012601010d0000000102047fffffff000000000000"
            "0000000000010000000000000000000000000000002653454c4543542069"
            "642046524f4d207363726f6c6c5f64656d6f204f524445522042592069640"
            "1010000000000000101000280820101010100")
        self.assertIn("028061", Hex)                 # FETCH|EXECUTE|PARSE
        self.assertTrue(Hex.endswith("0280820101010100"))

    def test_exec_scroll_reexecute(self):
        # Scroll re-execute (#181): open cursor (id 100), empty query, ABSOLUTE 5.
        # Two things differ from the open: the exec options are 0x8040
        # (NOT_PLSQL|FETCH only — the EXECUTE 0x20 bit is cleared so the server
        # scrolls instead of re-running the query), and the empty query emits NO
        # length-prefixed SQL byte (a stray 0x00 there shifts the al8i4 array and
        # the server rejects the call as malformed, ORA-03137 [12316]). al8i4 tail
        # is ABSOLUTE (0x20) / position 5. Byte-for-byte against a 23ai capture.
        from oracle.tns_consts import TNS_FETCH_ORIENTATION_ABSOLUTE
        Hex = self._scroll_exec(self._scroll_query(
            cursor=100, query='', scrollable=True,
            scroll=(TNS_FETCH_ORIENTATION_ABSOLUTE, 5)))
        self.assertEqual(Hex,
            "035e07000280400164000001010d0000000102047fffffff000000000000"
            "00000000000100000000000000000000000000000000010200000000000101"
            "000280820120010500")
        self.assertIn("028040", Hex)                 # FETCH only, EXECUTE cleared
        self.assertNotIn("028060", Hex)              # would be EXECUTE|FETCH
        self.assertTrue(Hex.endswith("0280820120010500"))

    def test_exec_scroll_reexecute_omits_empty_sql_byte(self):
        # The empty-query re-execute (#181) must be exactly one byte shorter than
        # the same frame would be with a zero-length SQL prefix — that stray 0x00
        # was the ORA-03137 [12316] bug. Compare against a non-scroll cursor
        # re-execute path is not possible (12c+ never sends an empty query
        # elsewhere), so assert the al8i4 array butts directly against the 12c
        # middle block (…000101000280820120010500, no 00 before 028082's run).
        from oracle.tns_consts import TNS_FETCH_ORIENTATION_ABSOLUTE
        Hex = self._scroll_exec(self._scroll_query(
            cursor=100, query='', scrollable=True,
            scroll=(TNS_FETCH_ORIENTATION_ABSOLUTE, 5)))
        # The 13-element al8i4 array begins at All8[0]=00 then All8[1]=Fetch(0102)
        # …; right before it is the 12c middle's trailing 00 then the query (none).
        # With the bug there would be an extra 00 between them.
        self.assertIn("0001010002808201", Hex)       # …DefLen 00 + middle + al8i4
        self.assertNotIn("000101000002808201", Hex)  # extra 00 (the bug)

    @patch('os.getpid')
    @patch('socket.gethostname')
    def test_tns_sess_0(self, mock_gethostname, mock_getpid):
        mock_getpid.return_value = 18967
        mock_gethostname.return_value = "ExampleHost"
        EnvOpts = { 'host' : "localhost", 'port' : 1521, 'user' : "system", 'password' : "MYORAPASS", 'sid' : "XE", 'app_name' : "oratest" }
        Dict = {'type' : DictionaryType.sess, 'env' : EnvOpts, 'seq' : 3}
        Ret = bytes([3,118,3,1,1,6,1,1,1,1,4,1,1,115,121,115,116,101,109,1,15,15,65,85,84,72,
       95,80,82,79,71,82,65,77,95,78,77,1,7,7,111,114,97,116,101,115,116,0,1,
       12,12,65,85,84,72,95,77,65,67,72,73,78,69,1,11,11,69,120,97,109,112,108,
       101,72,111,115,116,0,1,8,8,65,85,84,72,95,80,73,68,1,5,5,49,56,57,54,55,
       0,1,8,8,65,85,84,72,95,83,73,68,1,6,6,115,121,115,116,101,109,0])
        self.assertEqual(encode_dictionary(Dict), Ret)

    @patch('os.getpid')
    @patch('socket.gethostname')
    def test_tns_sess_1(self, mock_gethostname, mock_getpid):
        mock_getpid.return_value = 18967
        mock_gethostname.return_value = "ExampleHost"
        EnvOpts = { 'host' : "localhost", 'port' : 1521, 'user' : "system", 'password' : "MYORAPASS", 'sid' : "XE", 'app_name' : "oratest" }
        Dict = {'type' : DictionaryType.sess, 'env' : EnvOpts, 'seq' : 3}
        Ret = bytes([3,118,3,1,1,6,1,1,1,1,4,1,1,115,121,115,116,101,109,1,15,15,65,85,84,72,
       95,80,82,79,71,82,65,77,95,78,77,1,7,7,111,114,97,116,101,115,116,0,1,
       12,12,65,85,84,72,95,77,65,67,72,73,78,69,1,11,11,69,120,97,109,112,108,
       101,72,111,115,116,0,1,8,8,65,85,84,72,95,80,73,68,1,5,5,49,56,57,54,55,
       0,1,8,8,65,85,84,72,95,83,73,68,1,6,6,115,121,115,116,101,109,0])
        self.assertEqual(encode_dictionary_sess(Dict), Ret)

    @patch('socket.gethostname')
    def test_tns_description_0(self, mock_gethostname):
        mock_gethostname.return_value = "ExampleHost"
        EnvOpts = { 'host' : "localhost", 'port' : 1521, 'user' : "system", 'password' : "MYORAPASS", 'sid' : "XE", 'app_name' : "oratest" }
        Dict = {'type' : DictionaryType.description, 'env' : EnvOpts, 'seq' : 3}
        Ret = b"(DESCRIPTION=(CONNECT_DATA=(SID=XE)(CID=(PROGRAM=oratest)(HOST=ExampleHost)(USER=system)))(ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=1521)))"
        self.assertEqual(encode_dictionary(Dict), Ret)

    @patch('socket.gethostname')
    def test_tns_description_1(self, mock_gethostname):
        mock_gethostname.return_value = "ExampleHost"
        EnvOpts = { 'host' : "localhost", 'port' : 1521, 'user' : "system", 'password' : "MYORAPASS", 'sid' : "XE", 'app_name' : "oratest" }
        Dict = {'type' : DictionaryType.description, 'env' : EnvOpts, 'seq' : 3}
        Ret = b"(DESCRIPTION=(CONNECT_DATA=(SID=XE)(CID=(PROGRAM=oratest)(HOST=ExampleHost)(USER=system)))(ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=1521)))"
        self.assertEqual(encode_dictionary_description(Dict), Ret)

    @patch('socket.gethostname')
    def test_tns_login_0(self, mock_gethostname):
        mock_gethostname.return_value = "ExampleHost"
        EnvOpts = { 'host' : "localhost", 'port' : 1521, 'user' : "system", 'password' : "MYORAPASS", 'sid' : "XE", 'app_name' : "oratest" }
        Dict = {'type' : DictionaryType.login, 'env' : EnvOpts, 'sdu' : 8192}
        # CONNECT in the protocol-version-319 layout (#155): version 319,
        # service options 0x0401, TDU 0x2000, connect-data offset 74, plus the
        # 16-byte trailer (large SDU/TDU = 8192, connect_flags 0 / 1).
        Ret = bytes([1,63,1,44,4,1,32,0,32,0,79,152,0,0,0,1,0,142,0,74,0,0,0,0,132,132,
       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
       0,0,32,0,0,0,32,0,0,0,0,0,0,0,0,1,
       40,68,69,83,67,82,73,80,
       84,73,79,78,61,40,67,79,78,78,69,67,84,95,68,65,84,65,61,40,83,73,68,61,
       88,69,41,40,67,73,68,61,40,80,82,79,71,82,65,77,61,111,114,97,116,101,
       115,116,41,40,72,79,83,84,61,69,120,97,109,112,108,101,72,111,115,116,
       41,40,85,83,69,82,61,115,121,115,116,101,109,41,41,41,40,65,68,68,82,69,
       83,83,61,40,80,82,79,84,79,67,79,76,61,84,67,80,41,40,72,79,83,84,61,
       108,111,99,97,108,104,111,115,116,41,40,80,79,82,84,61,49,53,50,49,41,
       41,41])
        self.assertEqual(encode_dictionary(Dict), Ret)

    @patch('socket.gethostname')
    def test_tns_login_1(self, mock_gethostname):
        mock_gethostname.return_value = "ExampleHost"
        EnvOpts = { 'host' : "localhost", 'port' : 1521, 'user' : "system", 'password' : "MYORAPASS", 'sid' : "XE", 'app_name' : "oratest" }
        Dict = {'type' : DictionaryType.login, 'env' : EnvOpts, 'sdu' : 8192}
        # CONNECT in the protocol-version-319 layout (#155): version 319,
        # service options 0x0401, TDU 0x2000, connect-data offset 74, plus the
        # 16-byte trailer (large SDU/TDU = 8192, connect_flags 0 / 1).
        Ret = bytes([1,63,1,44,4,1,32,0,32,0,79,152,0,0,0,1,0,142,0,74,0,0,0,0,132,132,
       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
       0,0,32,0,0,0,32,0,0,0,0,0,0,0,0,1,
       40,68,69,83,67,82,73,80,
       84,73,79,78,61,40,67,79,78,78,69,67,84,95,68,65,84,65,61,40,83,73,68,61,
       88,69,41,40,67,73,68,61,40,80,82,79,71,82,65,77,61,111,114,97,116,101,
       115,116,41,40,72,79,83,84,61,69,120,97,109,112,108,101,72,111,115,116,
       41,40,85,83,69,82,61,115,121,115,116,101,109,41,41,41,40,65,68,68,82,69,
       83,83,61,40,80,82,79,84,79,67,79,76,61,84,67,80,41,40,72,79,83,84,61,
       108,111,99,97,108,104,111,115,116,41,40,80,79,82,84,61,49,53,50,49,41,
       41,41])
        self.assertEqual(encode_dictionary_login(Dict), Ret)

    @patch('oracle.crypto.token_bytes')
    def test_tns_auth_0(self, mock_token_bytes):
        mock_token_bytes.return_value = bytes([49,43,83,23,81,36,4,92,139,46,200,121,114,92,178,86,188,208,62,90,190,164,147,14,132,14,103,84,175,84,12,149,210,34,105,192,96,45,55,160,52,33,131,180,32,128,6,237])
        EnvOpts = { 'host' : "localhost", 'port' : 1521, 'user' : "system", 'password' : "MYORAPASS", 'sid' : "XE", 'app_name' : "oratest" }
        Auth = { 'sess' : bytes.fromhex("0E0D327F5244B2E5ACE0EC3B4C8DA2F97155E56B03B4D4A6E65CF3915664EBFCEAAD664DE044369B8EEE172BC4A94434"), 'salt' : bytes.fromhex("B03145C7EF60CA693E1D"), 'derived_salt' : None }
        Dict = {'type' : DictionaryType.auth, 'env' : EnvOpts, 'auth' : Auth, 'seq' : 4}
        Ret = bytes([3,115,4,1,1,6,2,1,1,1,1,2,1,1,115,121,115,116,101,109,1,13,13,65,85,84,72,
     95,80,65,83,83,87,79,82,68,1,64,64,69,56,55,55,52,51,67,50,67,52,52,52,48,
     67,56,55,66,65,51,67,67,68,69,55,53,50,66,50,49,51,57,50,50,70,65,54,56,
     56,70,49,56,55,66,66,52,50,55,51,56,49,54,55,54,67,53,48,53,57,49,48,56,
     68,55,68,0,1,12,12,65,85,84,72,95,83,69,83,83,75,69,89,1,96,96,56,66,69,
     69,51,50,53,48,66,49,50,70,65,66,54,69,48,70,50,70,56,48,65,68,65,68,67,
     69,66,65,48,68,50,67,69,66,55,48,54,53,52,67,67,50,48,70,51,57,70,53,51,
     69,55,69,65,53,68,51,68,48,48,54,69,69,65,53,67,55,66,70,52,54,56,70,51,
     56,52,50,55,54,56,55,55,50,55,48,53,53,68,56,55,68,54,57,54,57,1,1])
        ConnKey = bytes([212,243,165,74,231,92,68,245,19,138,89,126,42,178,151,8,104,26,203,93,221,17,183,19])
        self.assertEqual(encode_dictionary(Dict), (Ret, ConnKey))

    @patch('oracle.crypto.token_bytes')
    def test_tns_auth_1(self, mock_token_bytes):
        mock_token_bytes.return_value = bytes([49,43,83,23,81,36,4,92,139,46,200,121,114,92,178,86,188,208,62,90,190,164,147,14,132,14,103,84,175,84,12,149,210,34,105,192,96,45,55,160,52,33,131,180,32,128,6,237])
        EnvOpts = { 'host' : "localhost", 'port' : 1521, 'user' : "system", 'password' : "MYORAPASS", 'sid' : "XE", 'app_name' : "oratest" }
        Auth = { 'sess' : bytes.fromhex("0E0D327F5244B2E5ACE0EC3B4C8DA2F97155E56B03B4D4A6E65CF3915664EBFCEAAD664DE044369B8EEE172BC4A94434"), 'salt' : bytes.fromhex("B03145C7EF60CA693E1D"), 'derived_salt' : None }
        Dict = {'type' : DictionaryType.auth, 'env' : EnvOpts, 'auth' : Auth, 'seq' : 4}
        Ret = bytes([3,115,4,1,1,6,2,1,1,1,1,2,1,1,115,121,115,116,101,109,1,13,13,65,85,84,72,
     95,80,65,83,83,87,79,82,68,1,64,64,69,56,55,55,52,51,67,50,67,52,52,52,48,
     67,56,55,66,65,51,67,67,68,69,55,53,50,66,50,49,51,57,50,50,70,65,54,56,
     56,70,49,56,55,66,66,52,50,55,51,56,49,54,55,54,67,53,48,53,57,49,48,56,
     68,55,68,0,1,12,12,65,85,84,72,95,83,69,83,83,75,69,89,1,96,96,56,66,69,
     69,51,50,53,48,66,49,50,70,65,66,54,69,48,70,50,70,56,48,65,68,65,68,67,
     69,66,65,48,68,50,67,69,66,55,48,54,53,52,67,67,50,48,70,51,57,70,53,51,
     69,55,69,65,53,68,51,68,48,48,54,69,69,65,53,67,55,66,70,52,54,56,70,51,
     56,52,50,55,54,56,55,55,50,55,48,53,53,68,56,55,68,54,57,54,57,1,1])
        ConnKey = bytes([212,243,165,74,231,92,68,245,19,138,89,126,42,178,151,8,104,26,203,93,221,17,183,19])
        self.assertEqual(encode_dictionary_auth(Dict), (Ret, ConnKey))

    def test_tns_tran_0(self):
        Dict = {'type' : DictionaryType.tran, 'req' : 147, 'seq' : 8}
        self.assertEqual(encode_dictionary(Dict), bytes([3,147,8]))

    def test_tns_tran_1(self):
        Dict = {'type' : DictionaryType.tran, 'req' : 147, 'seq' : 8}
        self.assertEqual(encode_dictionary_tran(Dict), bytes([3,147,8]))

    def test_tns_exec_00(self):
        Query = {'type':'select', 'auto':1, 'fetch':15, 'server_version':11, 'cursor':0, 'query':"select * from customers", 'bind':[], 'batch':[], 'def':[]}
        Dict = {'type' : DictionaryType.exec, 'query' : Query, 'seq' : 5}
        Ret = bytes([3,94,5,2,128,33,0,1,1,23,1,1,13,0,0,4,255,255,255,255,1,15,4,127,255,
       255,255,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,115,101,108,101,99,116,32,42,
       32,102,114,111,109,32,99,117,115,116,111,109,101,114,115,1,1,0,0,0,0,0,
       0,1,1,0,0,0,0,0])
        self.assertEqual(encode_dictionary(Dict), Ret)

    def test_tns_exec_01(self):
        Query = {'type':'select', 'auto':1, 'fetch':15, 'server_version':11, 'cursor':1, 'query':"", 'bind':[], 'batch':[], 'def':[]}
        Dict = {'type' : DictionaryType.exec, 'query' : Query, 'seq' : 6}
        Ret = bytes([3,94,6,2,128,96,1,1,0,0,1,1,13,0,0,0,1,15,4,127,255,255,255,0,0,0,0,0,0,
       0,0,0,0,0,1,0,0,0,0,0,0,1,15,0,0,0,0,0,1,1,0,0,0,0,0])
        self.assertEqual(encode_dictionary_exec(Dict), Ret)

    def test_tns_exec_02(self):
        Query = {'type':'select', 'auto':1, 'fetch':15, 'server_version':11, 'cursor':0, 'query':"select 1 as one, sysdate, rowid from dual where 1=:1 ", 'bind':[1], 'batch':[], 'def':[]}
        Dict = {'type' : DictionaryType.exec, 'query' : Query, 'seq' : 5}
        Ret = bytes([3,94,5,2,128,41,0,1,1,53,1,1,13,0,0,4,255,255,255,255,1,15,4,127,255,
       255,255,1,1,1,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,115,101,108,101,99,116,32,
       49,32,97,115,32,111,110,101,44,32,115,121,115,100,97,116,101,44,32,114,
       111,119,105,100,32,102,114,111,109,32,100,117,97,108,32,119,104,101,114,
       101,32,49,61,58,49,32,1,1,0,0,0,0,0,0,1,1,0,0,0,0,0,2,3,0,0,1,22,0,0,0,
       0,0,1,0,7,2,193,2])
        self.assertEqual(encode_dictionary_exec(Dict), Ret)

    def test_tns_exec_03(self):
        Query = {'type':'change', 'auto':1, 'fetch':0, 'server_version':11, 'cursor':0, 'query':"CREATE TABLE customers ( customer_id number(10) NOT NULL, customer_name varchar2(50) NOT NULL, city varchar2(50))", 'bind':[], 'batch':[], 'def':[]}
        Dict = {'type' : DictionaryType.exec, 'query' : Query, 'seq' : 12}
        Ret = bytes([3,94,12,2,129,33,0,1,1,113,1,1,13,0,0,0,0,4,127,255,255,255,0,0,0,0,0,0,
       0,0,0,0,0,1,0,0,0,0,0,67,82,69,65,84,69,32,84,65,66,76,69,32,99,117,115,
       116,111,109,101,114,115,32,40,32,99,117,115,116,111,109,101,114,95,105,
       100,32,110,117,109,98,101,114,40,49,48,41,32,78,79,84,32,78,85,76,76,44,
       32,99,117,115,116,111,109,101,114,95,110,97,109,101,32,118,97,114,99,
       104,97,114,50,40,53,48,41,32,78,79,84,32,78,85,76,76,44,32,99,105,116,
       121,32,118,97,114,99,104,97,114,50,40,53,48,41,41,1,1,1,1,0,0,0,0,0,0,0,
       0,0,0,0])
        self.assertEqual(encode_dictionary_exec(Dict), Ret)

    def test_tns_exec_04(self):
        Query = {'type':'change', 'auto':1, 'fetch':0, 'server_version':11, 'cursor':0, 'query':"drop TABLE customers", 'bind':[], 'batch':[], 'def':[]}
        Dict = {'type' : DictionaryType.exec, 'query' : Query, 'seq' : 5}
        Ret = bytes([3,94,5,2,129,33,0,1,1,20,1,1,13,0,0,0,0,4,127,255,255,255,0,0,0,0,0,0,0,
       0,0,0,0,1,0,0,0,0,0,100,114,111,112,32,84,65,66,76,69,32,99,117,115,116,
       111,109,101,114,115,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0])
        self.assertEqual(encode_dictionary_exec(Dict), Ret)

    def test_tns_exec_05(self):
        Query = {'type':'change', 'auto':1, 'fetch':0, 'server_version':11, 'cursor':1, 'query':"", 'bind':[], 'batch':[], 'def':[]}
        Dict = {'type' : DictionaryType.exec, 'query' : Query, 'seq' : 6}
        Ret = bytes([3,94,6,2,129,32,1,1,0,0,1,1,13,0,0,0,0,4,127,255,255,255,0,0,0,0,0,0,0,
       0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0,0,0])
        self.assertEqual(encode_dictionary_exec(Dict), Ret)

    def test_tns_exec_06(self):
        Query = {'type':'select', 'auto':1, 'fetch':15, 'server_version':11, 'cursor':0, 'query':"select 1 as one, sysdate, rowid from dual where 1=:1 and 2=:2", 'bind':[1,2], 'batch':[], 'def':[]}
        Dict = {'type' : DictionaryType.exec, 'query' : Query, 'seq' : 6}
        Ret = bytes([3,94,6,2,128,41,0,1,1,61,1,1,13,0,0,4,255,255,255,255,1,15,4,127,255,
       255,255,1,1,2,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,115,101,108,101,99,116,32,
       49,32,97,115,32,111,110,101,44,32,115,121,115,100,97,116,101,44,32,114,
       111,119,105,100,32,102,114,111,109,32,100,117,97,108,32,119,104,101,114,
       101,32,49,61,58,49,32,97,110,100,32,50,61,58,50,1,1,0,0,0,0,0,0,1,1,0,0,
       0,0,0,2,3,0,0,1,22,0,0,0,0,0,1,0,2,3,0,0,1,22,0,0,0,0,0,1,0,7,2,193,2,2,
       193,3])
        self.assertEqual(encode_dictionary_exec(Dict), Ret)

from oracle.tns import encode_chr
from oracle.tns import encode_kv
from oracle.tns import encode_sb4
from oracle.tns import encode_token_raw
from oracle.tns import encode_token_oac
from oracle.tns import encode_token_rxd
from oracle.tns import encode_tokens_oac
from oracle.tns import encode_tokens_rxd
from oracle.tns import lnxpak
from oracle.tns import lnxmin
from oracle.tns import lnxfmt
from oracle.tns import set_opts
from oracle.tns import set_opts_all8
from oracle.cursor import cursor
from oracle.date import date

class TestTnsBaseEncoders(unittest.TestCase):

    def test_encode_sb4_0(self):
        self.assertEqual(encode_sb4(0), bytes([0]))

    def test_encode_sb4_1(self):
        self.assertEqual(encode_sb4(0xAB), bytes([1,171]))

    def test_encode_sb4_2(self):
        self.assertEqual(encode_sb4(0xABCD), bytes([2,171,205]))

    def test_encode_sb4_3(self):
        self.assertEqual(encode_sb4(0xABCDEF), bytes([3,171,205,239]))

    def test_encode_sb4_4(self):
        self.assertEqual(encode_sb4(0xABCDEF87), bytes([4,171,205,239,135]))

    def test_encode_kv(self):
        self.assertEqual(encode_kv(b"AUTH_MACHINE", b"ExampleHost"), bytes([1,12,12,65,85,84,72,95,77,65,67,72,73,78,69,1,11,11,69,120,97,109,112,108,101,72,111,115,116,0]))

    def test_set_opts_1_0(self):
        self.assertEqual(set_opts('select',0,0,0,15), (32864,0,2147483647,[0,15,0,0,0,0,0,1,0,0,0,0,0]))

    def test_set_opts_2_0(self):
        self.assertEqual(set_opts('select',1,0,0,1), (32801,4294967295,2147483647,[1,0,0,0,0,0,0,1,0,0,0,0,0]))

    def test_set_opts_2_1(self):
        self.assertEqual(set_opts('select',1,1,0,1), (32809,4294967295,2147483647,[1,0,0,0,0,0,0,1,0,0,0,0,0]))

    def test_set_opts_4_0(self):
        self.assertEqual(set_opts('change',1,0,0,1), (33057,0,2147483647,[1,1,0,0,0,0,0,0,0,0,0,0,0]))

    def test_set_opts_all8_0(self):
        self.assertEqual(set_opts_all8(1,0,1), [1,0,0,0,0,0,0,1,0,0,0,0,0])

    def test_set_opts_all8_1(self):
        self.assertEqual(set_opts_all8(0,15,1), [0,15,0,0,0,0,0,1,0,0,0,0,0])

    def test_set_opts_all8_2(self):
        self.assertEqual(set_opts_all8(1,1,0), [1,1,0,0,0,0,0,0,0,0,0,0,0])

    def test_encode_chr_0(self):
        self.assertEqual(encode_chr("hello"), bytes([5,104,101,108,108,111]))

    def test_encode_chr_1(self):
        Input = "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
        Output = bytes([254,64,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,7,72,72,72,72,72,72,72,0])
        self.assertEqual(encode_chr(Input), Output)

    def test_encode_chr_2(self):
        Input = "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
        Output = bytes([254,64,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,64,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,13,72,72,72,72,72,72,72,72,72,72,72,72,72,0])
        self.assertEqual(encode_chr(Input), Output)

    def test_encode_tokens_oac_0(self):
        self.assertEqual(encode_tokens_oac([1], b""), bytes([2,3,0,0,1,22,0,0,0,0,0,1,0]))

    def test_encode_tokens_oac_1(self):
        self.assertEqual(encode_tokens_oac([1, 2], b""), bytes([2,3,0,0,1,22,0,0,0,0,0,1,0,2,3,0,0,1,22,0,0,0,0,0,1,0]))

    def test_encode_tokens_oac_2(self):
        self.assertEqual(encode_tokens_oac([2], bytes([2,3,0,0,1,22,0,0,0,0,0,1,0])), bytes([2,3,0,0,1,22,0,0,0,0,0,1,0,2,3,0,0,1,22,0,0,0,0,0,1,0]))

    def test_encode_tokens_rxd_0(self):
        self.assertEqual(encode_tokens_rxd([1],bytes([2,3,0,0,1,22,0,0,0,0,0,1,0])), bytes([2,3,0,0,1,22,0,0,0,0,0,1,0,7,2,193,2]))

    def test_encode_tokens_rxd_1(self):
        self.assertEqual(encode_tokens_rxd([1,2],bytes([2,3,0,0,1,22,0,0,0,0,0,1,0,2,3,0,0,1,22,0,0,0,0,0,1,0])), bytes([2,3,0,0,1,22,0,0,0,0,0,1,0,2,3,0,0,1,22,0,0,0,0,0,1,0,7,2,193,2,2,193,3]))

    def test_encode_tokens_rxd_2(self):
        Out = bytes([2,3,0,0,1,22,0,0,0,0,0,1,0,2,3,0,0,1,22,0,0,0,0,0,1,0,1,3,0,0,2,15,160,0,1,16,0,0,2,3,103,1,0,7,2,193,2,2,193,3,5,104,101,108,108,111])
        self.assertEqual(encode_tokens_rxd([1,2,"hello"],bytes([2,3,0,0,1,22,0,0,0,0,0,1,0,2,3,0,0,1,22,0,0,0,0,0,1,0,1,3,0,0,2,15,160,0,1,16,0,0,2,3,103,1,0])), Out)

    def test_encode_token_oac_0(self):
        self.assertEqual(encode_token_oac(1), bytes([2,3,0,0,1,22,0,0,0,0,0,1,0]))

    def test_encode_token_oac_1(self):
        self.assertEqual(encode_token_oac(2), bytes([2,3,0,0,1,22,0,0,0,0,0,1,0]))

    def test_encode_token_oac_2(self):
        # NULL bind: a minimal VARCHAR OAC (max_size 1). Sizing it to the
        # actual value rather than 32767 avoids the LONG-reorder swap when a
        # NULL/str bind precedes another bind — see encode_token_oac.
        self.assertEqual(encode_token_oac(None), bytes([1,3,0,0,1,1,0,1,16,0,0,2,3,105,1,0]))

    def test_encode_token_oac_str_sized_to_value(self):
        # A VARCHAR bind's OAC max_size tracks the value's byte length, not a
        # flat 32767 (which the server treats as a LONG and reorders, swapping
        # the bind with the next one). "ab" -> max_size 2.
        self.assertEqual(encode_token_oac("ab"),
                         bytes([1,3,0,0,1,2,0,1,16,0,0,2,3,105,1,0]))

    def test_encode_token_oac_str_large_keeps_long_size(self):
        # A value over the 4000-byte VARCHAR2 cap keeps its true (large)
        # max_size so the LONG path still handles multi-KiB CLOB binds.
        Oac = encode_token_oac("x" * 5000)
        # data_type 1 (VARCHAR), and max_size sb4 encodes 5000 (0x1388).
        self.assertEqual(Oac[:4], bytes([1,3,0,0]))
        self.assertEqual(Oac[4:7], bytes([2,0x13,0x88]))

    def test_encode_token_oac_3(self):
        self.assertEqual(encode_token_oac(cursor()), bytes([102,3,0,0,1,1,0,0,0,0,2,3,103,1,0]))

    def test_encode_token_oac_4(self):
        self.assertEqual(encode_token_oac(date(2019, 8, 27)), bytes([12,3,0,0,1,7,0,0,0,0,0,1,0]))

    def test_encode_token_oac_5(self):
        Date = date(2019, 8, 27, 13, 24, 46)
        Date.has_timestamp = True
        self.assertEqual(encode_token_oac(Date), bytes([180,3,0,0,1,11,0,0,0,0,0,1,0]))

    def test_encode_token_oac_6(self):
        Date = date(2019, 8, 27, 13, 24, 46)
        Date.has_timestamp = True
        Date.timestamptz = 1
        self.assertEqual(encode_token_oac(Date), bytes([181,3,0,0,1,13,0,0,0,0,0,1,0]))

    def test_encode_token_rxd_0(self):
        self.assertEqual(encode_token_rxd(1), bytes([2,193,2]))

    def test_encode_token_rxd_1(self):
        self.assertEqual(encode_token_rxd(2), bytes([2,193,3]))

    def test_encode_token_rxd_2(self):
        self.assertEqual(encode_token_rxd("hello"), bytes([5,104,101,108,108,111]))

    def test_encode_token_rxd_3(self):
        # Bytes now go on the wire verbatim as RAW. The old expectation
        # (length-prefixed UTF-16BE) came from a now-fixed bug that
        # decoded bytes as UTF-8 first and re-encoded them.
        self.assertEqual(encode_token_rxd(b"hello"), bytes([5,104,101,108,108,111]))

    def test_encode_token_rxd_4(self):
        self.assertEqual(encode_token_rxd(1024), bytes([3,194,11,25]))

    def test_encode_token_rxd_5(self):
        self.assertEqual(encode_token_rxd(15000), bytes([3,195,2,51]))

    def test_encode_token_rxd_6(self):
        self.assertEqual(encode_token_rxd(1000000), bytes([2,196,2]))

    def test_encode_token_rxd_7(self):
        self.assertEqual(encode_token_rxd(1000000.1), bytes([6,196,2,1,1,1,11]))

    def test_encode_token_rxd_8(self):
        self.assertEqual(encode_token_rxd(-1000000.1), bytes([7,59,100,101,101,101,91,102]))

    def test_encode_token_rxd_9(self):
        self.assertEqual(encode_token_rxd(None), bytes([0]))

    def test_encode_token_rxd_10(self):
        self.assertEqual(encode_token_rxd(cursor()), bytes([1,0]))

    def test_encode_token_rxd_11(self):
        self.assertEqual(encode_token_rxd(date(2019, 8, 27)), bytes([7,120,119,8,27,1,1,1]))

    def test_encode_token_rxd_12(self):
        Date = date(2019, 8, 27, 13, 24, 46)
        Date.set_timestamp()
        self.assertEqual(encode_token_rxd(Date), bytes([11,120,119,8,27,14,25,47,0,0,0,0]))

    def test_encode_token_rxd_13(self):
        Date = date(2019, 8, 27, 13, 24, 46)
        Date.set_timestamptz(10)
        self.assertEqual(encode_token_rxd(Date), bytes([13,120,119,8,27,14,25,37,0,0,0,0,20,60]))

    def test_encode_token_raw_0(self):
        self.assertEqual(encode_token_raw(2,22,0,0,0), bytes([2,3,0,0,1,22,0,0,0,0,0,1,0]))

    def test_encode_token_raw_1(self):
        self.assertEqual(encode_token_raw(1,4000,16,871,0), bytes([1,3,0,0,2,15,160,0,1,16,0,0,2,3,103,1,0]))

    def test_encode_token_raw_2(self):
        self.assertEqual(encode_token_raw(102,1,0,871,0), bytes([102,3,0,0,1,1,0,0,0,0,2,3,103,1,0]))

    def test_encode_token_raw_3(self):
        self.assertEqual(encode_token_raw(12,7,0,0,0), bytes([12,3,0,0,1,7,0,0,0,0,0,1,0]))

    def test_encode_token_raw_4(self):
        self.assertEqual(encode_token_raw(180,11,0,0,0), bytes([180,3,0,0,1,11,0,0,0,0,0,1,0]))

    def test_encode_token_raw_5(self):
        self.assertEqual(encode_token_raw(181,13,0,0,0), bytes([181,3,0,0,1,13,0,0,0,0,0,1,0]))

    def test_lnxpak_0(self):
        self.assertEqual(lnxpak([0,0,0,1,2,3,4,5]), [5,4,3,2,1])

    def test_lnxpak_1(self):
        self.assertEqual(lnxpak([1,2,3,4,5]), [5,4,3,2,1])

    def test_lnxpak_2(self):
        self.assertEqual(lnxpak([0,0,1,2,3,4,5,0]), [0,5,4,3,2,1])

    def test_lnxmin_0(self):
        self.assertEqual(lnxmin(1,1,[]), [0,1])

    def test_lnxmin_1(self):
        self.assertEqual(lnxmin(2,1,[]), [0,2])

    def test_lnxmin_2(self):
        self.assertEqual(lnxmin(1024,1,[]), [1,10,24])

    def test_lnxmin_3(self):
        self.assertEqual(lnxmin(15000,1,[]), [2,1,50])

    def test_lnxmin_4(self):
        self.assertEqual(lnxmin(1000000,1,[]), [3,1])

    def test_lnxfmt_0(self):
        self.assertEqual(lnxfmt(lnxmin(1,1,[]), 1), [193,2])

    def test_lnxfmt_1(self):
        self.assertEqual(lnxfmt(lnxmin(2,1,[]), 2), [193,3])

    def test_lnxfmt_2(self):
        self.assertEqual(lnxfmt(lnxmin(1024,1,[]), 1024), [194,11,25])

    def test_lnxfmt_3(self):
        self.assertEqual(lnxfmt(lnxmin(15000,1,[]), 15000), [195,2,51])

    def test_lnxfmt_4(self):
        self.assertEqual(lnxfmt(lnxmin(1000000,1,[]), 1000000), [196,2])

if __name__ == '__main__':
    unittest.main()


from oracle.tns import (encode_o3logon_phase1, encode_o3logon_phase2,
                        capability_arrays, FIELD_VERSION_9_2)

class TestO3logonMessages(unittest.TestCase):
    # Pinned against the Oracle JDBC thin driver's 9i (#90) handshake: user
    # "pyo", and the AUTH_PASSWORD field "F18CC9AF1CE5A7E82" (hex of the DES
    # blocks + decimal pad count). seq 0 matches the capture.
    def test_phase1_3loga(self):
        self.assertEqual(
            encode_o3logon_phase1(0, b"pyo").hex(),
            "0352000101030000000000000101070101030101040210000000"
            "010110000000000101100170796f756e6b6e6f776e6f3969726f"
            "6f744a444243205468696e20436c69656e74")

    def test_phase2_3logon(self):
        self.assertEqual(
            encode_o3logon_phase2(0, b"pyo", b"F18CC9AF1CE5A7E82").hex(),
            "035100010103010111000000000101070101030101040210000000"
            "010110000000000001100070796f4631384343394146314345354137"
            "453832756e6b6e6f776e6f3969726f6f744a444243205468696e2043"
            "6c69656e74")

    def test_9i_capabilities_minimal(self):
        # Pre-10g caps must NOT advertise O5LOGON (LOGON_TYPES byte 0) or 9i
        # rejects the login with ORA-01017.
        Compile, Runtime = capability_arrays(FIELD_VERSION_9_2)
        self.assertEqual(len(Compile), 21)
        self.assertEqual(Compile[4], 0)        # CCAP_LOGON_TYPES
        self.assertEqual(Compile[17], 3)
        self.assertEqual(Runtime, bytes([2]))

    def test_9i_parse_no_binds(self):
        # fv2 TTI_ALL7 parse, no binds: option word 0x21, no bind section.
        # Exact bytes from a live 9.2.0.4 JDBC-thin capture.
        from oracle.tns import encode_o7_parse
        self.assertEqual(
            encode_o7_parse(0, "select 42 as n from dual").hex(),
            "03470002802101010101180000010107010102000000000073656c"
            "656374203432206173206e2066726f6d206475616c0101010100000000"
            "00")

    def test_9i_parse_with_binds(self):
        # fv2 TTI_ALL7 parse with a string + number bind: option word 0x29, a
        # bind-count field before the SQL, per-bind OAC + one RXD of values
        # after it. Exact bytes from a live 9.2.0.4 JDBC-thin capture (#100).
        from oracle.tns import encode_o7_parse
        self.assertEqual(
            encode_o7_parse(
                0, "select id from t97 where name = :1 and id = :2",
                ["carol", 3]).hex(),
            "034700028029010101012e000001010701010200000001010273656c"
            "6563742069642066726f6d20743937207768657265206e616d65203d"
            "203a3120616e64206964203d203a3201010101000000000001010000"
            "020fa000000000011f0106010000011600000000011f010705636172"
            "6f6c02c104")


class TestEndToEndPiggyback(unittest.TestCase):
    # SET_END_TO_END_ATTR piggyback (#183). Bytes byte-validated against a real
    # oracledb-thin capture on 23ai (fv24); the action/client-identifier cases
    # below are the exact piggyback portions of that capture.
    def test_action_matches_capture(self):
        from oracle.tns import encode_end_to_end_piggyback
        self.assertEqual(
            encode_end_to_end_piggyback(6, 24, {"action": "MYACT"}).hex(),
            "118706000000011000000000010105000000000000000000000000054d59414354")

    def test_client_identifier_matches_capture(self):
        from oracle.tns import encode_end_to_end_piggyback
        self.assertEqual(
            encode_end_to_end_piggyback(8, 24, {"client_identifier": "MYCLID"}).hex(),
            "118708000000010101010600000000000000000000000000000000064d59434c4944")

    def test_pre_23ai_omits_token(self):
        # On a < 23ai (fv <= 17) server the piggyback carries no ub8 token,
        # exactly like _fun_header.
        from oracle.tns import encode_end_to_end_piggyback
        fv16 = encode_end_to_end_piggyback(6, 16, {"action": "MYACT"}).hex()
        fv24 = encode_end_to_end_piggyback(6, 24, {"action": "MYACT"}).hex()
        # fv24 has one extra 00 (the token) right after the seq byte.
        self.assertEqual(fv16, "1187060000011000000000010105"
                               "000000000000000000000000054d59414354")
        self.assertEqual(len(fv24), len(fv16) + 2)

    def test_combined_flags(self):
        from oracle.tns import encode_end_to_end_piggyback
        out = encode_end_to_end_piggyback(
            7, 24, {"module": "M", "action": "A", "client_identifier": "C"})
        # flags = MODULE(0x08) | ACTION(0x10) | CLIENT_IDENTIFIER(0x01) = 0x19
        self.assertIn("0119", out.hex())
        self.assertTrue(out.startswith(bytes([0x11, 0x87, 7])))


class TestEndToEndClientInfoDbop(unittest.TestCase):
    # client_info / dbop on the same piggyback (#184).
    def test_client_info_and_dbop(self):
        from oracle.tns import encode_end_to_end_piggyback
        out = encode_end_to_end_piggyback(
            99, 24, {"client_info": "PYOINFO", "dbop": "PYODBOP"})
        # flags = CLIENT_INFO(0x100) | DBOP(0x200) = 0x300
        self.assertIn("0300", out.hex())
        # both values present, in field order (client_info before dbop)
        self.assertIn(b"PYOINFO".hex(), out.hex())
        self.assertIn(b"PYODBOP".hex(), out.hex())
        self.assertLess(out.hex().index(b"PYOINFO".hex()),
                        out.hex().index(b"PYODBOP".hex()))

    def test_dbop_alone_flag(self):
        from oracle.tns import encode_end_to_end_piggyback
        out = encode_end_to_end_piggyback(99, 24, {"dbop": "OP"})
        self.assertIn("0200", out.hex())          # DBOP flag
        self.assertTrue(out.hex().endswith(b"OP".hex()))


class TestScrollableExecEncoding(unittest.TestCase):
    # Server-side scrollable cursor wire encoding (#181, groundwork for 1.9.0).
    # The scroll request rides in the execute al8i4 array: al8i4[9] exec flags
    # (SCROLLABLE | NO_CANCEL_ON_EOF), al8i4[10] orientation, al8i4[11] position.
    # Bytes byte-validated against a 23ai oracledb-thin capture.
    def _exec(self, scroll=None, scrollable=False):
        # Run in a copied context so encode_dictionary_exec's fv24
        # _ENCODE_FIELD_VERSION.set() doesn't leak into other encoder tests.
        import contextvars
        from oracle.tns import encode_dictionary_exec
        d = {'seq': 0x0a, 'field_version': 24,
             'query': {'type': 'select', 'auto': 0, 'fetch': 100,
                       'server_version': 0x18000000, 'cursor': 100, 'query': '',
                       'bind': [], 'batch': [], 'def': [], 'batcherrors': None,
                       'arraydmlrowcounts': None, 'return_binds': None,
                       'scroll': scroll, 'scrollable': scrollable}}
        return contextvars.copy_context().run(encode_dictionary_exec, d)

    def test_absolute_matches_capture(self):
        from oracle.tns_consts import TNS_FETCH_ORIENTATION_ABSOLUTE
        self.assertIn("0280820120010500",
                      self._exec(scroll=(TNS_FETCH_ORIENTATION_ABSOLUTE, 5)).hex())

    def test_open_current_matches_capture(self):
        from oracle.tns_consts import TNS_FETCH_ORIENTATION_CURRENT
        self.assertIn("0280820101010100",
                      self._exec(scroll=(TNS_FETCH_ORIENTATION_CURRENT, 1)).hex())

    def test_non_scrollable_unchanged(self):
        # Default path carries no scroll exec flags (no regression).
        self.assertNotIn("028082", self._exec().hex())
