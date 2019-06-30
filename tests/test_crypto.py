# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import unittest
from oracle.crypto import o5logon0
from unittest.mock import patch

class TestCryptoLogonMethods(unittest.TestCase):

    @patch('oracle.crypto.token_bytes')
    def test_o5logon0_192_bit(self, mock_token_bytes):
        mock_token_bytes.return_value = bytes([254,21,49,233,19,16,109,99,125,4,62,46,96,172,72,12,39,169,178,114,83,9,119,159,122,112,199,108,204,130,62,183,228,171,137,125,215,132,73,249,226,39,150,231,117,33,160,73])

        Sess = bytes([133,116,72,228,112,43,211,202,81,171,240,178,217,51,25,244,17,153,217,160,237,192,58,132,219,67,232,8,142,208,11,224,177,173,243,130,147,163,110,100,101,238,151,30,47,239,182,196])
        KeySess = bytes([155,246,157,138,79,20,130,177,192,74,88,47,3,111,223,103,122,144,148,143,0,0,0,0])
        DerivedSalt = None
        DerivedKey = None
        Password = b"MYORAPASS"
        Bits = 192

        AuthPass = bytes([17,180,8,36,95,158,219,176,171,207,132,159,57,91,132,61,51,224,232,69,36,165,81,252,23,204,148,69,249,67,175,59])
        AuthSess = bytes([197,111,72,69,246,89,52,8,12,157,199,214,85,93,228,247,146,144,240,127,101,232,78,145,174,46,196,214,202,196,81,6,83,93,200,162,139,209,65,108,68,80,227,210,15,155,239,7])
        SpeedyKey = b""
        SpeedyKeyInd = 0
        ConnKey = bytes([136,47,159,158,118,54,245,71,3,63,153,55,248,39,220,82,61,148,222,183,87,164,249,26])

        self.assertEqual(o5logon0(Sess, KeySess, DerivedSalt, DerivedKey, Password, Bits), (AuthPass, AuthSess, SpeedyKey, SpeedyKeyInd, ConnKey))

from binascii import unhexlify
from oracle.crypto import validate

class TestCryptoValidateMethods(unittest.TestCase):

    def test1(self):
        # Data = bytes([96,41,180,15,65,106,25,78,86,192,156,221,168,28,186,252,83,69,82,86,69,82,95,84,79,95,67,76,73,69,78,84,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16])
        Resp = unhexlify("38D08E44015F289A4515D43C788D8F9A61D998801CC62FEB4FFC8A01B8AD059F53795B38C387C8ED474CCF14801579CD")
        Key = bytes([62,241,238,220,137,70,185,169,127,39,225,28,118,151,2,153,134,7,95,7,193,22,220,85])
        self.assertTrue(validate(Resp, Key))

    def test2(self):
        # Data = bytes([166,75,6,116,107,158,228,234,55,131,65,201,249,236,123,243,83,69,82,86,69,82,95,84,79,95,67,76,73,69,78,84,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16])
        Resp = unhexlify("A9BC207849A627B68589EFA9B605EB778702CEB869EF5E57249C687FF339BF073E7B88FEC42E2E577D83FA282EC9726C")
        Key = bytes([48,239,131,22,229,156,6,142,24,185,41,243,97,102,239,200,212,187,118,220,228,206,111,215])
        self.assertTrue(validate(Resp, Key))

    def test3(self):
        Resp = unhexlify("38D08E44015F289A4515D43C788D8F9A61D998801CC62FEB4FFC8A01B8AD059F53795B38C387C8ED474CCF14801579CD")
        Key = bytes([48,239,131,22,229,156,6,142,24,185,41,243,97,102,239,200,212,187,118,220,228,206,111,215])
        self.assertFalse(validate(Resp, Key))

from oracle.crypto import bin_xor
from oracle.crypto import cat_key
from oracle.crypto import conn_key
from oracle.crypto import norm
from oracle.crypto import pad1
from oracle.crypto import pad2

class TestCryptoPrivateMethods(unittest.TestCase):

    def test_pad1(self):
        self.assertEqual(pad1(b"hello"), bytes([16 for x in range(16)]) + b"hello" + bytes([11 for x in range(11)]))

    def test_pad2(self):
        self.assertEqual(pad2(b"hello", 80), b"helloPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP")

    def test_cat_key(self):
        CatKey = bytes([201,146,96,209,141,214,89,240,36,235,240,180,247,247,14,185,200,242,230,88,230,187,235,160])
        SrvSess = bytes([43,79,107,194,155,157,244,122,215,61,240,233,143,172,10,45,113,251,57,97,239,41,242,11,7,225,228,187,207,91,151,106,9,80,138,235,127,110,101,88,40,171,1,22,243,178,34,170])
        CliSess = bytes([165,21,71,218,29,12,54,254,237,186,229,174,80,3,207,249,184,105,89,176,98,255,171,251,35,10,20,15,56,172,153,211,193,162,108,179,153,213,142,248,152,67,118,10,169,63,79,80])
        DerivedSalt = None
        Bits = 192
        self.assertEqual(cat_key(SrvSess, CliSess, DerivedSalt, Bits), CatKey)

    def test_bin_xor(self):
        self.assertEqual(bin_xor(bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,14,16]), bytes([9,10,11,12,13,14,14,16,17,18,19,20,21,22,23,24])), b'\x08\x08\x08\x08\x08\x08\t\x18\x18\x18\x18\x18\x18\x18\x19\x08')

    def test_conn_key(self):
        ConnKey = bytes([168,155,17,236,85,63,171,127,84,73,105,67,156,205,22,35,200,221,59,168,11,44,197,70])
        CatKey = bytes([201,146,96,209,141,214,89,240,36,235,240,180,247,247,14,185,200,242,230,88,230,187,235,160])
        DerivedSalt = None
        Bits = 192
        self.assertEqual(conn_key(CatKey, DerivedSalt, Bits), ConnKey)

    def test_norm1(self):
        self.assertEqual(norm(bytes("hello", 'UTF-8')),bytes([0,72,0,69,0,76,0,76,0,79,0,0,0,0,0,0]))

    def test_norm2(self):
        self.assertEqual(norm(bytes("привет", 'UTF-8')),bytes([0,63,0,63,0,63,0,63,0,63,0,63,0,0,0,0]))


if __name__ == '__main__':
    unittest.main()
