# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

from oracle.tns import assemble_packet
from oracle.tns import decode_packet
from oracle.tns import decode_ub4
from oracle.tns import parse_redirect_address
from oracle.tns import decode_token_bvc
from oracle.tns import decode_token_dcb
from oracle.tns import decode_token_iov
from oracle.tns import decode_token_lob
from oracle.tns import decode_token_net
from oracle.tns import decode_token_oer
from oracle.tns import decode_token_oac
from oracle.tns import decode_token_pro
from oracle.tns import decode_token_rpa
from oracle.tns import decode_token_uds
from oracle.tns import decode_token_rxd
from oracle.tns import decode_token_rxh
from oracle.tns import decode_token_wrn
from oracle.tns_consts import (
    AL32UTF8_CHARSET, TNS_ACCEPT, TNS_DATA, TNS_RESEND, TTI_AUTH, TTI_SESS,
)
import unittest

class TestDecodeUb4(unittest.TestCase):
    """Variable-length integer decode, incl. multi-byte negatives (#24)."""

    def _check(self, raw, value, consumed):
        # Append a sentinel so we also assert exactly `consumed` bytes were taken.
        got, rest = decode_ub4(bytes(raw) + b"\x5a\xa5")
        self.assertEqual(got, value)
        self.assertEqual(rest, bytes(raw)[consumed:] + b"\x5a\xa5")
        self.assertEqual(len(bytes(raw) + b"\x5a\xa5") - len(rest), consumed)

    def test_zero(self):
        self._check([0], 0, 1)

    def test_positive_widths(self):
        self._check([1, 0x2a], 42, 2)
        self._check([2, 0x01, 0x00], 256, 3)
        self._check([3, 0x12, 0x34, 0x56], 0x123456, 4)
        self._check([4, 0xff, 0xff, 0xff, 0xff], 0xffffffff, 5)

    def test_negative_width_1(self):
        # The common forms: -1 and NUMBER scale -127.
        self._check([0x81, 0x01], -1, 2)
        self._check([0x81, 0x7f], -127, 2)

    def test_negative_multibyte(self):
        # The latent bug #24 fixed: negatives wider than one byte.
        self._check([0x82, 0x01, 0x00], -256, 3)
        self._check([0x83, 0x01, 0x00, 0x00], -65536, 4)
        self._check([0x84, 0xff, 0xff, 0xff, 0xff], -0xffffffff, 5)

    def test_raw_ub2_field_consumes_two_bytes(self):
        # A length byte 5..0x7f is not a real var-int — it is the raw ub2 /
        # counter field decode_token_oer reads through here. Historic lenient
        # behaviour (consume 2 bytes) must be preserved so the OER stream stays
        # aligned; the value is discarded by the caller.
        self._check([0x07, 0x00], 0, 2)
        self._check([0x0c, 0x34], -0x34, 2)


class TestParseRedirectAddress(unittest.TestCase):
    """Parse the HOST/PORT out of a TNS_REDIRECT descriptor (#23)."""

    def test_bare_address(self):
        body = b"(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.5)(PORT=1522))"
        self.assertEqual(parse_redirect_address(body), ("10.0.0.5", 1522))

    def test_full_description(self):
        body = (b"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db.example.com)"
                b"(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=ORCL)))")
        self.assertEqual(parse_redirect_address(body),
                         ("db.example.com", 1521))

    def test_prefers_address_host_over_cid_host(self):
        # The descriptor can also carry the original CONNECT_DATA whose CID has
        # the *client* HOST; the ADDRESS host is the reconnect target. Here the
        # CID/HOST appears first textually, so a naive first-match would be
        # wrong — the parser must scope to the ADDRESS block.
        body = (b"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)"
                b"(CID=(PROGRAM=app)(HOST=client-box)(USER=scott)))"
                b"(ADDRESS=(PROTOCOL=TCP)(HOST=server-box)(PORT=1530)))")
        self.assertEqual(parse_redirect_address(body), ("server-box", 1530))

    def test_case_insensitive_and_whitespace(self):
        body = b"(address=(protocol=tcp)(Host = 192.168.1.9)(Port = 1599))"
        self.assertEqual(parse_redirect_address(body), ("192.168.1.9", 1599))

    def test_unparseable_returns_none(self):
        self.assertEqual(parse_redirect_address(b"garbage"), (None, None))


class TestTnsCommandDecoders(unittest.TestCase):

    def test_tns_assemble_00(self):
        Data = bytes([0,8,0,0,11,0,0,0])
        Length = 8192
        self.assertEqual(assemble_packet(Data, Length), (True, TNS_RESEND, b"", b""))

    def test_tns_assemble_01(self):
        Data = bytes([0,32,0,0,2,0,0,0,1,57,0,1,32,0,255,255,1,0,0,0,0,32,197,0,0,0,0,0,0,0,0,0])
        Length = 8192
        self.assertEqual(assemble_packet(Data, Length), (True, TNS_ACCEPT, Data[8:], b""))

    def test_tns_assemble_02(self):
        Data = bytes([0,238,0,0,6,0,0,0,0,0,1,6,0,120,56,54,95,54,52,47,76,105,110,117,
            120,32,50,46,52,46,120,120,0,105,3,1,10,0,102,3,64,3,1,64,3,102,3,
            1,102,3,72,3,1,72,3,102,3,1,102,3,82,3,1,82,3,102,3,1,102,3,97,3,1,
            97,3,102,3,1,102,3,31,3,8,31,3,102,3,1,0,100,0,0,0,96,1,36,15,5,11,
            12,3,12,12,5,4,5,13,6,9,7,8,5,5,5,5,5,15,5,5,5,5,5,10,5,5,5,5,5,4,
            5,6,7,8,8,35,71,35,71,8,17,35,8,17,65,176,71,0,131,3,105,7,208,3,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,39,6,1,1,1,15,1,1,6,1,1,1,1,1,1,1,127,255,3,10,3,3,1,0,127,1,
            127,255,1,6,1,1,63,1,3,6,0,1,3,2,7,2,1,0,1,24,0,3])
        Length = 8192
        self.assertEqual(assemble_packet(Data, Length), (True, TNS_DATA, Data[10:], b""))

    def test_decode_packet_sta(self):
        self.assertEqual(decode_packet(bytes([9,1,1,1,8]), [1, {'foo':'bar'}]), (True, [1, {'foo':'bar'}]))

    def test_decode_select_response_21c(self):
        # Full 'SELECT 1 FROM dual' response captured from Oracle 21c (DCB +
        # RXH + RXD + RPA + OER), decoded with the 21.1 field version. Exercises
        # the 12c per-column DCB format (sb1 scale, oaccolid) and confirms the
        # row decodes to 1. With the default 11g field version this same buffer
        # would mis-parse, so it guards the version-gated decode path.
        import contextvars
        from oracle.tns import decode_packet, FIELD_VERSION_21_1
        Resp = bytes.fromhex(
            "101735ebcd3cc510be7fdf53b18448bb2dda787e0608123633010201015c0200"
            "00810102000000000000000001010101013100000000010707787e0608123633"
            "00021fe80102010200062201010001020000000702c10208010603284b3a0001"
            "02000000000000040101011b010102057b00000102010e0300000000000000000"
            "0000000030001010000000002057b0101010300194f52412d30313430333a206e"
            "6f206461746120666f756e640a")
        # Run in a copied context so the field-version ContextVar set by
        # decode_packet does not leak into other tests (production resets it per
        # response). Mirrors how each connection decodes in its own context.
        Result = contextvars.copy_context().run(
            decode_packet, Resp, (None, None, []), FIELD_VERSION_21_1)
        Rows = Result[4]
        RowFormat = Result[3][1]
        self.assertEqual(Rows, [[1]])
        self.assertEqual(RowFormat[0]['data_type'], 2)   # NUMBER
        self.assertEqual(RowFormat[0]['column_name'], b'1')

    def test_decode_token_pro_11g(self):
        # Authentic 11g PRO response (same bytes as test_tns_assemble_02, minus
        # the 8-byte TNS header and 2-byte data flags). field_version 6 = 11.2.
        Body = bytes([1,6,0,120,56,54,95,54,52,47,76,105,110,117,120,32,50,46,52,46,
            120,120,0,105,3,1,10,0,102,3,64,3,1,64,3,102,3,1,102,3,72,3,1,72,3,102,
            3,1,102,3,82,3,1,82,3,102,3,1,102,3,97,3,1,97,3,102,3,1,102,3,31,3,8,31,
            3,102,3,1,0,100,0,0,0,96,1,36,15,5,11,12,3,12,12,5,4,5,13,6,9,7,8,5,5,5,
            5,5,15,5,5,5,5,5,10,5,5,5,5,5,4,5,6,7,8,8,35,71,35,71,8,17,35,8,17,65,176,
            71,0,131,3,105,7,208,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,39,6,1,1,1,15,1,1,6,1,1,1,1,1,1,1,127,255,3,10,3,
            3,1,0,127,1,127,255,1,6,1,1,63,1,3,6,0,1,3,2,7,2,1,0,1,24,0,3])
        Pro = decode_token_pro(Body)
        self.assertEqual(Pro['server_version'], 6)
        self.assertEqual(Pro['banner'], b'x86_64/Linux 2.4.xx')
        self.assertEqual(len(Pro['compile_caps']), 39)
        self.assertEqual(Pro['compile_caps'][7], 6)   # CCAP_FIELD_VERSION = 11.2
        self.assertEqual(len(Pro['runtime_caps']), 7)

    def test_decode_token_pro_21c(self):
        # Authentic 21c PRO response body (captured via tools/capture_proxy.py).
        # field_version 16 = 21.1; the server's compile array is 45 bytes.
        Body = bytes.fromhex(
            "0106007838365f36342f4c696e757820322e342e7878006903010a006603400301"
            "400366030166034803014803660301660352030152036603016603610301610366"
            "030166031f03081f0366030100640000006001240f050b0c030c0c0504050d0609"
            "070805050505050f05050505050a050505050504050607080823472347081123081"
            "141b0470083036907d0030000000000000000000000000000000000000000000000"
            "00000000000000000000000000002d060101016f0101100101010101010"
            "17fff031003030101ff01ffff010b0101ff01060ce6017f050f7f0d0300010702010"
            "00118007f")
        Pro = decode_token_pro(Body)
        self.assertEqual(Pro['server_version'], 6)
        self.assertEqual(Pro['compile_caps'][7], 16)  # CCAP_FIELD_VERSION = 21.1
        self.assertEqual(len(Pro['compile_caps']), 45)

    def test_tns_decode_token_oac_00(self):
        self.assertEqual(decode_token_oac(bytes([2,3,0,0,1,22,0,0,0,0,0,1,0]), None), (2,22,0,0, b""))

    def test_tns_decode_token_oac_01(self):
        Data = bytes([2,0,0,129,127,1,2,0,0,0,0,0,0,0,1,3,1,3,3,79,78,69,0,0,0,0,
                   12,0,0,0,1,1,0,0,0,0,0,0,0,1,7,1,7,7,83,89,83,68,65,84,69,0,
                   0,1,1,0,11,0,0,0,1,1,0,0,0,0,0,0,0,0,5,1,5,5,82,79,87,73,68,
                   0,0,1,2,0,1,7,7,120,119,9,6,8,41,17,0,2,31,232,1,2,1,2,0,6,
                   34,1,3,0,1,15,0,0,0,7,2,193,2,7,120,119,9,6,8,41,17,14,1,
                   116,1,1,0,2,3,161,0,8,1,6,3,42,55,122,0,1,1,0,0,0,0,0,0,4,1,
                   1,1,4,1,1,2,5,123,0,0,1,1,0,3,0,0,0,0,0,0,0,0,0,0,0,0,5,0,1,
                   1,25,79,82,65,45,48,49,52,48,51,58,32,110,111,32,100,97,116,
                   97,32,102,111,117,110,100,10])
        Rest = bytes([1,3,1,3,3,79,78,69,0,0,0,0,12,0,0,0,1,1,0,0,0,0,0,0,0,1,7,1,7,7,83,89,83,68,
   65,84,69,0,0,1,1,0,11,0,0,0,1,1,0,0,0,0,0,0,0,0,5,1,5,5,82,79,87,73,68,0,0,
   1,2,0,1,7,7,120,119,9,6,8,41,17,0,2,31,232,1,2,1,2,0,6,34,1,3,0,1,15,0,0,0,
   7,2,193,2,7,120,119,9,6,8,41,17,14,1,116,1,1,0,2,3,161,0,8,1,6,3,42,55,122,
   0,1,1,0,0,0,0,0,0,4,1,1,1,4,1,1,2,5,123,0,0,1,1,0,3,0,0,0,0,0,0,0,0,0,0,0,0,
   5,0,1,1,25,79,82,65,45,48,49,52,48,51,58,32,110,111,32,100,97,116,97,32,102,
   111,117,110,100,10])
        self.assertEqual(decode_token_oac(Data, None), (2,2,-127,0,Rest))

    def test_tns_decode_token_oac_02(self):
        Data = bytes([12,0,0,0,1,1,0,0,0,0,0,0,0,1,7,1,7,7,83,89,83,68,65,84,69,0,
                   0,1,1,0,11,0,0,0,1,1,0,0,0,0,0,0,0,0,5,1,5,5,82,79,87,73,68,
                   0,0,1,2,0,1,7,7,120,119,9,6,8,41,17,0,2,31,232,1,2,1,2,0,6,
                   34,1,3,0,1,15,0,0,0,7,2,193,2,7,120,119,9,6,8,41,17,14,1,
                   116,1,1,0,2,3,161,0,8,1,6,3,42,55,122,0,1,1,0,0,0,0,0,0,4,1,
                   1,1,4,1,1,2,5,123,0,0,1,1,0,3,0,0,0,0,0,0,0,0,0,0,0,0,5,0,1,
                   1,25,79,82,65,45,48,49,52,48,51,58,32,110,111,32,100,97,116,
                   97,32,102,111,117,110,100,10])
        Rest = bytes([1,7,1,7,7,83,89,83,68,65,84,69,0,0,1,1,0,11,0,0,0,1,1,0,0,0,0,0,0,0,0,5,1,5,
   5,82,79,87,73,68,0,0,1,2,0,1,7,7,120,119,9,6,8,41,17,0,2,31,232,1,2,1,2,0,6,
   34,1,3,0,1,15,0,0,0,7,2,193,2,7,120,119,9,6,8,41,17,14,1,116,1,1,0,2,3,161,
   0,8,1,6,3,42,55,122,0,1,1,0,0,0,0,0,0,4,1,1,1,4,1,1,2,5,123,0,0,1,1,0,3,0,0,
   0,0,0,0,0,0,0,0,0,0,5,0,1,1,25,79,82,65,45,48,49,52,48,51,58,32,110,111,32,
   100,97,116,97,32,102,111,117,110,100,10])
        self.assertEqual(decode_token_oac(Data, None), (12,1,0,0,Rest))

    def test_tns_decode_token_oac_03(self):
        Data = bytes([11,0,0,0,1,1,0,0,0,0,0,0,0,0,5,1,5,5,82,79,87,73,68,0,0,1,2,
                   0,1,7,7,120,119,9,6,8,41,17,0,2,31,232,1,2,1,2,0,6,34,1,3,0,
                   1,15,0,0,0,7,2,193,2,7,120,119,9,6,8,41,17,14,1,116,1,1,0,2,
                   3,161,0,8,1,6,3,42,55,122,0,1,1,0,0,0,0,0,0,4,1,1,1,4,1,1,2,
                   5,123,0,0,1,1,0,3,0,0,0,0,0,0,0,0,0,0,0,0,5,0,1,1,25,79,82,
                   65,45,48,49,52,48,51,58,32,110,111,32,100,97,116,97,32,102,
                   111,117,110,100,10])
        Rest = bytes([0,5,1,5,5,82,79,87,73,68,0,0,1,2,0,1,7,7,120,119,9,6,8,41,17,0,2,31,232,1,2,
   1,2,0,6,34,1,3,0,1,15,0,0,0,7,2,193,2,7,120,119,9,6,8,41,17,14,1,116,1,1,0,
   2,3,161,0,8,1,6,3,42,55,122,0,1,1,0,0,0,0,0,0,4,1,1,1,4,1,1,2,5,123,0,0,1,1,
   0,3,0,0,0,0,0,0,0,0,0,0,0,0,5,0,1,1,25,79,82,65,45,48,49,52,48,51,58,32,110,
   111,32,100,97,116,97,32,102,111,117,110,100,10])
        self.assertEqual(decode_token_oac(Data, None), (11,1,0,0,Rest))

    def test_tns_decode_token_oer_04(self):
        # Real OER bytes captured from Oracle XE 11g for
        # "DROP TABLE nonexistent_xyz" — ORA-00942 with the full message
        # text as the trailing length-prefixed DALC. Exercises the unified
        # OER decoder end to end: extended error number, DML rowcount = 0,
        # and the human-readable message round-tripping cleanly.
        Data = bytes([
            0x04,                                       # TTI_OER token
            0x01, 0x05,                                 # call_status = 5
            0x01, 0x04,                                 # end-to-end seq# = 4
            0x00,                                       # current row # / rowcount = 0
            0x02, 0x03, 0xae,                           # ORA error code = 942
            0x00, 0x00,                                 # array elem error x2
            0x01, 0x01,                                 # cursor id = 1
            0x01, 0x0b,                                 # error position = 11
            0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,         # 6 ub1 fields
            0x00, 0x00, 0x00, 0x00, 0x00,               # rowid (all zero)
            0x00,                                       # OS error
            0x00, 0x07,                                 # stmt #, call # (7)
            0x00,                                       # padding
            0x00,                                       # success_iters
            0x00,                                       # oerrdd len = 0
            0x00, 0x00, 0x00,                           # 3 batch-error counts
            0x28,                                       # DALC length = 40
        ]) + b"ORA-00942: table or view does not exist\n"
        Cursor = None
        RowFormat = None
        Rows = []
        self.assertEqual(
            decode_token_oer(Data, (Cursor, RowFormat, Rows)),
            (5,             # call_status
             942,           # ORA-00942
             1,             # cursor id
             (0, None),     # rowcount, row_format
             [],            # rows
             "ORA-00942: table or view does not exist",
             None,          # lastrowid (rowid bytes all zero -> no row)
             []),           # batch errors (none)
        )

    def test_tns_decode_token_oer_rowid(self):
        # Same OER frame as _04 but with a real (non-zero) rowid in the
        # rowid slot, so the decoder must render it as the trailing lastrowid.
        from oracle.tns import encode_sb4
        from oracle.types import rowid_to_string
        Obj, File, Block, Slot = 4, 2, 300, 7
        RowidBytes = (encode_sb4(Obj) + encode_sb4(File) + b"\x00"
                      + encode_sb4(Block) + encode_sb4(Slot))
        Data = bytes([
            0x04,
            0x01, 0x05,
            0x01, 0x04,
            0x00,
            0x02, 0x03, 0xae,
            0x00, 0x00,
            0x01, 0x01,
            0x01, 0x0b,
            0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]) + RowidBytes + bytes([
            0x00,
            0x00, 0x07,
            0x00,
            0x00,
            0x00,
            0x00, 0x00, 0x00,
            0x28,
        ]) + b"ORA-00942: table or view does not exist\n"
        Result = decode_token_oer(Data, (None, None, []))
        self.assertEqual(Result[6], rowid_to_string(Obj, File, Block, Slot))

    def test_tns_decode_token_rpa_00(self):
        Data = bytes([1,3,1,12,12,65,85,84,72,95,83,69,83,83,75,69,89,1,96,
                       254,64,49,48,65,55,51,69,54,68,65,51,48,66,54,67,65,53,
                       65,68,68,68,49,69,69,67,48,66,51,57,56,49,69,49,53,50,
                       67,66,54,67,68,67,65,54,51,56,54,69,68,54,68,65,50,66,
                       53,52,55,69,48,69,66,66,50,68,54,51,32,49,68,56,51,57,
                       67,69,56,52,54,69,67,54,68,69,70,49,53,54,69,67,49,50,
                       70,54,52,54,53,49,54,49,67,0,0,1,13,13,65,85,84,72,95,
                       86,70,82,95,68,65,84,65,1,20,20,66,48,51,49,52,53,67,55,
                       69,70,54,48,67,65,54,57,51,69,49,68,2,27,37,1,26,26,65,
                       85,84,72,95,71,76,79,66,65,76,76,89,95,85,78,73,81,85,
                       69,95,68,66,73,68,0,1,32,32,54,54,56,65,53,51,70,50,50,
                       68,69,48,68,65,50,57,69,54,69,69,48,69,70,70,49,50,53,
                       67,49,50,57,56,0,4,1,1,1,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                       0,0,0,0,0,3,0,0])
        SessKey = b"10A73E6DA30B6CA5ADDD1EEC0B3981E152CB6CDCA6386ED6DA2B547E0EBB2D631D839CE846EC6DEF156EC12F6465161C"
        Salt = b"B03145C7EF60CA693E1D"
        DerivedSalt = None
        self.assertEqual(decode_token_rpa(Data, None), (TTI_SESS, SessKey, Salt, DerivedSalt))

    def test_tns_decode_token_rpa_01(self):
        Data = bytes([1,39,1,19,19,65,85,84,72,95,86,69,82,83,73,79,78,95,83,
                       84,82,73,78,71,1,18,18,45,32,54,52,98,105,116,32,80,114,
                       111,100,117,99,116,105,111,110,0,1,16,16,65,85,84,72,95,
                       86,69,82,83,73,79,78,95,83,81,76,1,2,2,50,50,0,1,19,19,
                       65,85,84,72,95,88,65,67,84,73,79,78,95,84,82,65,73,84,
                       83,1,1,1,51,0,1,15,15,65,85,84,72,95,86,69,82,83,73,79,
                       78,95,78,79,1,9,9,49,56,54,54,52,55,48,52,48,0,1,19,19,
                       65,85,84,72,95,86,69,82,83,73,79,78,95,83,84,65,84,85,
                       83,1,1,1,48,0,1,21,21,65,85,84,72,95,67,65,80,65,66,73,
                       76,73,84,89,95,84,65,66,76,69,0,0,1,11,11,65,85,84,72,
                       95,68,66,78,65,77,69,1,2,2,88,69,0,1,17,17,65,85,84,72,
                       95,68,66,95,77,79,85,78,84,95,73,68,0,1,10,10,50,56,57,
                       56,53,48,56,54,52,50,0,1,11,11,65,85,84,72,95,68,66,95,
                       73,68,0,1,10,10,50,56,57,51,51,55,48,49,55,55,0,1,12,12,
                       65,85,84,72,95,85,83,69,82,95,73,68,1,1,1,53,0,1,15,15,
                       65,85,84,72,95,83,69,83,83,73,79,78,95,73,68,1,3,3,49,
                       54,48,0,1,15,15,65,85,84,72,95,83,69,82,73,65,76,95,78,
                       85,77,1,4,4,49,55,50,53,0,1,16,16,65,85,84,72,95,73,78,
                       83,84,65,78,67,69,95,78,79,1,1,1,49,0,1,16,16,65,85,84,
                       72,95,70,65,73,76,79,86,69,82,95,73,68,1,1,1,49,0,1,15,
                       15,65,85,84,72,95,83,69,82,86,69,82,95,80,73,68,1,5,5,
                       49,52,55,48,52,0,1,19,19,65,85,84,72,95,83,67,95,83,69,
                       82,86,69,82,95,72,79,83,84,1,12,12,101,57,100,98,52,50,
                       50,55,54,48,49,53,0,1,21,21,65,85,84,72,95,83,67,95,68,
                       66,85,78,73,81,85,69,95,78,65,77,69,1,2,2,88,69,0,1,21,
                       21,65,85,84,72,95,83,67,95,73,78,83,84,65,78,67,69,95,
                       78,65,77,69,1,2,2,88,69,0,1,20,20,65,85,84,72,95,83,67,
                       95,83,69,82,86,73,67,69,95,78,65,77,69,1,9,9,83,89,83,
                       36,85,83,69,82,83,0,1,19,19,65,85,84,72,95,83,67,95,73,
                       78,83,84,65,78,67,69,95,73,68,1,1,1,49,0,1,27,27,65,85,
                       84,72,95,83,67,95,73,78,83,84,65,78,67,69,95,83,84,65,
                       82,84,95,84,73,77,69,1,36,36,50,48,49,57,45,48,56,45,50,
                       55,32,48,57,58,53,55,58,52,56,46,48,48,48,48,48,48,48,
                       48,48,32,43,48,48,58,48,48,0,1,17,17,65,85,84,72,95,83,
                       67,95,68,66,95,68,79,77,65,73,78,0,0,1,17,17,65,85,84,
                       72,95,83,67,95,83,86,67,95,70,76,65,71,83,1,1,1,48,0,1,
                       17,17,65,85,84,72,95,73,78,83,84,65,78,67,69,78,65,77,
                       69,1,2,2,88,69,0,1,15,15,65,85,84,72,95,78,76,83,95,76,
                       88,76,65,78,0,1,8,8,65,77,69,82,73,67,65,78,0,1,22,22,
                       65,85,84,72,95,78,76,83,95,76,88,67,84,69,82,82,73,84,
                       79,82,89,0,1,7,7,65,77,69,82,73,67,65,0,1,21,21,65,85,
                       84,72,95,78,76,83,95,76,88,67,67,85,82,82,69,78,67,89,0,
                       1,1,1,36,0,1,20,20,65,85,84,72,95,78,76,83,95,76,88,67,
                       73,83,79,67,85,82,82,0,1,7,7,65,77,69,82,73,67,65,0,1,
                       21,21,65,85,84,72,95,78,76,83,95,76,88,67,78,85,77,69,
                       82,73,67,83,0,1,2,2,46,44,0,1,19,19,65,85,84,72,95,78,
                       76,83,95,76,88,67,68,65,84,69,70,77,0,1,9,9,68,68,45,77,
                       79,78,45,82,82,0,1,21,21,65,85,84,72,95,78,76,83,95,76,
                       88,67,68,65,84,69,76,65,78,71,0,1,8,8,65,77,69,82,73,67,
                       65,78,0,1,17,17,65,85,84,72,95,78,76,83,95,76,88,67,83,
                       79,82,84,0,1,6,6,66,73,78,65,82,89,0,1,21,21,65,85,84,
                       72,95,78,76,83,95,76,88,67,67,65,76,69,78,68,65,82,0,1,
                       9,9,71,82,69,71,79,82,73,65,78,0,1,21,21,65,85,84,72,95,
                       78,76,83,95,76,88,67,85,78,73,79,78,67,85,82,0,1,1,1,36,
                       0,1,19,19,65,85,84,72,95,78,76,83,95,76,88,67,84,73,77,
                       69,70,77,0,1,14,14,72,72,46,77,73,46,83,83,88,70,70,32,
                       65,77,0,1,19,19,65,85,84,72,95,78,76,83,95,76,88,67,83,
                       84,77,80,70,77,0,1,24,24,68,68,45,77,79,78,45,82,82,32,
                       72,72,46,77,73,46,83,83,88,70,70,32,65,77,0,1,19,19,65,
                       85,84,72,95,78,76,83,95,76,88,67,84,84,90,78,70,77,0,1,
                       18,18,72,72,46,77,73,46,83,83,88,70,70,32,65,77,32,84,
                       90,82,0,1,19,19,65,85,84,72,95,78,76,83,95,76,88,67,83,
                       84,90,78,70,77,0,1,28,28,68,68,45,77,79,78,45,82,82,32,
                       72,72,46,77,73,46,83,83,88,70,70,32,65,77,32,84,90,82,0,
                       1,17,17,65,85,84,72,95,83,86,82,95,82,69,83,80,79,78,83,
                       69,1,96,254,64,54,54,48,55,57,49,51,56,55,48,54,54,69,
                       65,53,53,69,55,48,67,51,70,68,67,68,57,48,49,66,55,54,
                       68,69,50,57,66,65,53,51,70,69,48,66,68,66,55,52,52,56,
                       50,56,65,66,54,50,55,51,56,50,52,68,65,67,53,32,50,50,
                       54,67,51,68,50,56,49,56,70,52,69,53,48,53,49,50,53,57,
                       53,54,54,65,68,56,55,67,52,49,68,69,0,0,4,1,1,1,3,0,0,0,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,0,0])
        Resp = b"660791387066EA55E70C3FDCD901B76DE29BA53FE0BDB744828AB6273824DAC5226C3D2818F4E5051259566AD87C41DE"
        # Full packed AUTH_VERSION_NO (0x0b200200 = 11.2.0.2.0); the connection
        # masks the major release out of this for its protocol gate.
        Ver = 186647040
        SessId = b"160"
        self.assertEqual(decode_token_rpa(Data, None), (TTI_AUTH, Resp, Ver, SessId))

from oracle.tns import decode_chr
from oracle.tns import decode_kv
from oracle.tns import decode_ub4

class TestTnsBaseDecoders(unittest.TestCase):

    def test_decode_ub4_0(self):
        self.assertEqual(decode_ub4(bytes([0])), (0, b""))

    def test_decode_ub4_1(self):
        self.assertEqual(decode_ub4(bytes([1,171])), (0xAB, b""))

    def test_decode_ub4_2(self):
        self.assertEqual(decode_ub4(bytes([2,171,205])), (0xABCD, b""))

    def test_decode_ub4_3(self):
        self.assertEqual(decode_ub4(bytes([3,171,205,239])), (0xABCDEF, b""))

    def test_decode_ub4_4(self):
        self.assertEqual(decode_ub4(bytes([4,171,205,239,135])), (0xABCDEF87, b""))

    def test_decode_ub4_from_stream(self):
        Data = bytes([3,171,205,239,1,2,3,4,5])
        self.assertEqual(decode_ub4(Data), (0xABCDEF, bytes([1,2,3,4,5])))

    def test_decode_chr_0(self):
        self.assertEqual(decode_chr(bytes([5,104,101,108,108,111])), (b"hello", b""))

    def test_decode_chr_1(self):
        Input = bytes([254,64,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,7,72,72,72,72,72,72,72,0])
        Output = b"HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
        self.assertEqual(decode_chr(Input), (Output, b""))

    def test_decode_chr_2(self):
        Input = bytes([254,64,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,64,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,72,
  72,72,72,72,72,72,13,72,72,72,72,72,72,72,72,72,72,72,72,72,0])
        Output = b"HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
        self.assertEqual(decode_chr(Input), (Output, b""))

    def test_decode_kv_00(self):
        Data = bytes([1,12,12,65,85,84,72,95,77,65,67,72,73,78,69,1,11,11,69,120,97,109,112,108,101,72,111,115,116,0])
        self.assertEqual(decode_kv(Data, 1, []), ([(b"AUTH_MACHINE", b"ExampleHost")], b""), )

    def test_decode_kv_01(self):
        Data = bytes([1,12,12,65,85,84,72,95,83,69,83,83,75,69,89,1,96,254,64,52,66,66,
             49,51,66,65,54,67,53,54,52,70,66,52,56,55,48,66,56,67,55,70,68,48,
             68,68,55,57,65,51,49,68,53,54,56,66,55,53,50,48,66,57,54,56,65,50,
             53,56,53,53,53,65,49,65,52,54,68,65,65,55,51,53,70,32,49,55,51,70,
             57,51,52,56,66,70,69,54,52,48,67,70,55,67,68,56,66,54,65,57,55,52,
             50,55,54,48,48,57,0,0,1,13,13,65,85,84,72,95,86,70,82,95,68,65,84,
             65,1,20,20,66,48,51,49,52,53,67,55,69,70,54,48,67,65,54,57,51,69,
             49,68,2,27,37,1,26,26,65,85,84,72,95,71,76,79,66,65,76,76,89,95,
             85,78,73,81,85,69,95,68,66,73,68,0,1,32,32,54,54,56,65,53,51,70,
             50,50,68,69,48,68,65,50,57,69,54,69,69,48,69,70,70,49,50,53,67,49,
             50,57,56,0,4,1,1,1,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3,0,0])
        Remainder = bytes([4,1,1,1,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3,0,0])
        KVs = [
            (b"AUTH_GLOBALLY_UNIQUE_DBID\x00", b"668A53F22DE0DA29E6EE0EFF125C1298"),
            (b"AUTH_SESSKEY", b"4BB13BA6C564FB4870B8C7FD0DD79A31D568B7520B968A258555A1A46DAA735F173F9348BFE640CF7CD8B6A974276009"),
            (b"AUTH_VFR_DATA", b"B03145C7EF60CA693E1D")
        ]
        self.assertEqual(decode_kv(Data, 3, []), (KVs, Remainder))

    def test_decode_kv_02(self):
        Data = bytes([1,19,19,65,85,84,72,95,86,69,82,83,73,79,78,95,83,84,82,73,78,71,
             1,18,18,45,32,54,52,98,105,116,32,80,114,111,100,117,99,116,105,
             111,110,0,1,16,16,65,85,84,72,95,86,69,82,83,73,79,78,95,83,81,76,
             1,2,2,50,50,0,1,19,19,65,85,84,72,95,88,65,67,84,73,79,78,95,84,
             82,65,73,84,83,1,1,1,51,0,1,15,15,65,85,84,72,95,86,69,82,83,73,
             79,78,95,78,79,1,9,9,49,56,54,54,52,55,48,52,48,0,1,19,19,65,85,
             84,72,95,86,69,82,83,73,79,78,95,83,84,65,84,85,83,1,1,1,48,0,1,
             21,21,65,85,84,72,95,67,65,80,65,66,73,76,73,84,89,95,84,65,66,76,
             69,0,0,1,11,11,65,85,84,72,95,68,66,78,65,77,69,1,2,2,88,69,0,1,
             17,17,65,85,84,72,95,68,66,95,77,79,85,78,84,95,73,68,0,1,10,10,
             50,56,57,56,53,48,56,54,52,50,0,1,11,11,65,85,84,72,95,68,66,95,
             73,68,0,1,10,10,50,56,57,51,51,55,48,49,55,55,0,1,12,12,65,85,84,
             72,95,85,83,69,82,95,73,68,1,1,1,53,0,1,15,15,65,85,84,72,95,83,
             69,83,83,73,79,78,95,73,68,1,2,2,54,55,0,1,15,15,65,85,84,72,95,
             83,69,82,73,65,76,95,78,85,77,1,5,5,49,49,50,48,55,0,1,16,16,65,
             85,84,72,95,73,78,83,84,65,78,67,69,95,78,79,1,1,1,49,0,1,16,16,
             65,85,84,72,95,70,65,73,76,79,86,69,82,95,73,68,1,1,1,49,0,1,15,
             15,65,85,84,72,95,83,69,82,86,69,82,95,80,73,68,1,5,5,49,55,51,57,
             48,0,1,19,19,65,85,84,72,95,83,67,95,83,69,82,86,69,82,95,72,79,
             83,84,1,12,12,101,57,100,98,52,50,50,55,54,48,49,53,0,1,21,21,65,
             85,84,72,95,83,67,95,68,66,85,78,73,81,85,69,95,78,65,77,69,1,2,2,
             88,69,0,1,21,21,65,85,84,72,95,83,67,95,73,78,83,84,65,78,67,69,
             95,78,65,77,69,1,2,2,88,69,0,1,20,20,65,85,84,72,95,83,67,95,83,
             69,82,86,73,67,69,95,78,65,77,69,1,9,9,83,89,83,36,85,83,69,82,83,
             0,1,19,19,65,85,84,72,95,83,67,95,73,78,83,84,65,78,67,69,95,73,
             68,1,1,1,49,0,1,27,27,65,85,84,72,95,83,67,95,73,78,83,84,65,78,
             67,69,95,83,84,65,82,84,95,84,73,77,69,1,36,36,50,48,49,57,45,48,
             56,45,50,55,32,48,57,58,53,55,58,52,56,46,48,48,48,48,48,48,48,48,
             48,32,43,48,48,58,48,48,0,1,17,17,65,85,84,72,95,83,67,95,68,66,
             95,68,79,77,65,73,78,0,0,1,17,17,65,85,84,72,95,83,67,95,83,86,67,
             95,70,76,65,71,83,1,1,1,48,0,1,17,17,65,85,84,72,95,73,78,83,84,
             65,78,67,69,78,65,77,69,1,2,2,88,69,0,1,15,15,65,85,84,72,95,78,
             76,83,95,76,88,76,65,78,0,1,8,8,65,77,69,82,73,67,65,78,0,1,22,22,
             65,85,84,72,95,78,76,83,95,76,88,67,84,69,82,82,73,84,79,82,89,0,
             1,7,7,65,77,69,82,73,67,65,0,1,21,21,65,85,84,72,95,78,76,83,95,
             76,88,67,67,85,82,82,69,78,67,89,0,1,1,1,36,0,1,20,20,65,85,84,72,
             95,78,76,83,95,76,88,67,73,83,79,67,85,82,82,0,1,7,7,65,77,69,82,
             73,67,65,0,1,21,21,65,85,84,72,95,78,76,83,95,76,88,67,78,85,77,
             69,82,73,67,83,0,1,2,2,46,44,0,1,19,19,65,85,84,72,95,78,76,83,95,
             76,88,67,68,65,84,69,70,77,0,1,9,9,68,68,45,77,79,78,45,82,82,0,1,
             21,21,65,85,84,72,95,78,76,83,95,76,88,67,68,65,84,69,76,65,78,71,
             0,1,8,8,65,77,69,82,73,67,65,78,0,1,17,17,65,85,84,72,95,78,76,83,
             95,76,88,67,83,79,82,84,0,1,6,6,66,73,78,65,82,89,0,1,21,21,65,85,
             84,72,95,78,76,83,95,76,88,67,67,65,76,69,78,68,65,82,0,1,9,9,71,
             82,69,71,79,82,73,65,78,0,1,21,21,65,85,84,72,95,78,76,83,95,76,
             88,67,85,78,73,79,78,67,85,82,0,1,1,1,36,0,1,19,19,65,85,84,72,95,
             78,76,83,95,76,88,67,84,73,77,69,70,77,0,1,14,14,72,72,46,77,73,
             46,83,83,88,70,70,32,65,77,0,1,19,19,65,85,84,72,95,78,76,83,95,
             76,88,67,83,84,77,80,70,77,0,1,24,24,68,68,45,77,79,78,45,82,82,
             32,72,72,46,77,73,46,83,83,88,70,70,32,65,77,0,1,19,19,65,85,84,
             72,95,78,76,83,95,76,88,67,84,84,90,78,70,77,0,1,18,18,72,72,46,
             77,73,46,83,83,88,70,70,32,65,77,32,84,90,82,0,1,19,19,65,85,84,
             72,95,78,76,83,95,76,88,67,83,84,90,78,70,77,0,1,28,28,68,68,45,
             77,79,78,45,82,82,32,72,72,46,77,73,46,83,83,88,70,70,32,65,77,32,
             84,90,82,0,1,17,17,65,85,84,72,95,83,86,82,95,82,69,83,80,79,78,
             83,69,1,96,254,64,70,48,67,48,51,67,48,69,65,57,68,57,51,50,66,66,
             66,70,67,49,52,52,51,55,51,53,51,53,53,70,69,52,49,68,65,53,65,56,
             65,50,66,67,52,50,68,68,55,70,48,70,54,70,52,66,48,65,70,49,52,54,
             56,65,51,52,32,69,57,52,48,50,67,49,53,56,55,57,53,50,48,56,48,48,
             50,56,66,53,67,52,70,50,51,67,66,69,52,56,66,0,0,4,1,1,1,3,0,0,0,
             0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,0,0])
        Remainder = bytes([4,1,1,1,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,0,0])
        KVs = [
            (b'AUTH_CAPABILITY_TABLE', None),
            (b'AUTH_DBNAME', b'XE'),
            (b'AUTH_DB_ID\x00', b'2893370177'),
            (b'AUTH_DB_MOUNT_ID\x00', b'2898508642'),
            (b'AUTH_FAILOVER_ID', b'1'),
            (b'AUTH_INSTANCENAME', b'XE'),
            (b'AUTH_INSTANCE_NO', b'1'),
            (b'AUTH_NLS_LXCCALENDAR\x00', b'GREGORIAN'),
            (b'AUTH_NLS_LXCCURRENCY\x00', b'$'),
            (b'AUTH_NLS_LXCDATEFM\x00', b'DD-MON-RR'),
            (b'AUTH_NLS_LXCDATELANG\x00', b'AMERICAN'),
            (b'AUTH_NLS_LXCISOCURR\x00', b'AMERICA'),
            (b'AUTH_NLS_LXCNUMERICS\x00', b'.,'),
            (b'AUTH_NLS_LXCSORT\x00', b'BINARY'),
            (b'AUTH_NLS_LXCSTMPFM\x00', b'DD-MON-RR HH.MI.SSXFF AM'),
            (b'AUTH_NLS_LXCSTZNFM\x00', b'DD-MON-RR HH.MI.SSXFF AM TZR'),
            (b'AUTH_NLS_LXCTERRITORY\x00', b'AMERICA'),
            (b'AUTH_NLS_LXCTIMEFM\x00', b'HH.MI.SSXFF AM'),
            (b'AUTH_NLS_LXCTTZNFM\x00', b'HH.MI.SSXFF AM TZR'),
            (b'AUTH_NLS_LXCUNIONCUR\x00', b'$'),
            (b'AUTH_NLS_LXLAN\x00', b'AMERICAN'),
            (b'AUTH_SC_DBUNIQUE_NAME', b'XE'),
            (b'AUTH_SC_DB_DOMAIN', None),
            (b'AUTH_SC_INSTANCE_ID', b'1'),
            (b'AUTH_SC_INSTANCE_NAME', b'XE'),
            (b'AUTH_SC_INSTANCE_START_TIME', b'2019-08-27 09:57:48.000000000 +00:00'),
            (b'AUTH_SC_SERVER_HOST', b'e9db42276015'),
            (b'AUTH_SC_SERVICE_NAME', b'SYS$USERS'),
            (b'AUTH_SC_SVC_FLAGS', b'0'),
            (b'AUTH_SERIAL_NUM', b'11207'),
            (b'AUTH_SERVER_PID', b'17390'),
            (b'AUTH_SESSION_ID', b'67'),
            (b'AUTH_SVR_RESPONSE', b'F0C03C0EA9D932BBBFC1443735355FE41DA5A8A2BC42DD7F0F6F4B0AF1468A34E9402C1587952080028B5C4F23CBE48B'),
            (b'AUTH_USER_ID', b'5'),
            (b'AUTH_VERSION_NO', b'186647040'),
            (b'AUTH_VERSION_SQL', b'22'),
            (b'AUTH_VERSION_STATUS', b'0'),
            (b'AUTH_VERSION_STRING', b'- 64bit Production'),
            (b'AUTH_XACTION_TRAITS', b'3')
        ]
        self.assertEqual(decode_kv(Data, 39, []), (KVs, Remainder))

if __name__ == '__main__':
    unittest.main()
