# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Golden test: the 11g PRO/DTY handshake replies are now GENERATED from the
server's named identity pieces (seerdb.server._handshake_11g) rather than stored
as verbatim DATA packets. These captures, from a live XE 11.2 listener, pin the
builders byte-for-byte so the Mirror stays wire-identical to the real server.
"""

import unittest

from seerdb.common.tns import encode_packet
from seerdb.common.tns_consts import DEFAULT_SDU, TNS_DATA
from seerdb.server import _handshake_11g as H

# --- captured golden packets (live XE 11.2) ---
PRO_REPLY = bytes.fromhex(
    '00ee00000600000000000106007838365f36342f4c696e757820322e342e7878006903010a00'
    '6603400301400366030166034803014803660301660352030152036603016603610301610366'
    '030166031f03081f0366030100640000006001240f050b0c030c0c0504050d06090708050505'
    '05050f05050505050a050505050504050607080823472347081123081141b0470083036907d0'
    '0300000000000000000000000000000000000000000000000000000000000000000000000000'
    '27060101010f010106010101010101017fff030a030301007f017fff010601013f0103060001'
    '03020702010001180003'
)
DTY_REPLY = bytes.fromhex(
    '039c0000060000000000020101010002020a00080801000c0c0a001717010018180100191901'
    '001a1a01001b1b01001c1c01001d1d01001e1e01001f1f010020200100212101000a0a01000b'
    '0b01002828010029290100757501007878010022220100232301002424010025250100262601'
    '002a2a01002b2b01002c2c01002d2d01002e2e01002f2f010030300100313101003232010033'
    '3301003434010035350100363601003737010038380100393901003b3b01003c3c01003d3d01'
    '003e3e01003f3f0100404001004141010042420100434301004747010048480100494901004b'
    '4b01004d4d01004e4e01004f4f01005050010051510100525201005353010054540100555501'
    '00565601005757010058580100595901005a5a01005c5c01005d5d0100626201006363010067'
    '6701006b6b01007c7c01007d7d01007e7e01007f7f0100808001008181010082820100838301'
    '0084840100858501008686010087870100898901008a8a01008b8b01008c8c01008d8d01008e'
    '8e01008f8f01009090010091910100949401009595010096960100979701009d9d01009e9e01'
    '009f9f0100a0a00100a1a10100a2a20100a3a30100a4a40100a5a50100a6a60100a7a70100a8'
    'a80100a9a90100aaaa0100abab0100adad0100aeae0100afaf0100b0b00100b1b10100c1c101'
    '00c2c20100c6c60100c7c70100c8c80100c9c90100caca0100cbcb0100cccc0100cdcd0100ce'
    'ce0100cfcf0100d2d20100d3d30100d4d40100d5d50100d6d60100d7d70100d8d80100d9d901'
    '00dada0100dbdb0100dcdc0100dddd0100dede0100dfdf0100e0e00100e1e10100e2e20100e3'
    'e30100e4e40100e5e50100e6e60100eaea0100ebeb0100ecec0100eded0100eeee0100efef01'
    '00f0f00100f2f20100f3f30100f4f40100f5f50100f600fd00fe0003020a0004020a00050101'
    '0006020a0007020a00090101000d000e000f1701001000110012001300140015001600277801'
    '003a0044020a00450046004a004c005b020a005e0101005f1701006060010061600100646401'
    '006565010066660100680069006a6a01006c6d01006d6d01006e6f01006f6f01007070010071'
    '7101007272010073730100746601007600770079007a007b008800929201009393010098020a'
    '0099020a009a020a009b0101009c0c0a00ac020a00b2b20100b3b30100b4b40100b5b50100b6'
    'b60100b7b70100b800b900ba00bb00bc00bd00be00bf00c000c300c400c500d0d00100d100e7'
    'e70100e800e9e90100f10000'
)
PRO_REPLY_SQLPLUS = bytes.fromhex(
    '007f0000060000000000deadbeef0075000000000004000004000300000000000400050b2002'
    '0000020006001f000e0001deadbeef000300000002000400010001000200000000000400050b'
    '20020000020006fbff0002000200000000000400050b20020000010002000003000200000000'
    '000400050b2002000001000200'
)
DTY_REPLY_SQLPLUS = bytes.fromhex(
    '00ee00000600000000000106007838365f36342f4c696e757820322e342e7878006903010a00'
    '6603400301400366030166034803014803660301660352030152036603016603610301610366'
    '030166031f03081f0366030100640000006001240f050b0c030c0c0504050d06090708050505'
    '05050f05050505050a050505050504050607080823472347081123081141b0470083036907d0'
    '0300000000000000000000000000000000000000000000000000000000000000000000000000'
    '27060101010f010106010101010101017fff030a030301007f017fff010601013f0103060001'
    '03020702010001180003'
)
TYPE_REPLY_SQLPLUS = bytes.fromhex(
    '001a000006000000000002800000003c3c3c800000000000000e'
)


def _framed(payload):
    packet, _ = encode_packet(TNS_DATA, payload, DEFAULT_SDU)
    return packet


class TestHandshakeGeneration(unittest.TestCase):
    def test_caps_block_is_thin_pro_reply(self):
        self.assertEqual(_framed(H.build_caps_block_reply()), PRO_REPLY)

    def test_caps_block_is_sqlplus_dty_reply(self):
        # the same capability block serves the sqlplus DTY reply (de-duped)
        self.assertEqual(_framed(H.build_caps_block_reply()), DTY_REPLY_SQLPLUS)
        self.assertEqual(PRO_REPLY, DTY_REPLY_SQLPLUS)

    def test_dty_type_reply(self):
        self.assertEqual(_framed(H.build_dty_type_reply()), DTY_REPLY)

    def test_pro_sqlplus_reply(self):
        self.assertEqual(_framed(H.build_pro_sqlplus_reply()), PRO_REPLY_SQLPLUS)

    def test_type_reply_sqlplus(self):
        self.assertEqual(_framed(H.build_type_reply_sqlplus()), TYPE_REPLY_SQLPLUS)

    def test_banner_is_readable(self):
        self.assertIn(b'x86_64/Linux', H.build_caps_block_reply())


class DtyTableCodecTest(unittest.TestCase):
    """The fv2/8i DATA_TYPES conversion tables are generated from entry lists;
    pin the codec round-trip and that it reproduces both tables byte-for-byte."""

    def test_dty8i_and_server_tables_roundtrip(self):
        from seerdb.common.tns import (
            _DTY_8I,
            _DTY_8I_ENTRIES,
            _DTY_8I_HEADER,
            _SERVER_DTY_ENTRIES,
            _SERVER_DTY_TABLE,
            decode_dty_table,
            encode_dty_table,
        )

        # encode(entries) reproduces each table exactly
        self.assertEqual(_SERVER_DTY_TABLE, encode_dty_table(_SERVER_DTY_ENTRIES))
        self.assertEqual(_DTY_8I, _DTY_8I_HEADER + encode_dty_table(_DTY_8I_ENTRIES))
        # decode is the inverse of encode
        for entries in (_SERVER_DTY_ENTRIES, _DTY_8I_ENTRIES):
            body = encode_dty_table(entries)
            self.assertEqual(decode_dty_table(body), entries)


class CharsetElementsCodecTest(unittest.TestCase):
    """The TTI_PRO charset-element array is generated from an entry list; pin the
    codec round-trip and that it reproduces the captured block byte-for-byte."""

    def test_charset_elements_roundtrip(self):
        from seerdb.common.tns import (
            _PRO_CHARSET_ELEMENTS,
            _PRO_CHARSET_ENTRIES,
            decode_charset_elements,
            encode_charset_elements,
        )

        # encode(entries) reproduces the captured array exactly
        self.assertEqual(
            _PRO_CHARSET_ELEMENTS, encode_charset_elements(_PRO_CHARSET_ENTRIES)
        )
        # decode is the inverse of encode
        self.assertEqual(
            decode_charset_elements(_PRO_CHARSET_ELEMENTS), _PRO_CHARSET_ENTRIES
        )


class FdoBuilderTest(unittest.TestCase):
    """The FDO is built from named fields (the DB + national charset ids); pin that
    it reproduces the captured block and that a client can still locate the national
    charset inside it at offset 6 + fdo[5] + fdo[6]."""

    def test_fdo_reproduces_capture_and_locates_charset(self):
        import struct

        from seerdb.common.tns import _PRO_FDO, _build_pro_fdo
        from seerdb.common.tns_consts import AL16UTF16_CHARSET, AL32UTF8_CHARSET

        # the captured 11.2 FDO, byte-for-byte
        captured = bytes.fromhex(
            '0000006001240f050b0c030c0c0504050d0609070805050505050f05050505050a0505050505'
            '04050607080823472347081123081141b0470083036907d00300000000000000000000000000'
            '000000000000000000000000000000000000000000000000'
        )
        self.assertEqual(_build_pro_fdo(), captured)
        self.assertEqual(_PRO_FDO, captured)

        # a client reads the national charset at 6 + fdo[5] + fdo[6]; the DB charset
        # sits just before it — both are the driver's named constants.
        num3 = 6 + _PRO_FDO[5] + _PRO_FDO[6]
        self.assertEqual(
            struct.unpack('>H', _PRO_FDO[num3 + 1 : num3 + 3])[0], AL32UTF8_CHARSET
        )
        self.assertEqual(
            struct.unpack('>H', _PRO_FDO[num3 + 3 : num3 + 5])[0], AL16UTF16_CHARSET
        )


class ServerCapsTest(unittest.TestCase):
    """The server's compile/runtime capability vectors are modelled as named
    {index: value} feature maps; pin that they still render the captured bytes and
    that the field-version slot the client negotiates off reads back correctly."""

    def test_server_caps_reproduce_capture(self):
        from seerdb.common.tns import _SERVER_COMPILE_CAPS, _SERVER_RUNTIME_CAPS
        from seerdb.common.tns_consts import CCAP_FIELD_VERSION, FIELD_VERSION_11_2

        self.assertEqual(
            _SERVER_COMPILE_CAPS,
            bytes.fromhex(
                '060101010f010106010101010101017fff030a030301007f017fff010601013f01030600010302'
            ),
        )
        self.assertEqual(_SERVER_RUNTIME_CAPS, bytes.fromhex('02010001180003'))
        # the field version the client reads out of the server vector
        self.assertEqual(_SERVER_COMPILE_CAPS[CCAP_FIELD_VERSION], FIELD_VERSION_11_2)


if __name__ == '__main__':
    unittest.main()
