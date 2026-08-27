# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The 11g server's fixed identity for the PRO / DTY handshake replies.

The Mirror answers the protocol (PRO) and data-type (DTY) negotiation with a
real XE 11.2 listener's replies (PROTOCOL.md §4.1). Rather than store the whole
DATA packets verbatim, the server's fixed identity is kept as named pieces —
the version banner, charset, the server capability vectors, and the
type-conversion table — and the builders below assemble the TTC payload (the
packet header is added by ``encode_packet``). Two dialects (§4.1):

- **TTI_PRO (0x01)** — python-oracledb / seerdb. The same capability block is the
  thin PRO reply *and* the sqlplus/deadbeef DTY reply (byte-identical, so one
  builder serves both). The thin DTY reply is the type-conversion table.
- **sqlplus `deadbeef`** — the PRO reply and the extra third-round type reply are
  opaque negotiation blocks kept verbatim.

The values are the server's identity, captured once from a live XE 11.2 server;
``tests/test_handshake_generation.py`` pins the builders to those captures
byte-for-byte so the Mirror stays wire-identical to the real server.
"""

import struct

from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    FIELD_VERSION_11_2,
    TTI_DTY,
    TTI_PRO,
)

# --- the TTI_PRO capability block (thin PRO reply == sqlplus DTY reply) ---
_SERVER_PRO_VERSION = FIELD_VERSION_11_2  # negotiates field version 6 (11g)
_SERVER_BANNER = b'x86_64/Linux 2.4.xx'
_PRO_CHARSET_ID = struct.pack('<H', AL32UTF8_CHARSET)  # AL32UTF8 (873), LE
_PRO_FLAGS = 1
_PRO_CHARSET_ELEMENTS = bytes.fromhex(  # 10 x 5-byte charset elements
    '6603400301400366030166034803014803660301660352030152036603016603610301610366'
    '030166031f03081f03660301'
)
_PRO_FDO = bytes.fromhex(  # 100-byte fixed descriptor block
    '0000006001240f050b0c030c0c0504050d0609070805050505050f05050505050a0505050505'
    '04050607080823472347081123081141b0470083036907d00300000000000000000000000000'
    '000000000000000000000000000000000000000000000000'
)
_SERVER_COMPILE_CAPS = bytes.fromhex(  # 39-byte server 11g compile caps
    '060101010f010106010101010101017fff030a030301007f017fff010601013f01030600010302'
)
_SERVER_RUNTIME_CAPS = bytes.fromhex('02010001180003')  # 7-byte server runtime caps

# --- the thin DTY reply: the server's type-conversion table ---
_SERVER_DTY_TABLE = bytes.fromhex(  # 913-byte type-conversion table
    '0101010002020a00080801000c0c0a001717010018180100191901001a1a01001b1b01001c1c'
    '01001d1d01001e1e01001f1f010020200100212101000a0a01000b0b01002828010029290100'
    '757501007878010022220100232301002424010025250100262601002a2a01002b2b01002c2c'
    '01002d2d01002e2e01002f2f0100303001003131010032320100333301003434010035350100'
    '363601003737010038380100393901003b3b01003c3c01003d3d01003e3e01003f3f01004040'
    '01004141010042420100434301004747010048480100494901004b4b01004d4d01004e4e0100'
    '4f4f010050500100515101005252010053530100545401005555010056560100575701005858'
    '0100595901005a5a01005c5c01005d5d01006262010063630100676701006b6b01007c7c0100'
    '7d7d01007e7e01007f7f01008080010081810100828201008383010084840100858501008686'
    '010087870100898901008a8a01008b8b01008c8c01008d8d01008e8e01008f8f010090900100'
    '91910100949401009595010096960100979701009d9d01009e9e01009f9f0100a0a00100a1a1'
    '0100a2a20100a3a30100a4a40100a5a50100a6a60100a7a70100a8a80100a9a90100aaaa0100'
    'abab0100adad0100aeae0100afaf0100b0b00100b1b10100c1c10100c2c20100c6c60100c7c7'
    '0100c8c80100c9c90100caca0100cbcb0100cccc0100cdcd0100cece0100cfcf0100d2d20100'
    'd3d30100d4d40100d5d50100d6d60100d7d70100d8d80100d9d90100dada0100dbdb0100dcdc'
    '0100dddd0100dede0100dfdf0100e0e00100e1e10100e2e20100e3e30100e4e40100e5e50100'
    'e6e60100eaea0100ebeb0100ecec0100eded0100eeee0100efef0100f0f00100f2f20100f3f3'
    '0100f4f40100f5f50100f600fd00fe0003020a0004020a000501010006020a0007020a000901'
    '01000d000e000f1701001000110012001300140015001600277801003a0044020a0045004600'
    '4a004c005b020a005e0101005f17010060600100616001006464010065650100666601006800'
    '69006a6a01006c6d01006d6d01006e6f01006f6f010070700100717101007272010073730100'
    '746601007600770079007a007b008800929201009393010098020a0099020a009a020a009b01'
    '01009c0c0a00ac020a00b2b20100b3b30100b4b40100b5b50100b6b60100b7b70100b800b900'
    'ba00bb00bc00bd00be00bf00c000c300c400c500d0d00100d100e7e70100e800e9e90100f100'
    '00'
)

# --- opaque deadbeef-dialect blocks (kept verbatim) ---
_PRO_SQLPLUS_PAYLOAD = bytes.fromhex(  # 117-byte deadbeef PRO / ANO reply
    'deadbeef0075000000000004000004000300000000000400050b20020000020006001f000e00'
    '01deadbeef000300000002000400010001000200000000000400050b20020000020006fbff00'
    '02000200000000000400050b20020000010002000003000200000000000400050b2002000001'
    '000200'
)
_TYPE_REPLY_SQLPLUS_PAYLOAD = bytes.fromhex(  # 26B third-round type reply
    '02800000003c3c3c800000000000000e'
)


def build_caps_block_reply() -> bytes:
    """The TTI_PRO capability block as a TTC payload (no packet header): version
    banner, charset, the charset-element array, the fixed descriptor, and the
    server 11g capability vectors. Serves both the thin PRO reply and the
    sqlplus/deadbeef DTY reply (they are byte-identical)."""
    return (
        bytes([TTI_PRO, _SERVER_PRO_VERSION, 0])
        + _SERVER_BANNER
        + b'\x00'
        + _PRO_CHARSET_ID
        + bytes([_PRO_FLAGS])
        + struct.pack('<H', len(_PRO_CHARSET_ELEMENTS) // 5)
        + _PRO_CHARSET_ELEMENTS
        + struct.pack('>H', len(_PRO_FDO))
        + _PRO_FDO
        + bytes([len(_SERVER_COMPILE_CAPS)])
        + _SERVER_COMPILE_CAPS
        + bytes([len(_SERVER_RUNTIME_CAPS)])
        + _SERVER_RUNTIME_CAPS
    )


def build_dty_type_reply() -> bytes:
    """The thin DTY reply as a TTC payload: TTI_DTY then the server's
    type-conversion table."""
    return bytes([TTI_DTY]) + _SERVER_DTY_TABLE


def build_pro_sqlplus_reply() -> bytes:
    """The sqlplus/deadbeef PRO reply payload (also the ANO null-negotiation
    reply). An opaque negotiation block, kept verbatim."""
    return _PRO_SQLPLUS_PAYLOAD


def build_type_reply_sqlplus() -> bytes:
    """The deadbeef dialect's third-round type reply payload (#265)."""
    return _TYPE_REPLY_SQLPLUS_PAYLOAD
