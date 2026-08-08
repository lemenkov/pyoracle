# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for the protocol-version-319 / large-SDU handshake (#155): the
# 4-byte ("large") packet framing and the extended-ACCEPT parse. The ACCEPT
# fixture is a real 23ai (23.26) accept body captured through the proxy.

import struct
import unittest

from oracle.connection import _parse_accept_eor, _parse_accept_sdu
from oracle.tns import (
    CCAP_TTC4,
    assemble_packet,
    decode_packet,
    encode_dictionary_dty,
    encode_dictionary_login,
    encode_packet,
)
from oracle.tns_consts import (
    TNS_CCAP_END_OF_RESPONSE,
    TNS_DATA,
    TTI_END_OF_RESPONSE,
    DictionaryType,
)


class TestLargePacketFraming(unittest.TestCase):
    def test_large_header_is_4byte_length(self):
        # A large-SDU DATA packet uses a 4-byte length at bytes 0-3, type at 4.
        (pkt, rest) = encode_packet(TNS_DATA, b'hello', 8192, True)
        self.assertIsNone(rest)
        self.assertEqual(struct.unpack('>I', pkt[:4])[0], len(pkt))
        self.assertEqual(pkt[4], TNS_DATA)
        self.assertEqual(pkt.endswith(b'hello'), True)

    def test_legacy_header_is_2byte_length(self):
        # Legacy framing keeps the 2-byte length at bytes 0-1 (default).
        (pkt, _) = encode_packet(TNS_DATA, b'hello', 8192, False)
        self.assertEqual(struct.unpack('>H', pkt[:2])[0], len(pkt))
        self.assertEqual(pkt[4], TNS_DATA)

    def test_roundtrip_large(self):
        (pkt, _) = encode_packet(TNS_DATA, b'payload-bytes', 8192, True)
        (flag, typ, body, rest) = assemble_packet(pkt, 8192, True)
        self.assertEqual(typ, TNS_DATA)
        self.assertEqual(body, b'payload-bytes')
        self.assertEqual(rest, b'')

    def test_roundtrip_legacy_unchanged(self):
        (pkt, _) = encode_packet(TNS_DATA, b'payload-bytes', 8192, False)
        (flag, typ, body, rest) = assemble_packet(pkt, 8192, False)
        self.assertEqual(typ, TNS_DATA)
        self.assertEqual(body, b'payload-bytes')

    def test_login_advertises_319(self):
        Dict = {
            'type': DictionaryType.login,
            'env': {
                'host': 'h',
                'port': 1,
                'user': 'u',
                'password': 'p',
                'sid': 'XE',
                'app_name': 'a',
            },
            'sdu': 8192,
        }
        out = encode_dictionary_login(Dict)
        self.assertEqual(struct.unpack('>H', out[:2])[0], 319)  # version
        self.assertEqual(struct.unpack('>H', out[2:4])[0], 300)  # compat floor
        self.assertEqual(struct.unpack('>H', out[18:20])[0], 74)  # connect-data offset


class TestEndOfResponseCap(unittest.TestCase):
    def _dty(self, supports_eor):
        Dict = {
            'type': DictionaryType.dty,
            'field_version': 24,
            'req': 873,
            'supports_eor': supports_eor,
        }
        return encode_dictionary_dty(Dict)

    def _ttc4(self, dty):
        # The compile-caps array is a length byte + array, after the 5-byte DTY
        # header (token + charset_in(2) + charset_out(2) + flag). Index by
        # CCAP_TTC4 into the array.
        caps_len = dty[6]
        caps = dty[7 : 7 + caps_len]
        return caps[CCAP_TTC4]

    def test_eor_bit_set_when_supported(self):
        self.assertTrue(self._ttc4(self._dty(True)) & TNS_CCAP_END_OF_RESPONSE)

    def test_eor_bit_clear_otherwise(self):
        self.assertFalse(self._ttc4(self._dty(False)) & TNS_CCAP_END_OF_RESPONSE)

    def test_end_of_response_token_is_terminal(self):
        # The EOR (29) marker terminates a response decode without raising.
        (flag, acc) = decode_packet(bytes([TTI_END_OF_RESPONSE]), (None, None, []))
        self.assertEqual(flag, True)


class TestAcceptParse(unittest.TestCase):
    # Real 23ai accept body (8-byte packet header already stripped): protocol
    # version 319, large SDU 8192 at offset 24, flags2 0x1a000000 at offset 33
    # (the 0x02000000 bit = end-of-response support).
    _ACCEPT = bytes.fromhex(
        '013f00010000000001000000003dc500000000000000000000'
        '00200000002000001a000000f0ac1eea6c5151fdc20891823652b87b'
    )

    def test_version_and_sdu(self):
        (ver,) = struct.unpack('>H', self._ACCEPT[:2])
        self.assertEqual(ver, 319)
        self.assertEqual(_parse_accept_sdu(ver, self._ACCEPT, 0x2000), 8192)

    def test_eor_bit_detected(self):
        (ver,) = struct.unpack('>H', self._ACCEPT[:2])
        self.assertTrue(_parse_accept_eor(ver, self._ACCEPT))

    def test_pre318_no_eor(self):
        # A legacy (version < 318) accept never reports EOR.
        self.assertFalse(_parse_accept_eor(313, self._ACCEPT))

    def test_pre315_keeps_legacy_sdu(self):
        # Below the large-SDU floor the 16-bit legacy SDU is kept.
        self.assertEqual(_parse_accept_sdu(313, self._ACCEPT, 0x2000), 0x2000)


if __name__ == '__main__':
    unittest.main()
