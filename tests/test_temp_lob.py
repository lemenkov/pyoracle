# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the temporary-LOB bind path (#91).

Large CLOB / BLOB values can't be bound into a PL/SQL locator parameter through
the streamed path (ORA-01460); the driver allocates a server temp LOB
(TTI_LOBOPS CREATE_TEMP), streams the value in (WRITE) and binds the locator.
These tests pin the request/response wire bytes reverse-engineered from
python-oracledb on 21c (docs/PROTOCOL.md §14) — no server needed.
"""

import struct
import unittest

from seerdb.datatypes import TempLob
from seerdb.tns import (
    _DECODE_FIELD_VERSION,
    _ENCODE_FIELD_VERSION,
    decode_lobops_oer,
    encode_dictionary_lobops,
    encode_token_oac,
    encode_token_rxd,
)
from seerdb.tns_consts import TNS_LOB_OP_WRITE


class _FieldVersionIsolated(unittest.TestCase):
    """Restore the encode/decode field-version context vars after each test.

    The bind/OER fixtures here advertise a 12c+ field version; without a reset
    that mutation leaks (context vars persist across tests in one process) and
    breaks later 11g-default tests."""

    def setUp(self):
        self._enc = _ENCODE_FIELD_VERSION.set(_ENCODE_FIELD_VERSION.get())
        self._dec = _DECODE_FIELD_VERSION.set(_DECODE_FIELD_VERSION.get())
        self.addCleanup(lambda: _ENCODE_FIELD_VERSION.reset(self._enc))
        self.addCleanup(lambda: _DECODE_FIELD_VERSION.reset(self._dec))


# A real 38-byte temp-LOB locator captured from a 21c CREATE_TEMP response.
LOCATOR = bytes.fromhex(
    '0001820880010002e31e00000129000000010369000a000000010000a62b6539000000010000'
)


class CreateTempEncode(unittest.TestCase):
    def test_clob_body(self):
        Body = encode_dictionary_lobops({'seq': 3, 'create_temp': True})[3:]
        # type 0x70 (CLOB), trailing sb4 0x0369; captured verbatim.
        self.assertEqual(
            Body.hex(),
            '01012800010a0000010001020110000001010170' + '00' * 47 + '020369',
        )

    def test_blob_body(self):
        Body = encode_dictionary_lobops(
            {'seq': 3, 'create_temp': True, 'is_blob': True}
        )[3:]
        # type 0x71 (BLOB) — one byte shorter type spec than CLOB.
        self.assertEqual(
            Body.hex(), '01012800010a00000100010201100000000171' + '00' * 47 + '020369'
        )


class WriteEncode(unittest.TestCase):
    def _write(self, data):
        return encode_dictionary_lobops(
            {'seq': 4, 'operation': TNS_LOB_OP_WRITE, 'locator': LOCATOR, 'data': data}
        )

    def test_short_inline(self):
        # "HI" UTF-16BE -> 0x0E marker + ub1 length 4 + data, locator ub2-prefixed.
        Out = self._write('HI'.encode('utf-16-be'))
        self.assertEqual(
            Out,
            bytes.fromhex('0360040101280000000000000001400000010100000000000000000026')
            + LOCATOR
            + bytes.fromhex('0e0400480049'),
        )

    def test_chunked_large(self):
        # > 0xFC bytes -> 0x0E + 0xFE + (<sb4 chunklen><chunk>)... + 0x00.
        Data = ('Z' * 60000).encode('utf-16-be')  # 120000 bytes
        Out = self._write(Data)
        Tail = Out[Out.index(LOCATOR) + len(LOCATOR) :]
        self.assertEqual(Tail[:2].hex(), '0efe')
        i, chunks = 2, []
        while i < len(Tail):
            n = Tail[i]
            if n == 0:
                break
            ln = int.from_bytes(Tail[i + 1 : i + 1 + n], 'big')
            i += 1 + n + ln
            chunks.append(ln)
        self.assertEqual(chunks, [32767, 32767, 32767, 21699])
        self.assertEqual(sum(chunks), len(Data))


class BindEncode(_FieldVersionIsolated):
    def setUp(self):
        super().setUp()
        _ENCODE_FIELD_VERSION.set(16)  # 21c

    def test_clob_oac(self):
        Oac = encode_token_oac(TempLob(LOCATOR, False, 400000))
        # type 0x70, LOB cont-flag 0x02000000, charset 873 (AL32UTF8), csfrm 1.
        self.assertEqual(Oac.hex(), '7001000003061a800004020000000000020369010000')

    def test_blob_oac(self):
        Oac = encode_token_oac(TempLob(LOCATOR, True, 60000))
        # type 0x71, cont-flag 0x02000000, charset 0, csfrm 0.
        self.assertEqual(Oac.hex(), '7101000002ea60000402000000000000000000')

    def test_rxd_descriptor(self):
        # LOB-descriptor prefix 01 28 28 + ub2 locator length + locator.
        Rxd = encode_token_rxd(TempLob(LOCATOR, False, 400000))
        self.assertEqual(
            Rxd, bytes.fromhex('012828') + struct.pack('>H', len(LOCATOR)) + LOCATOR
        )


class OerDecode(_FieldVersionIsolated):
    # The OER call status is 1 for a standalone op but 5 right after a PL/SQL
    # call; decode_lobops_oer must find the OER in both and report success.
    def test_call_status_1(self):
        Pkt = bytes.fromhex(
            '08002600018208800100028dc300000129000000010369000a000000'
            '010000a62b6539000000010000040101028598'
            + '00' * 21
            + '0800000000000000000000'
        )
        self.assertEqual(decode_lobops_oer(Pkt, 16), (0, None))

    def test_call_status_5(self):
        Pkt = bytes.fromhex(
            '08002600018208800100028dc300000129000000020369000a000000'
            '010000a62b653900000001000004010502859b'
            + '00' * 21
            + '0b00000000000000000000'
        )
        self.assertEqual(decode_lobops_oer(Pkt, 16), (0, None))


if __name__ == '__main__':
    unittest.main()
