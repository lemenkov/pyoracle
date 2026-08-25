# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Codec tests for the Oracle Advanced Networking (ANO) negotiation (#437).

Offline byte-level checks of the negotiation container, its services, and the
typed sub-packets. The wire layouts are re-expressed from the go-ora driver
(MIT); go-ora ships no ANO tests, so these known-answer bytes are computed by
hand from the format the server enforces (magic 0xDEADBEEF framing, big-endian).
"""

import struct
import unittest

from seerdb.common import ano


class TestSubpackets(unittest.TestCase):
    def test_ub1(self):
        # length(1) | type(2) | one byte.
        self.assertEqual(ano.sp_ub1(1), bytes.fromhex('0001000201'))

    def test_ub2(self):
        self.assertEqual(ano.sp_ub2(0x1234), bytes.fromhex('000200031234'))

    def test_ub4(self):
        self.assertEqual(ano.sp_ub4(0xDEADBEEF), bytes.fromhex('00040004deadbeef'))

    def test_version(self):
        self.assertEqual(ano.sp_version(), bytes.fromhex('0004000517000000'))

    def test_status(self):
        # length(2) | type(6) | status(2) = 0x001f (31).
        self.assertEqual(ano.sp_status(31), bytes.fromhex('00020006001f'))

    def test_string_and_bytes(self):
        self.assertEqual(
            ano.sp_string(b'AES256'), bytes.fromhex('00060000') + b'AES256'
        )
        self.assertEqual(ano.sp_bytes(b'\x01\x08'), bytes.fromhex('000200010108'))

    def test_ub2_array_layout_and_roundtrip(self):
        Enc = ano.sp_ub2_array([4, 1, 2, 3])
        # header length = 10 + 2*4 = 18 (0x12), type 1; then DEADBEEF|3|count|vals.
        self.assertEqual(
            Enc,
            bytes.fromhex('00120001deadbeef0003000000040004000100020003'),
        )
        # The payload (past the 4-byte sub-packet header) round-trips.
        self.assertEqual(ano.parse_ub2_array(Enc[4:]), [4, 1, 2, 3])


class TestServices(unittest.TestCase):
    def test_supervisor_service_bytes(self):
        Expected = bytes.fromhex(
            '0004000300000000'  # service header: type 4, 3 sub-packets, err 0
            '0004000517000000'  # version 0x17000000
            '00080001'
            + ano.SUPERVISOR_CID.hex()  # control id (8 bytes)
            + '00120001deadbeef0003000000040004000100020003'  # service list {4,1,2,3}
        )
        self.assertEqual(ano.supervisor_service(), Expected)

    def test_encryption_service_offers_expected_ids(self):
        Names = [
            'RC4_40',
            'RC4_56',
            'RC4_128',
            'RC4_256',
            'DES56C',
            'AES128',
            'AES192',
            'AES256',
        ]
        Svc = ano.encryption_service(Names)
        # Decode it back and check the offered algorithm-ID bytes.
        (SType, Count, _Err) = struct.unpack_from('>HHI', Svc, 0)
        self.assertEqual((SType, Count), (ano.SERVICE_ENCRYPTION, 3))
        Parsed = ano.decode_ano(ano.encode_ano([Svc]))['services'][0]
        (_t, Version) = Parsed['subpackets'][0]
        (_t, Ids) = Parsed['subpackets'][1]
        (_t, Flag) = Parsed['subpackets'][2]
        self.assertEqual(Version, ano.ANO_VERSION)
        self.assertEqual(list(Ids), [1, 8, 10, 6, 2, 15, 16, 17])
        self.assertEqual(Flag, 1)

    def test_data_integrity_service_offers_expected_ids(self):
        Svc = ano.data_integrity_service(['SHA256', 'SHA512', 'SHA384', 'SHA1', 'MD5'])
        Parsed = ano.decode_ano(ano.encode_ano([Svc]))['services'][0]
        (_t, Ids) = Parsed['subpackets'][1]
        self.assertEqual(list(Ids), [5, 4, 6, 3, 1])


class TestContainer(unittest.TestCase):
    def _client_request(self):
        return ano.encode_ano(
            [
                ano.supervisor_service(),
                ano.encryption_service(['AES256', 'AES192']),
                ano.data_integrity_service(['SHA256']),
            ]
        )

    def test_header_fields_and_length(self):
        Packet = self._client_request()
        (Magic, Length, Version, Count, Err) = struct.unpack_from('>IHIHB', Packet, 0)
        self.assertEqual(Magic, ano.ANO_MAGIC)
        self.assertEqual(Version, ano.ANO_VERSION)
        self.assertEqual(Count, 3)
        self.assertEqual(Err, 0)
        self.assertEqual(Length, len(Packet))  # length counts the whole packet

    def test_roundtrip_decode(self):
        Decoded = ano.decode_ano(self._client_request())
        self.assertEqual(Decoded['version'], ano.ANO_VERSION)
        Types = [S['type'] for S in Decoded['services']]
        self.assertEqual(
            Types,
            [
                ano.SERVICE_SUPERVISOR,
                ano.SERVICE_ENCRYPTION,
                ano.SERVICE_DATA_INTEGRITY,
            ],
        )
        # Supervisor's third sub-packet is the announced service list.
        Sup = Decoded['services'][0]['subpackets']
        self.assertEqual(ano.parse_ub2_array(Sup[2][1]), [4, 1, 2, 3])


class TestDecodeResponse(unittest.TestCase):
    def test_parses_a_synthetic_server_reply(self):
        # A plausible server reply: supervisor echoes version + status 31 + list,
        # encryption picks AES256 (id 17), data-integrity picks SHA256 (id 5).
        Sup = ano.encode_service(
            ano.SERVICE_SUPERVISOR,
            [
                ano.sp_version(),
                ano.sp_status(ano.SUPERVISOR_STATUS_OK),
                ano.sp_ub2_array([4, 1, 2, 3]),
            ],
        )
        Enc = ano.encode_service(
            ano.SERVICE_ENCRYPTION, [ano.sp_version(), ano.sp_ub1(17)]
        )
        Integ = ano.encode_service(
            ano.SERVICE_DATA_INTEGRITY, [ano.sp_version(), ano.sp_ub1(5)]
        )
        Decoded = ano.decode_ano(ano.encode_ano([Sup, Enc, Integ]))
        (_t, Status) = Decoded['services'][0]['subpackets'][1]
        self.assertEqual(Status, ano.SUPERVISOR_STATUS_OK)
        (_t, EncId) = Decoded['services'][1]['subpackets'][1]
        (_t, IntId) = Decoded['services'][2]['subpackets'][1]
        self.assertEqual((EncId, IntId), (17, 5))


class TestErrors(unittest.TestCase):
    def test_bad_magic(self):
        Bad = struct.pack('>IHIHB', 0x12345678, 13, ano.ANO_VERSION, 0, 0)
        with self.assertRaises(ano.AnoError):
            ano.decode_ano(Bad)

    def test_error_flag_raises(self):
        Bad = struct.pack('>IHIHB', ano.ANO_MAGIC, 13, ano.ANO_VERSION, 0, 5)
        with self.assertRaises(ano.AnoError):
            ano.decode_ano(Bad)

    def test_short_packet(self):
        with self.assertRaises(ano.AnoError):
            ano.decode_ano(b'\x00\x01')


if __name__ == '__main__':
    unittest.main()
