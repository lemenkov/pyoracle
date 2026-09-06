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
from seerdb.common.tns_consts import VERSION_11_2_0_2


class TestSubpackets(unittest.TestCase):
    def test_ub1(self):
        # length(1) | type(2) | one byte.
        self.assertEqual(ano.sp_ub1(1), bytes.fromhex('0001000201'))

    def test_ub2(self):
        self.assertEqual(ano.sp_ub2(0x1234), bytes.fromhex('000200031234'))

    def test_ub4(self):
        self.assertEqual(ano.sp_ub4(0xDEADBEEF), bytes.fromhex('00040004deadbeef'))

    def test_version(self):
        self.assertEqual(ano.sp_version(), bytes.fromhex('000400050b200200'))

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
            '000400050b200200'  # version 0x0B200200
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
        self.assertEqual(Version, VERSION_11_2_0_2)
        # The offered list is prefixed with the null algorithm (ID 0).
        self.assertEqual(list(Ids), [0, 1, 8, 10, 6, 2, 15, 16, 17])
        self.assertEqual(Flag, 1)

    def test_data_integrity_service_offers_expected_ids(self):
        Svc = ano.data_integrity_service(['SHA256', 'SHA512', 'SHA384', 'SHA1', 'MD5'])
        Parsed = ano.decode_ano(ano.encode_ano([Svc]))['services'][0]
        (_t, Ids) = Parsed['subpackets'][1]
        # Prefixed with the null algorithm (ID 0).
        self.assertEqual(list(Ids), [0, 5, 4, 6, 3, 1])


class TestGoOraReference(unittest.TestCase):
    # The exact ANO negotiation container a working go-ora client sends to a
    # 26ai server that requires AES/SHA (captured on the wire). Our encoder must
    # reproduce it byte-for-byte — the definitive validation of the request side.
    GOORA_REQUEST = bytes.fromhex(
        'deadbeef00970b2002000004000004000300000000000400050b200200000800'
        '010000101c66ec28ea00120001deadbeef000300000004000400010002000300'
        '01000300000000000400050b20020000020003e0e100020006fcff0002000300'
        '000000000400050b200200000900010001080a06020f10110001000201000300'
        '0200000000000400050b20020000060001000103040506'
    )

    def test_encoder_matches_captured_client(self):
        Ours = ano.encode_ano(
            [
                ano.supervisor_service(),
                ano.auth_service(),
                ano.encryption_service(
                    [
                        'RC4_40',
                        'RC4_56',
                        'RC4_128',
                        'RC4_256',
                        'DES56C',
                        'AES128',
                        'AES192',
                        'AES256',
                    ]
                ),
                ano.data_integrity_service(
                    ['MD5', 'SHA1', 'SHA512', 'SHA256', 'SHA384']
                ),
            ]
        )
        self.assertEqual(Ours, self.GOORA_REQUEST)

    def test_auth_service_markers(self):
        Parsed = ano.decode_ano(ano.encode_ano([ano.auth_service()]))['services'][0]
        self.assertEqual(Parsed['type'], ano.SERVICE_AUTH)
        self.assertEqual(Parsed['subpackets'][1], (ano.SP_UB2, ano.AUTH_MARKER))
        self.assertEqual(Parsed['subpackets'][2], (ano.SP_STATUS, ano.AUTH_STATUS_NONE))


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
        self.assertEqual(Version, VERSION_11_2_0_2)
        self.assertEqual(Count, 3)
        self.assertEqual(Err, 0)
        self.assertEqual(Length, len(Packet))  # length counts the whole packet

    def test_roundtrip_decode(self):
        Decoded = ano.decode_ano(self._client_request())
        self.assertEqual(Decoded['version'], VERSION_11_2_0_2)
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
        Bad = struct.pack('>IHIHB', 0x12345678, 13, VERSION_11_2_0_2, 0, 0)
        with self.assertRaises(ano.AnoError):
            ano.decode_ano(Bad)

    def test_error_flag_raises(self):
        Bad = struct.pack('>IHIHB', ano.ANO_MAGIC, 13, VERSION_11_2_0_2, 0, 5)
        with self.assertRaises(ano.AnoError):
            ano.decode_ano(Bad)

    def test_short_packet(self):
        with self.assertRaises(ano.AnoError):
            ano.decode_ano(b'\x00\x01')


# RFC 2409 Second Oakley Group (1024-bit MODP), generator 2 — a realistic stand-in
# for the DH parameters an Oracle server sends (which vary but are this magnitude).
_MODP_1024 = bytes.fromhex(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381'
    'FFFFFFFFFFFFFFFF'
)
_GEN_2 = b'\x02'


class TestDiffieHellman(unittest.TestCase):
    def test_both_sides_agree_on_the_shared_secret(self):
        P = int.from_bytes(_MODP_1024, 'big')
        ByteLen = len(_MODP_1024)  # 128
        # Server picks a private key and publishes g^a mod p.
        ServerPriv = (2**900 + 7).to_bytes(ByteLen, 'big')
        ServerPublic = pow(2, int.from_bytes(ServerPriv, 'big'), P).to_bytes(
            ByteLen, 'big'
        )
        # Client runs its half against the server's public key.
        ClientPriv = (2**777 + 99).to_bytes(ByteLen, 'big')
        Result = ano.compute_dh(_GEN_2, _MODP_1024, ServerPublic, Private=ClientPriv)
        # The DH invariant: (g^a)^b == (g^b)^a.
        ServerShared = pow(
            int.from_bytes(Result.public_key, 'big'),
            int.from_bytes(ServerPriv, 'big'),
            P,
        ).to_bytes(ByteLen, 'big')
        self.assertEqual(Result.session_key, ServerShared)

    def test_key_lengths_and_iv(self):
        ServerPublic = pow(2, 123456789, int.from_bytes(_MODP_1024, 'big')).to_bytes(
            len(_MODP_1024), 'big'
        )
        Result = ano.compute_dh(
            _GEN_2, _MODP_1024, ServerPublic, Private=(2**500).to_bytes(128, 'big')
        )
        # Keys are left-padded to the prime's byte length; IV is session_key[32:64].
        self.assertEqual(len(Result.public_key), 128)
        self.assertEqual(len(Result.session_key), 128)
        self.assertEqual(len(Result.iv), 32)
        self.assertEqual(Result.iv, Result.session_key[0x20:0x40])

    def test_random_private_key_still_agrees(self):
        # Omitting Private draws a random one; agreement must still hold.
        P = int.from_bytes(_MODP_1024, 'big')
        ServerPriv = 424242
        ServerPublic = pow(2, ServerPriv, P).to_bytes(128, 'big')
        Result = ano.compute_dh(_GEN_2, _MODP_1024, ServerPublic)
        ServerShared = pow(
            int.from_bytes(Result.public_key, 'big'), ServerPriv, P
        ).to_bytes(128, 'big')
        self.assertEqual(Result.session_key, ServerShared)

    def test_extract_dh_params_from_service_reply(self):
        # A data-integrity reply carrying the 8-subpacket DH tail.
        Svc = ano.encode_service(
            ano.SERVICE_DATA_INTEGRITY,
            [
                ano.sp_version(),
                ano.sp_ub1(5),  # chosen integrity algo
                ano.sp_ub2(1024),  # generator bit-length
                ano.sp_ub2(1024),  # prime bit-length
                ano.sp_bytes(_GEN_2),
                ano.sp_bytes(_MODP_1024),
                ano.sp_bytes(b'\xab' * 128),  # server public key
                ano.sp_bytes(b'\x01' * 16),  # old IV
            ],
        )
        Service = ano.decode_ano(ano.encode_ano([Svc]))['services'][0]
        (Gen, Prime, ServerPub, OldIv) = ano.extract_dh_params(Service)
        self.assertEqual(Gen, _GEN_2)
        self.assertEqual(Prime, _MODP_1024)
        self.assertEqual(ServerPub, b'\xab' * 128)
        self.assertEqual(OldIv, b'\x01' * 16)

    def test_extract_requires_full_dh_tail(self):
        Svc = ano.data_integrity_service(['SHA256'])  # only 2 sub-packets
        Service = ano.decode_ano(ano.encode_ano([Svc]))['services'][0]
        with self.assertRaises(ano.AnoError):
            ano.extract_dh_params(Service)


class TestServerSide(unittest.TestCase):
    """The Mirror's server half of the negotiation (#448)."""

    def test_group_is_modp_2048_generator_2(self):
        self.assertEqual(len(ano.DH_PRIME), 256)
        self.assertEqual(ano.DH_GROUP_BITS, 2048)
        self.assertEqual(int.from_bytes(ano.DH_GENERATOR, 'big'), 2)
        self.assertTrue(
            ano.DH_PRIME.hex().upper().startswith('FFFFFFFFFFFFFFFFC90FDAA2')
        )
        self.assertEqual(ano.DH_SERVER_IV, b'foo bar baz bat quux')

    def test_server_and_client_derive_the_same_secret(self):
        # The server advertises its public key; the client computes DH against
        # it; the server derives from the client's public key — both agree.
        server = ano.server_dh_keypair()
        response = ano.encode_ano_response(
            ano.ENCRYPTION_ALGO_IDS['AES256'],
            ano.INTEGRITY_ALGO_IDS['SHA256'],
            server.public_key,
        )
        decoded = ano.decode_ano(response)
        by_type = {s['type']: s for s in decoded['services']}
        self.assertEqual(by_type[ano.SERVICE_ENCRYPTION]['subpackets'][1][1], 17)
        self.assertEqual(by_type[ano.SERVICE_DATA_INTEGRITY]['subpackets'][1][1], 5)
        (Gen, Prime, ServerPub, Iv) = ano.extract_dh_params(
            by_type[ano.SERVICE_DATA_INTEGRITY]
        )
        self.assertEqual(ServerPub, server.public_key)
        self.assertEqual(Iv, ano.DH_SERVER_IV)
        client = ano.compute_dh(Gen, Prime, ServerPub)
        self.assertEqual(server.derive(client.public_key), client.session_key)

    def test_offered_algorithm_ids(self):
        req = ano.decode_ano(
            ano.encode_ano(
                [
                    ano.supervisor_service(),
                    ano.auth_service(),
                    ano.encryption_service(['AES256', 'AES128']),
                    ano.data_integrity_service(['SHA256']),
                ]
            )
        )
        # Null (0) is prefixed to each offered list.
        self.assertEqual(
            ano.offered_algorithm_ids(req, ano.SERVICE_ENCRYPTION), [0, 17, 15]
        )
        self.assertEqual(
            ano.offered_algorithm_ids(req, ano.SERVICE_DATA_INTEGRITY), [0, 5]
        )

    def test_client_public_key_roundtrips(self):
        Key = bytes(range(256))
        parsed = ano.client_public_key(ano.decode_ano(ano.dh_public_key_round(Key)))
        self.assertEqual(parsed, Key)


if __name__ == '__main__':
    unittest.main()
