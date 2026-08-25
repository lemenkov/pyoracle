# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""ANO negotiation-to-crypto bridge, validated against a real server (#437).

`tests/fixtures/ano_server_response.bin` is the actual ANO negotiation response
a 26ai server (requiring AES256 + SHA256) sent on the wire — captured from a
working go-ora client through a logging proxy. These tests decode it, run the
DH, and build the session cipher + MAC from it, exercising the whole response
side against genuine server bytes.
"""

import os
import unittest

from seerdb.common import ano
from seerdb.common.ano_cipher import AnoAESCipher
from seerdb.common.ano_mac import AnoMac
from seerdb.common.ano_session import AnoChannel, make_cipher, make_mac

# The constant DH IV a real server supplies for the MAC (negotiation's 8th
# data-integrity sub-packet), used to key the data-integrity MAC.
_SERVER_IV = b'foo bar baz bat quux'

_RESPONSE = open(
    os.path.join(os.path.dirname(__file__), 'fixtures', 'ano_server_response.bin'), 'rb'
).read()


class TestRealServerResponse(unittest.TestCase):
    def setUp(self):
        self.decoded = ano.decode_ano(_RESPONSE)
        self.by_type = {s['type']: s for s in self.decoded['services']}

    def test_server_selected_aes256_and_sha256(self):
        Enc = self.by_type[ano.SERVICE_ENCRYPTION]['subpackets'][1][1]
        Integ = self.by_type[ano.SERVICE_DATA_INTEGRITY]['subpackets'][1][1]
        self.assertEqual(Enc, ano.ENCRYPTION_ALGO_IDS['AES256'])  # 17
        self.assertEqual(Integ, ano.INTEGRITY_ALGO_IDS['SHA256'])  # 5

    def test_supervisor_status_ok(self):
        Sup = self.by_type[ano.SERVICE_SUPERVISOR]['subpackets']
        self.assertEqual(Sup[1], (ano.SP_STATUS, ano.SUPERVISOR_STATUS_OK))

    def test_dh_params_extract_and_compute(self):
        (Gen, Prime, ServerPub, OldIv) = ano.extract_dh_params(
            self.by_type[ano.SERVICE_DATA_INTEGRITY]
        )
        self.assertEqual(len(Prime), 256)  # 2048-bit DH group
        self.assertEqual(len(ServerPub), 256)
        Result = ano.compute_dh(
            Gen, Prime, ServerPub, Private=(2**2000).to_bytes(256, 'big')
        )
        self.assertEqual(len(Result.session_key), 256)
        self.assertEqual(len(Result.public_key), 256)
        self.assertEqual(Result.iv, Result.session_key[0x20:0x40])
        # The second-round packet carries exactly that public key.
        Round2 = ano.dh_public_key_round(Result.public_key)
        Svc = ano.decode_ano(Round2)['services'][0]
        self.assertEqual(Svc['type'], ano.SERVICE_DATA_INTEGRITY)
        self.assertEqual(Svc['subpackets'][0][1], Result.public_key)


class TestSessionBridge(unittest.TestCase):
    def _session_key(self):
        Integ = {s['type']: s for s in ano.decode_ano(_RESPONSE)['services']}
        (Gen, Prime, ServerPub, _iv) = ano.extract_dh_params(
            Integ[ano.SERVICE_DATA_INTEGRITY]
        )
        return ano.compute_dh(
            Gen, Prime, ServerPub, Private=(2**2000).to_bytes(256, 'big')
        ).session_key

    def test_make_cipher_aes256(self):
        Cipher = make_cipher(ano.ENCRYPTION_ALGO_IDS['AES256'], self._session_key())
        self.assertIsInstance(Cipher, AnoAESCipher)
        self.assertEqual(Cipher.decrypt(Cipher.encrypt(b'payload')), b'payload')

    def test_make_mac_sha256_roundtrip(self):
        Key = self._session_key()
        Client = make_mac(
            ano.INTEGRITY_ALGO_IDS['SHA256'], Key, _SERVER_IV, ClientSide=True
        )
        Server = make_mac(
            ano.INTEGRITY_ALGO_IDS['SHA256'], Key, _SERVER_IV, ClientSide=False
        )
        self.assertIsInstance(Client, AnoMac)
        self.assertEqual(Server.validate(Client.sign(b'select 1')), b'select 1')

    def test_null_algorithm_yields_no_cipher_or_mac(self):
        self.assertIsNone(make_cipher(0, self._session_key()))
        self.assertIsNone(make_mac(0, self._session_key(), _SERVER_IV))

    def test_cipher_uses_zero_iv(self):
        # The AES-CBC cipher runs with an all-zero IV (go-ora's nil IV), so it
        # matches a fresh AnoAESCipher built with 16 zero bytes.
        Key = self._session_key()
        Ours = make_cipher(ano.ENCRYPTION_ALGO_IDS['AES256'], Key)
        Ref = AnoAESCipher(Key[:32], bytes(16))
        self.assertEqual(Ours.encrypt(b'x' * 20), Ref.encrypt(b'x' * 20))

    def test_client_and_server_channels_interoperate(self):
        # A server channel (ClientSide=False) and a client channel decrypt each
        # other's packets — the crux of the Mirror's server-side ANO (#448). The
        # MAC keystreams are stateful, so each pair must advance in lock-step.
        Key = self._session_key()
        Client = AnoChannel(17, 5, Key, _SERVER_IV, ClientSide=True)
        Server = AnoChannel(17, 5, Key, _SERVER_IV, ClientSide=False)
        for i in range(3):
            c2s = f'client says {i}'.encode()
            self.assertEqual(Server.unwrap(Client.wrap(c2s)), c2s)
            s2c = f'server says {i}'.encode()
            self.assertEqual(Client.unwrap(Server.wrap(s2c)), s2c)


if __name__ == '__main__':
    unittest.main()
