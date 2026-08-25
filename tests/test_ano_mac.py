# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Tests for the ANO AES-keystream data-integrity MAC (#437, phase 4).

Offline: a client and a server instance (with swapped send/receive keystreams)
exercise the real MAC round-trip in both directions, plus tamper detection and
the stateful keystream. The construction is re-expressed from go-ora (MIT),
which ships no crypto tests, so validation is by self-consistent round-trip.
"""

import unittest

from seerdb.common.ano_mac import AnoMac, AnoMacError

KEY = bytes(range(32))  # a stand-in DH session key
IV = bytes(range(64, 80))  # 16-byte IV


class TestAnoMac(unittest.TestCase):
    def _pair(self, algo='SHA256'):
        Client = AnoMac(KEY, IV, algo, ClientSide=True)
        Server = AnoMac(KEY, IV, algo, ClientSide=False)
        return (Client, Server)

    def test_client_to_server_roundtrip(self):
        (Client, Server) = self._pair()
        for Msg in (b'x', b'select 1 from dual', bytes(range(200))):
            with self.subTest(msg=Msg[:8]):
                self.assertEqual(Server.validate(Client.sign(Msg)), Msg)

    def test_server_to_client_roundtrip(self):
        (Client, Server) = self._pair()
        # The other direction uses the mirror keystream.
        self.assertEqual(
            Client.validate(Server.sign(b'reply payload')), b'reply payload'
        )

    def test_all_sha2_sizes(self):
        for Algo in ('SHA256', 'SHA384', 'SHA512'):
            with self.subTest(algo=Algo):
                (Client, Server) = self._pair(Algo)
                self.assertEqual(Server.validate(Client.sign(b'payload')), b'payload')

    def test_keystream_is_stateful(self):
        # Identical payloads produce different MACs (the keystream advances),
        # and a matched receiver still validates both in order.
        (Client, Server) = self._pair()
        Mac1 = Client.compute(b'same')
        Mac2 = Client.compute(b'same')
        self.assertNotEqual(Mac1, Mac2)
        self.assertEqual(Server.validate(b'same' + Mac1), b'same')
        self.assertEqual(Server.validate(b'same' + Mac2), b'same')

    def test_tamper_is_rejected(self):
        (Client, Server) = self._pair()
        Tagged = bytearray(Client.sign(b'important'))
        Tagged[0] ^= 0x01  # flip a payload bit
        with self.assertRaises(AnoMacError):
            Server.validate(bytes(Tagged))

    def test_wrong_mac_rejected(self):
        (Client, Server) = self._pair()
        with self.assertRaises(AnoMacError):
            Server.validate(b'payload' + b'\x00' * 32)

    def test_short_input_rejected(self):
        (_Client, Server) = self._pair()
        with self.assertRaises(AnoMacError):
            Server.validate(b'short')

    def test_unsupported_algorithm(self):
        with self.assertRaises(AnoMacError):
            AnoMac(KEY, IV, 'MD5')  # RC4-keystream path is deferred


if __name__ == '__main__':
    unittest.main()
