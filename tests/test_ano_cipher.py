# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Tests for the ANO AES-CBC network cipher (#437, phase 3).

Offline: a NIST AES-128-CBC known-answer vector pins the primitive, and
round-trips exercise Oracle's zero-pad + trailing-marker framing. The wire
layout is re-expressed from go-ora (MIT); go-ora ships no crypto tests.
"""

import unittest

from seerdb.common.ano_cipher import BLOCK_SIZE, AnoAESCipher, AnoCipherError

# NIST SP 800-38A F.2.1, AES-128-CBC, first block.
NIST_KEY = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
NIST_IV = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
NIST_PT = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
NIST_CT = bytes.fromhex('7649abac8119b246cee98e9b12e9197d')


class TestAnoAESCipher(unittest.TestCase):
    def _cipher(self, key=NIST_KEY):
        return AnoAESCipher(key, NIST_IV)

    def test_nist_vector_aligned_block(self):
        # An exactly-aligned block gets padding 0 -> trailing marker 1, and the
        # ciphertext is the plain AES-CBC of the input (independent KAT).
        Out = self._cipher().encrypt(NIST_PT)
        self.assertEqual(Out, NIST_CT + b'\x01')
        self.assertEqual(self._cipher().decrypt(Out), NIST_PT)

    def test_roundtrip_various_lengths(self):
        Cipher = self._cipher()
        for Length in (0, 1, 5, 15, 16, 17, 31, 32, 100):
            with self.subTest(length=Length):
                Data = bytes(range(256))[:Length]
                self.assertEqual(Cipher.decrypt(Cipher.encrypt(Data)), Data)

    def test_padding_marker_values(self):
        # 16-aligned -> marker 1 (no padding); 15 bytes -> marker 2 (1 pad byte).
        self.assertEqual(self._cipher().encrypt(b'\x00' * 16)[-1], 1)
        self.assertEqual(self._cipher().encrypt(b'\x00' * 15)[-1], 2)
        self.assertEqual(self._cipher().encrypt(b'')[-1], 1)

    def test_fixed_iv_not_chained(self):
        # AES does not chain the IV across packets: same input -> same output.
        Cipher = self._cipher()
        self.assertEqual(Cipher.encrypt(b'hello'), Cipher.encrypt(b'hello'))

    def test_aes_256_key(self):
        Cipher = AnoAESCipher(bytes(range(32)), NIST_IV)
        self.assertEqual(
            Cipher.decrypt(Cipher.encrypt(b'secret payload')), b'secret payload'
        )

    def test_rejects_bad_key_and_iv(self):
        with self.assertRaises(AnoCipherError):
            AnoAESCipher(b'shortkey', NIST_IV)
        with self.assertRaises(AnoCipherError):
            AnoAESCipher(NIST_KEY, b'shortiv')

    def test_rejects_bad_ciphertext(self):
        Cipher = self._cipher()
        with self.assertRaises(AnoCipherError):
            Cipher.decrypt(b'')  # empty
        with self.assertRaises(AnoCipherError):
            Cipher.decrypt(NIST_CT + b'\x99')  # marker out of range
        with self.assertRaises(AnoCipherError):
            Cipher.decrypt(b'\x00' * 10 + b'\x01')  # not a whole block count

    def test_block_size_constant(self):
        self.assertEqual(BLOCK_SIZE, 16)


if __name__ == '__main__':
    unittest.main()
