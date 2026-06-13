# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the VECTOR (native vector) decoder.

Each fixture is a real VECTOR image captured from a live Oracle 23ai server for
a known vector (see docs/PROTOCOL.md §18). No server is needed to run these.
"""

import unittest

from oracle.vector import decode_vector, VectorError


# (label, expected values, captured VECTOR image as hex)
FIXTURES = [
    ("f32_simple", [1.5, 2.5, 3.5],
     "db0000120200000003c012388ac0059c28bfc00000c0200000c0600000"),
    ("f32_neg", [-1.0, 0.0, 100.0],
     "db0000120200000003c0590051eafee8b3407fffff80000000c2c80000"),
    ("f32_four", [0.5, -0.5, 2.0, -2.0],
     "db0000120200000004c00752e50db3a3a2bf00000040ffffffc00000003fffffff"),
    ("f64_simple", [1.5, 2.5, 3.5],
     "db0000120300000003c012388ac0059c28bff8000000000000c004000000000000"
     "c00c000000000000"),
    ("int8_simple", [1, -2, 3, -4],
     "db0000120400000004c015e8add236a58f01fe03fc"),
    # BINARY (bit) vectors (#60): element_type 5, count = dimension/bit count,
    # payload = bits packed 8/byte (ceil(count/8) bytes), surfaced verbatim.
    ("bin8_aa", [0xAA],
     "db01001005000000088000000000000000aa"),
    ("bin8_one", [0x01],
     "db0100100500000008800000000000000001"),
    ("bin16_aa01", [0xAA, 0x01],
     "db01001005000000108000000000000000aa01"),
    ("bin24_010203", [0x01, 0x02, 0x03],
     "db01001005000000188000000000000000010203"),
]


class TestVectorDecode(unittest.TestCase):

    def test_fixtures(self):
        for label, expect, hexstr in FIXTURES:
            with self.subTest(label=label):
                got = decode_vector(bytes.fromhex(hexstr))
                self.assertEqual(len(got), len(expect))
                for a, b in zip(got, expect):
                    self.assertAlmostEqual(a, b, places=4)

    def test_int8_returns_ints(self):
        got = decode_vector(bytes.fromhex(
            "db0000120400000004c015e8add236a58f01fe03fc"))
        self.assertEqual(got, [1, -2, 3, -4])
        self.assertTrue(all(isinstance(v, int) for v in got))

    def test_float32_returns_floats(self):
        got = decode_vector(bytes.fromhex(
            "db0000120200000003c012388ac0059c28bfc00000c0200000c0600000"))
        self.assertTrue(all(isinstance(v, float) for v in got))

    def test_binary_returns_packed_bytes(self):
        # VECTOR(16, BINARY) '[170, 1]' -> two packed bytes, ints, verbatim.
        got = decode_vector(bytes.fromhex(
            "db01001005000000108000000000000000aa01"))
        self.assertEqual(got, [0xAA, 0x01])
        self.assertTrue(all(isinstance(v, int) for v in got))

    def test_bad_magic_raises(self):
        with self.assertRaises(VectorError):
            decode_vector(b"\x00\x01\x02\x03")

    def test_unsupported_element_type_raises(self):
        # element_type 9 is not one we decode; must raise, not corrupt.
        with self.assertRaises(VectorError):
            decode_vector(bytes.fromhex("db00001209000000010000000000000000"))


if __name__ == "__main__":
    unittest.main()
