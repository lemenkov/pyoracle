# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the VECTOR (native vector) decoder.

Each fixture is a real VECTOR image captured from a live Oracle 23ai server for
a known vector (see docs/PROTOCOL.md §18). No server is needed to run these.
"""

import array
import unittest

from seerdb.common.vector import (
    SparseVector,
    VectorError,
    decode_vector,
    encode_vector,
    is_vector_bind,
)

# (label, expected values, captured VECTOR image as hex)
FIXTURES = [
    (
        'f32_simple',
        [1.5, 2.5, 3.5],
        'db0000120200000003c012388ac0059c28bfc00000c0200000c0600000',
    ),
    (
        'f32_neg',
        [-1.0, 0.0, 100.0],
        'db0000120200000003c0590051eafee8b3407fffff80000000c2c80000',
    ),
    (
        'f32_four',
        [0.5, -0.5, 2.0, -2.0],
        'db0000120200000004c00752e50db3a3a2bf00000040ffffffc00000003fffffff',
    ),
    (
        'f64_simple',
        [1.5, 2.5, 3.5],
        'db0000120300000003c012388ac0059c28bff8000000000000c004000000000000'
        'c00c000000000000',
    ),
    ('int8_simple', [1, -2, 3, -4], 'db0000120400000004c015e8add236a58f01fe03fc'),
    # BINARY (bit) vectors (#60): element_type 5, count = dimension/bit count,
    # payload = bits packed 8/byte (ceil(count/8) bytes), surfaced verbatim.
    ('bin8_aa', [0xAA], 'db01001005000000088000000000000000aa'),
    ('bin8_one', [0x01], 'db0100100500000008800000000000000001'),
    ('bin16_aa01', [0xAA, 0x01], 'db01001005000000108000000000000000aa01'),
    ('bin24_010203', [0x01, 0x02, 0x03], 'db01001005000000188000000000000000010203'),
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
        got = decode_vector(bytes.fromhex('db0000120400000004c015e8add236a58f01fe03fc'))
        self.assertEqual(got, [1, -2, 3, -4])
        self.assertTrue(all(isinstance(v, int) for v in got))

    def test_float32_returns_floats(self):
        got = decode_vector(
            bytes.fromhex('db0000120200000003c012388ac0059c28bfc00000c0200000c0600000')
        )
        self.assertTrue(all(isinstance(v, float) for v in got))

    def test_binary_returns_packed_bytes(self):
        # VECTOR(16, BINARY) '[170, 1]' -> two packed bytes, ints, verbatim.
        got = decode_vector(bytes.fromhex('db01001005000000108000000000000000aa01'))
        self.assertEqual(got, [0xAA, 0x01])
        self.assertTrue(all(isinstance(v, int) for v in got))

    def test_bad_magic_raises(self):
        with self.assertRaises(VectorError):
            decode_vector(b'\x00\x01\x02\x03')

    def test_unsupported_element_type_raises(self):
        # element_type 9 is not one we decode; must raise, not corrupt.
        with self.assertRaises(VectorError):
            decode_vector(bytes.fromhex('db00001209000000010000000000000000'))


class TestVectorBoundedDecode(unittest.TestCase):
    # A malformed VECTOR image must never hang the client (#165): a count field
    # (dense ub4 element count, packed-bit count, or sparse index count) that
    # cannot fit in the image must raise VectorError promptly, never spin
    # building a multi-billion-entry list.

    def test_oversized_element_count_raises(self):
        # Dense FLOAT64 images with a huge ub4 num_elements, from SeerODBC's
        # fuzz corpus -- these spun decode_vector for seconds before the bound.
        for hx in (
            'db0100100302f64f4fffffffffffffffffffffffffffffffffffffff69ff',
            'db01ff040302f601005d0000004f4f01007bd20400000000010000680000',
        ):
            with self.subTest(hx=hx[:16]):
                with self.assertRaises(VectorError):
                    decode_vector(bytes.fromhex(hx))

    def test_oversized_binary_count_raises(self):
        # BINARY image claiming 0xffffffff bits with no payload.
        with self.assertRaises(VectorError):
            decode_vector(bytes.fromhex('db00000005ffffffff'))

    def test_oversized_sparse_index_count_raises(self):
        # Sparse image (flag 0x20) claiming 0xffff stored indices with none.
        with self.assertRaises(VectorError):
            decode_vector(bytes.fromhex('db0000200200000010ffff'))


class TestVectorBind(unittest.TestCase):
    # Bind side (#62): a vector-like value encodes to its native binary image
    # (encode_vector), the inverse of decode_vector.

    def test_detects_sequences(self):
        self.assertTrue(is_vector_bind([1.0, 2.0]))
        self.assertTrue(is_vector_bind((1, 2, 3)))
        self.assertTrue(is_vector_bind(array.array('f', [1.0])))
        self.assertTrue(is_vector_bind(array.array('B', [1, 2])))

    def test_ignores_non_vectors(self):
        for v in ('[1,2]', b'\x01\x02', [], [True, False], ['a'], 42, None):
            self.assertFalse(is_vector_bind(v), v)

    def test_encode_matches_read_image(self):
        # The bind image equals the read image except its norm is zeroed, so
        # decode(encode(x)) == x for every element type.
        self.assertEqual(
            encode_vector(array.array('f', [1.5, 2.5, 3.5])).hex(),
            'db00001202000000030000000000000000bfc00000c0200000c0600000',
        )
        self.assertEqual(
            decode_vector(encode_vector(array.array('d', [1.5, -2.5]))), [1.5, -2.5]
        )
        self.assertEqual(
            decode_vector(encode_vector(array.array('b', [1, -2, 3]))), [1, -2, 3]
        )
        self.assertEqual(
            decode_vector(encode_vector(array.array('B', [170, 1]))), [170, 1]
        )
        self.assertEqual(
            decode_vector(encode_vector([1.5, 2.5, 3.5])), [1.5, 2.5, 3.5]
        )  # plain list -> FLOAT32

    def test_encode_sparse_roundtrips(self):
        sv = SparseVector(8, [2, 5], [1.5, 2.5])
        self.assertEqual(decode_vector(encode_vector(sv)), sv)


class TestSparseVector(unittest.TestCase):
    # SPARSE vectors (#68), captured from VECTOR(n, T, SPARSE) columns on 23ai:
    # version 2, flag 0x20, then count(ub2) + indices(ub4) + values.
    def test_decode_float32(self):
        self.assertEqual(
            decode_vector(
                bytes.fromhex(
                    'db0200320200000008c00752e50db3a3a2000200000002000000'
                    '05bfc00000c0200000'
                )
            ),
            SparseVector(8, [2, 5], [1.5, 2.5]),
        )

    def test_decode_float32_index0_and_negative(self):
        self.assertEqual(
            decode_vector(
                bytes.fromhex(
                    'db0200320200000008bff6a09e667f3bcd00020000000000000007'
                    'bf800000407fffff'
                )
            ),
            SparseVector(8, [0, 7], [1.0, -1.0]),
        )

    def test_decode_int8(self):
        self.assertEqual(
            decode_vector(
                bytes.fromhex(
                    'db0200320400000008c0140000000000000002000000020000000503fc'
                )
            ),
            SparseVector(8, [2, 5], [3, -4]),
        )

    def test_decode_wide_index_ub4(self):
        self.assertEqual(
            decode_vector(
                bytes.fromhex(
                    'db020032020000012cc00752e50db3a3a20002000000010000012b'
                    'bfc00000c0200000'
                )
            ),
            SparseVector(300, [1, 299], [1.5, 2.5]),
        )

    def test_is_vector_bind_and_encode(self):
        sv = SparseVector(8, [2, 5], [1.5, 2.5])
        self.assertTrue(is_vector_bind(sv))
        # encodes to a version-2 / flag-0x20 sparse image that round-trips.
        img = encode_vector(sv)
        self.assertEqual(img[1], 2)  # version 2
        self.assertTrue(((img[2] << 8) | img[3]) & 0x20)  # sparse flag
        self.assertEqual(decode_vector(img), sv)


if __name__ == '__main__':
    unittest.main()
