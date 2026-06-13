# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Decoder for Oracle's VECTOR binary image (the on-the-wire form of a native
``VECTOR`` column, 23ai+).

Reverse-engineered from images captured off a live 23ai server (see
docs/PROTOCOL.md §18); every encoding below is backed by a captured sample with
known content. The image is:

    magic 0xDB | version (1) | flags (ub2) | element_type (1) | num_elements (ub4)
    [ norm (8 bytes, when flags & 0x10) ]
    elements...

`element_type`: 2 = FLOAT32, 3 = FLOAT64, 4 = INT8, 5 = BINARY. FLOAT32 /
FLOAT64 elements are stored in Oracle's order-preserving ("sortable") float
encoding — the sign bit is flipped for a positive value and all bits are
inverted for a negative one — so a byte-wise compare orders them numerically.
INT8 elements are plain two's-complement bytes. For BINARY (bit) vectors
`num_elements` is the number of dimensions (bits), packed 8 to a byte, so the
payload is ``ceil(num_elements / 8)`` bytes stored verbatim; we surface those
packed bytes unchanged (matching the form a ``VECTOR(n, BINARY)`` literal takes,
e.g. ``[170]`` ⇒ byte ``0xAA``). The 8-byte norm is a cached magnitude (also
sortable-encoded) that we skip; it is not part of the value.

Returns a list of Python floats (FLOAT32/64) or ints (INT8 values, or BINARY
packed bytes).
"""

import struct

VECTOR_MAGIC = 0xDB

# element_type byte
_VEC_FLOAT32 = 2
_VEC_FLOAT64 = 3
_VEC_INT8 = 4
_VEC_BINARY = 5

_FLAG_NORM = 0x10        # an 8-byte magnitude follows the header


class VectorError(Exception):
    """Raised on a VECTOR image whose encoding we do not yet decode."""


def _unsort_uint(value: int, bits: int) -> int:
    # Reverse Oracle's order-preserving float transform: a set top bit means
    # the original was positive (clear it); a clear top bit means the original
    # was negative (invert every bit).
    top = 1 << (bits - 1)
    mask = (1 << bits) - 1
    if value & top:
        return value & (top - 1)
    return ~value & mask


def _decode_float(chunk: bytes, fmt: str, bits: int) -> float:
    u = _unsort_uint(int.from_bytes(chunk, "big"), bits)
    return struct.unpack(">" + fmt, u.to_bytes(bits // 8, "big"))[0]


def decode_vector(image: bytes) -> list:
    """Decode a VECTOR binary image to a list of floats / ints."""
    if not image or image[0] != VECTOR_MAGIC:
        raise VectorError(
            f"not a VECTOR image (magic {image[:1].hex() if image else '∅'})")
    flags = (image[2] << 8) | image[3]
    element_type = image[4]
    count = int.from_bytes(image[5:9], "big")
    pos = 9
    if flags & _FLAG_NORM:
        pos += 8                                     # skip the cached magnitude
    if element_type == _VEC_FLOAT32:
        return [_decode_float(image[pos + 4 * i:pos + 4 * i + 4], "f", 32)
                for i in range(count)]
    if element_type == _VEC_FLOAT64:
        return [_decode_float(image[pos + 8 * i:pos + 8 * i + 8], "d", 64)
                for i in range(count)]
    if element_type == _VEC_INT8:
        return [v - 256 if v > 127 else v
                for v in image[pos:pos + count]]
    if element_type == _VEC_BINARY:
        # `count` is the dimension (bit) count; the payload is the bits packed
        # 8 to a byte. Surface the packed bytes verbatim.
        nbytes = (count + 7) // 8
        return list(image[pos:pos + nbytes])
    raise VectorError(
        f"unsupported VECTOR element type {element_type} "
        "(only FLOAT32/FLOAT64/INT8/BINARY reverse-engineered so far)")
