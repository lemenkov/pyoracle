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

import array
import struct

VECTOR_MAGIC = 0xDB

# element_type byte
_VEC_FLOAT32 = 2
_VEC_FLOAT64 = 3
_VEC_INT8 = 4
_VEC_BINARY = 5

_FLAG_NORM = 0x10        # an 8-byte magnitude follows the header
_FLAG_SPARSE = 0x20      # sparse image: count(ub2) + indices(ub4) + values


class VectorError(Exception):
    """Raised on a VECTOR image whose encoding we do not yet decode."""


class SparseVector:
    """A decoded sparse VECTOR (23ai): the total ``num_dimensions``, the
    ``indices`` of the stored (non-zero) elements, and their ``values``.
    Mirrors the column literal form ``[dims, [indices], [values]]``."""

    __slots__ = ("num_dimensions", "indices", "values")

    def __init__(self, num_dimensions: int, indices, values):
        self.num_dimensions = num_dimensions
        self.indices = list(indices)
        self.values = list(values)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SparseVector):
            return NotImplemented
        return (self.num_dimensions == other.num_dimensions
                and self.indices == other.indices
                and self.values == other.values)

    def __repr__(self) -> str:
        return (f"SparseVector(num_dimensions={self.num_dimensions}, "
                f"indices={self.indices}, values={self.values})")


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


def _decode_elements(image: bytes, pos: int, element_type: int, n: int) -> list:
    # Decode `n` consecutive numeric vector elements starting at `pos`.
    if element_type == _VEC_FLOAT32:
        return [_decode_float(image[pos + 4 * i:pos + 4 * i + 4], "f", 32)
                for i in range(n)]
    if element_type == _VEC_FLOAT64:
        return [_decode_float(image[pos + 8 * i:pos + 8 * i + 8], "d", 64)
                for i in range(n)]
    if element_type == _VEC_INT8:
        return [v - 256 if v > 127 else v for v in image[pos:pos + n]]
    raise VectorError(
        f"unsupported VECTOR element type {element_type} "
        "(only FLOAT32/FLOAT64/INT8/BINARY reverse-engineered so far)")


def decode_vector(image: bytes) -> list:
    """Decode a VECTOR binary image to a list of floats / ints (dense) or a
    SparseVector (sparse, 23ai)."""
    if not image or image[0] != VECTOR_MAGIC:
        raise VectorError(
            f"not a VECTOR image (magic {image[:1].hex() if image else '∅'})")
    flags = (image[2] << 8) | image[3]
    element_type = image[4]
    num_elements = int.from_bytes(image[5:9], "big")
    pos = 9
    if flags & _FLAG_NORM:
        pos += 8                                     # skip the cached magnitude
    if flags & _FLAG_SPARSE:
        # `num_elements` is the total dimension count; the body is a ub2 count
        # of stored elements, their ub4 dimension indices, then their values
        # (same per-element encoding as a dense image). Captured on 23ai
        # (docs/PROTOCOL.md §18.2).
        nnz = int.from_bytes(image[pos:pos + 2], "big")
        pos += 2
        indices = [int.from_bytes(image[pos + 4 * i:pos + 4 * i + 4], "big")
                   for i in range(nnz)]
        pos += 4 * nnz
        values = _decode_elements(image, pos, element_type, nnz)
        return SparseVector(num_elements, indices, values)
    if element_type == _VEC_BINARY:
        # `num_elements` is the dimension (bit) count; the payload is the bits
        # packed 8 to a byte. Surface the packed bytes verbatim.
        nbytes = (num_elements + 7) // 8
        return list(image[pos:pos + nbytes])
    return _decode_elements(image, pos, element_type, num_elements)


def is_vector_bind(value: object) -> bool:
    """True if `value` is a vector-like sequence we bind as a VECTOR.

    An ``array.array`` (any typecode), a ``SparseVector``, or a non-empty
    list/tuple of real numbers qualifies. Strings, bytes and bool elements are
    left for the other bind paths.
    """
    if isinstance(value, (array.array, SparseVector)):
        return True
    return bool(value) and isinstance(value, (list, tuple)) and all(
        isinstance(x, (int, float)) and not isinstance(x, bool)
        for x in value)


def vector_to_literal(value: object) -> str:
    """Render a vector-like sequence as Oracle's ``VECTOR`` text literal, e.g.
    ``[1.5, 2.5, 3.5]``. pyoracle binds this as a string and the server casts
    VARCHAR -> VECTOR; the result is precision-identical to a native binary
    bind (an inline binary VECTOR image is the future native path, see #62 /
    docs/PROTOCOL.md §18.1). Integer-valued elements render as ints (needed for
    INT8 / BINARY columns); other values keep full float precision via repr.
    A ``SparseVector`` renders as ``[dims, [indices], [values]]``.
    """
    def fmt(x):
        if isinstance(x, int) or (isinstance(x, float) and x.is_integer()):
            return str(int(x))
        return repr(float(x))
    if isinstance(value, SparseVector):
        idx = ", ".join(str(int(i)) for i in value.indices)
        vals = ", ".join(fmt(v) for v in value.values)
        return f"[{value.num_dimensions}, [{idx}], [{vals}]]"
    return "[" + ", ".join(fmt(x) for x in value) + "]"
