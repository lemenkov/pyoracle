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
from typing import Sequence, cast

VECTOR_MAGIC = 0xDB

# element_type byte
_VEC_FLOAT32 = 2
_VEC_FLOAT64 = 3
_VEC_INT8 = 4
_VEC_BINARY = 5

_FLAG_NORM = 0x10  # an 8-byte magnitude follows the header
_FLAG_SPARSE = 0x20  # sparse image: count(ub2) + indices(ub4) + values


class VectorError(Exception):
    """Raised on a VECTOR image whose encoding we do not yet decode."""


class SparseVector:
    """A decoded sparse VECTOR (23ai): the total ``num_dimensions``, the
    ``indices`` of the stored (non-zero) elements, and their ``values``.
    Mirrors the column literal form ``[dims, [indices], [values]]``."""

    __slots__ = ('num_dimensions', 'indices', 'values')

    def __init__(self, num_dimensions: int, indices, values):
        self.num_dimensions = num_dimensions
        self.indices = list(indices)
        self.values = list(values)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SparseVector):
            return NotImplemented
        return (
            self.num_dimensions == other.num_dimensions
            and self.indices == other.indices
            and self.values == other.values
        )

    def __repr__(self) -> str:
        return (
            f'SparseVector(num_dimensions={self.num_dimensions}, '
            f'indices={self.indices}, values={self.values})'
        )


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
    u = _unsort_uint(int.from_bytes(chunk, 'big'), bits)
    return struct.unpack('>' + fmt, u.to_bytes(bits // 8, 'big'))[0]


_VEC_ELEMENT_WIDTH = {_VEC_FLOAT32: 4, _VEC_FLOAT64: 8, _VEC_INT8: 1}


def _decode_elements(image: bytes, pos: int, element_type: int, n: int) -> list:
    # Decode `n` consecutive numeric vector elements starting at `pos`.
    width = _VEC_ELEMENT_WIDTH.get(element_type)
    if width is None:
        raise VectorError(
            f'unsupported VECTOR element type {element_type} '
            '(only FLOAT32/FLOAT64/INT8/BINARY reverse-engineered so far)'
        )
    # `n` comes straight from the image's ub4 element count (or ub2 sparse
    # count); reject a count that cannot fit before iterating, so a crafted
    # value (e.g. a ~4-billion ub4) can't spin building a huge list (#165).
    if pos + width * n > len(image):
        raise VectorError('VECTOR element count exceeds image')
    if element_type == _VEC_FLOAT32:
        return [
            _decode_float(image[pos + 4 * i : pos + 4 * i + 4], 'f', 32)
            for i in range(n)
        ]
    if element_type == _VEC_FLOAT64:
        return [
            _decode_float(image[pos + 8 * i : pos + 8 * i + 8], 'd', 64)
            for i in range(n)
        ]
    return [v - 256 if v > 127 else v for v in image[pos : pos + n]]


def decode_vector(image: bytes) -> list | SparseVector:
    """Decode a VECTOR binary image to a list of floats / ints (dense) or a
    SparseVector (sparse, 23ai)."""
    if not image or image[0] != VECTOR_MAGIC:
        raise VectorError(
            f'not a VECTOR image (magic {image[:1].hex() if image else "∅"})'
        )
    flags = (image[2] << 8) | image[3]
    element_type = image[4]
    num_elements = int.from_bytes(image[5:9], 'big')
    pos = 9
    if flags & _FLAG_NORM:
        pos += 8  # skip the cached magnitude
    if flags & _FLAG_SPARSE:
        # `num_elements` is the total dimension count; the body is a ub2 count
        # of stored elements, their ub4 dimension indices, then their values
        # (same per-element encoding as a dense image). Captured on 23ai
        # (docs/PROTOCOL.md §18.2).
        nnz = int.from_bytes(image[pos : pos + 2], 'big')
        pos += 2
        if pos + 4 * nnz > len(image):  # index array must fit (#165)
            raise VectorError('VECTOR sparse index count exceeds image')
        indices = [
            int.from_bytes(image[pos + 4 * i : pos + 4 * i + 4], 'big')
            for i in range(nnz)
        ]
        pos += 4 * nnz
        values = _decode_elements(image, pos, element_type, nnz)
        return SparseVector(num_elements, indices, values)
    if element_type == _VEC_BINARY:
        # `num_elements` is the dimension (bit) count; the payload is the bits
        # packed 8 to a byte. Surface the packed bytes verbatim.
        nbytes = (num_elements + 7) // 8
        if pos + nbytes > len(image):  # packed bit payload must fit (#165)
            raise VectorError('VECTOR bit count exceeds image')
        return list(image[pos : pos + nbytes])
    return _decode_elements(image, pos, element_type, num_elements)


def is_vector_bind(value: object) -> bool:
    """True if `value` is a vector-like sequence we bind as a VECTOR.

    An ``array.array`` (any typecode), a ``SparseVector``, or a non-empty
    list/tuple of real numbers qualifies. Strings, bytes and bool elements are
    left for the other bind paths.
    """
    if isinstance(value, (array.array, SparseVector)):
        return True
    return (
        bool(value)
        and isinstance(value, (list, tuple))
        and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in value)
    )


# Native binary VECTOR bind (#62). Captured from python-oracledb on 23ai
# (docs/PROTOCOL.md §18.1): the bind OAC is type 127 with the cont-flag field
# 0x02000000 and a 1 MiB max length; the value carries a fixed descriptor (the
# same one python-oracledb uses for any LOB-backed inline bind), then the image
# length (ub2), 22 zero bytes, then the image via the normal 12c length framing.
# Both constants are stable across element types and vector sizes.
VECTOR_BIND_OAC = bytes.fromhex('7f010000040010000000040200000000000000040010000000')
VECTOR_BIND_DESCRIPTOR = bytes.fromhex('01282800260004610800000001000000000000')

# Per-element-type (version, flags) for the bind image. FLOAT32/64/INT8 use
# version 0 / flags 0x12; BINARY version 1 / flags 0x10; a sparse image is
# version 2 with the 0x20 flag added.
_BIND_HEADER = {
    _VEC_FLOAT32: (0, 0x0012),
    _VEC_FLOAT64: (0, 0x0012),
    _VEC_INT8: (0, 0x0012),
    _VEC_BINARY: (1, 0x0010),
}
_TYPECODE_ELEMENT = {
    'f': _VEC_FLOAT32,
    'd': _VEC_FLOAT64,
    'b': _VEC_INT8,
    'B': _VEC_BINARY,
}


def _sort_uint(value: int, bits: int) -> int:
    # Inverse of _unsort_uint: positive -> set the top bit; negative -> invert.
    top = 1 << (bits - 1)
    mask = (1 << bits) - 1
    return (~value & mask) if (value & top) else (value | top)


def _encode_float(x: float, fmt: str, bits: int) -> bytes:
    u = int.from_bytes(struct.pack('>' + fmt, x), 'big')
    return _sort_uint(u, bits).to_bytes(bits // 8, 'big')


def _encode_dense_body(values, element_type: int) -> bytes:
    if element_type == _VEC_FLOAT32:
        return b''.join(_encode_float(v, 'f', 32) for v in values)
    if element_type == _VEC_FLOAT64:
        return b''.join(_encode_float(v, 'd', 64) for v in values)
    return bytes(int(v) & 0xFF for v in values)  # INT8 / packed bytes


def encode_vector(value: object) -> bytes:
    """Encode a vector bind value to its VECTOR binary image (the inverse of
    decode_vector). Dense list/tuple -> FLOAT32; an array.array maps by typecode
    (f/d/b/B); a SparseVector -> a sparse FLOAT32 image. The 8-byte norm is sent
    as zeros (the server recomputes it)."""
    if isinstance(value, SparseVector):
        element_type = _VEC_FLOAT32
        flags = _BIND_HEADER[element_type][1] | _FLAG_SPARSE
        header = (
            bytes([VECTOR_MAGIC, 2])
            + flags.to_bytes(2, 'big')
            + bytes([element_type])
            + value.num_dimensions.to_bytes(4, 'big')
            + b'\x00' * 8
        )
        indices = b''.join(int(i).to_bytes(4, 'big') for i in value.indices)
        return (
            header
            + len(value.indices).to_bytes(2, 'big')
            + indices
            + _encode_dense_body(value.values, element_type)
        )
    if isinstance(value, array.array):
        element_type = _TYPECODE_ELEMENT.get(value.typecode, _VEC_FLOAT32)
    else:
        element_type = _VEC_FLOAT32
    version, flags = _BIND_HEADER[element_type]
    # Past the SparseVector branch, value is a dense sized sequence (list/tuple/
    # array.array) — is_vector_bind gated it upstream.
    seq = cast(Sequence, value)
    if element_type == _VEC_BINARY:
        body = bytes(int(v) & 0xFF for v in seq)
        count = len(body) * 8
    else:
        body = _encode_dense_body(seq, element_type)
        count = len(seq)
    return (
        bytes([VECTOR_MAGIC, version])
        + flags.to_bytes(2, 'big')
        + bytes([element_type])
        + count.to_bytes(4, 'big')
        + b'\x00' * 8
        + body
    )
