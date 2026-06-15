# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Decoder for Oracle's OSON binary JSON image (the on-the-wire form of a
native ``JSON`` column, 21c+).

The format was reverse-engineered from images captured off a live 21c server
(see docs/PROTOCOL.md §17); every encoding below is backed by a captured sample
with known content. An OSON image is:

    magic "FF 4A 5A" | version(1) | flags(ub2) | body

``flags & 0x2000`` marks a *tree* (container) image; otherwise the body is a
single bare scalar. A tree body is::

    num_fnames(ub1) | fnames_seg_size(ub2) | tree_seg_size(ub2) | reserved(ub2)
    hash_array(num_fnames * 1)        # one hash byte per field name (unused here)
    offset_array(num_fnames * ub2)    # field-id -> offset into fnames_seg
    fnames_seg                        # the field names, each <len><utf8>
    tree_seg                          # the node tree, root at offset 0

Nodes (within tree_seg, or the lone scalar of a non-tree image):

    0x00..0x1F  short string, length = tag, then that many UTF-8 bytes
    0x20..0x2F  number, Oracle NUMBER of (tag - 0x1F) bytes
    0x30        null      0x31  true      0x32  false
    0x33        string, ub1 length prefix, then UTF-8 bytes
    0x34        number, ub1 length prefix, then Oracle NUMBER bytes
    (tag & 0xC0) == 0x80   object: count(ub1), field_id(ub1)*count,
                           value_offset(ub2)*count   (offsets rel. to tree_seg)
    (tag & 0xC0) == 0xC0   array:  count(ub1), value_offset(ub2)*count

A field id is 1-based; ``offset_array[id-1]`` locates its name in fnames_seg.

Extended scalar nodes (binary double/float, date, timestamp, interval) are
decoded too (see ``_EXT_SCALAR``). Not yet covered (raise ``OsonError`` rather
than decode wrong): images whose flags select ub4 segment sizes / ub4 node
offsets (oracledb-produced and large documents) and ub2 field-ids (>255 distinct
keys) — both tracked under #69.
"""

from oracle.types import (
    decode_number, decode_date, decode_binary_float, decode_binary_double,
    decode_interval_ds, decode_interval_ym,
)

OSON_MAGIC = b"\xff\x4a\x5a"

# Extended scalar node tags (#69): each is a tag byte followed by a fixed-width
# Oracle binary value (no length prefix — the width is intrinsic to the type),
# decoded by the same routines used for the column wire forms. Tag values
# reverse-engineered from JSON_SCALAR(<native>) images captured on 21c (each
# backed by a fixture in tests/test_oson.py); binary_float/double are stored in
# the order-preserving ("sortable") form, which decode_binary_* already invert.
_EXT_SCALAR = {
    0x36: (8, decode_binary_double),
    0x7F: (4, decode_binary_float),
    0x3C: (7, decode_date),          # DATE
    0x7D: (7, decode_date),          # DATE (variant seen in ub4-offset images)
    0x39: (11, decode_date),         # TIMESTAMP
    0x7C: (13, decode_date),         # TIMESTAMP WITH TIME ZONE
    0x3D: (5, decode_interval_ym),
    0x3E: (11, decode_interval_ds),
}

# Image flags (header ub2).
_FLAG_TREE = 0x2000          # container image (object/array) vs bare scalar
_FLAG_UB2_OFFSETS = 0x04     # container value-offsets are ub2; else ub4 (#69).
                             # Server JSON_OBJECT / JSON() literals set it;
                             # oracledb-produced images (flags 0x2102) clear it
                             # and use ub4 offsets.
_FLAG_UB2_FNAMES = 0x0400    # num_fnames is ub2 (object with > 255 field names);
                             # else ub1 (#69). A container node tag with the
                             # 0x08 bit then also has a ub2 count + ub2 field-ids.
_TAG_WIDE_COUNT = 0x08       # container count + field-ids are ub2, not ub1


class OsonError(Exception):
    """Raised on an OSON image whose encoding we do not yet decode."""


def json_to_text(value: object) -> str:
    """Serialise a Python value to JSON text for a JSON bind (#50).

    pyoracle binds this text as a string and the server casts it to the
    column's JSON type — the native binary OSON encoder is future work (the
    decoder is the inverse). ``Decimal`` is emitted as a JSON number (integral
    values stay exact; others go through ``float``); other unsupported types
    raise ``TypeError`` from :func:`json.dumps`. ``ensure_ascii=False`` keeps
    UTF-8 text natural (pyoracle advertises AL32UTF8)."""
    import json
    from decimal import Decimal

    def default(o):
        if isinstance(o, Decimal):
            return int(o) if o == o.to_integral_value() else float(o)
        raise TypeError(
            f"object of type {type(o).__name__} is not JSON-serialisable")

    return json.dumps(value, ensure_ascii=False, default=default)


def _u16(buf: bytes, pos: int) -> int:
    return (buf[pos] << 8) | buf[pos + 1]


def _uint(buf: bytes, pos: int, size: int) -> int:
    return int.from_bytes(buf[pos:pos + size], "big")


def decode_oson(data: bytes) -> object:
    """Decode an OSON image to the corresponding Python value."""
    if data[:3] != OSON_MAGIC:
        raise OsonError(f"not an OSON image (magic {data[:3].hex()})")
    flags = _u16(data, 4)
    pos = 6
    # Container value-offsets are ub2 when the compact flag is set, else ub4.
    off_size = 2 if (flags & _FLAG_UB2_OFFSETS) else 4
    if not (flags & _FLAG_TREE):
        # Bare scalar image: reserved(ub1), value_size(ub1), scalar node.
        size = data[pos + 1]
        seg = data[pos + 2:pos + 2 + size]
        value, _ = _decode_node(seg, 0, None, seg, off_size)
        return value
    if flags & _FLAG_UB2_FNAMES:              # > 255 field names (#69)
        num_fnames = _u16(data, pos)
        pos += 2
    else:
        num_fnames = data[pos]
        pos += 1
    fnames_size = _u16(data, pos)
    tree_size = _u16(data, pos + 2)
    pos += 6                                  # fnames_size + tree_size + reserved
    pos += num_fnames                         # hash array (1 byte / field)
    offsets = [_u16(data, pos + 2 * i) for i in range(num_fnames)]
    pos += 2 * num_fnames
    fnames_seg = data[pos:pos + fnames_size]
    pos += fnames_size
    tree_seg = data[pos:pos + tree_size]

    def field_name(field_id: int) -> str:
        off = offsets[field_id - 1]
        length = fnames_seg[off]
        return fnames_seg[off + 1:off + 1 + length].decode("utf-8")

    value, _ = _decode_node(tree_seg, 0, field_name, tree_seg, off_size)
    return value


def _decode_node(seg: bytes, off: int, field_name, tree: bytes, off_size: int = 2):
    # Returns (python_value, next_offset). `tree` is the tree segment that
    # container value-offsets are relative to; `field_name` maps an object's
    # field id to its key (None for scalar-only images). `off_size` is the
    # width (2 or 4) of container value-offsets for this image (#69).
    tag = seg[off]
    if tag <= 0x1F:                           # inline short string
        return seg[off + 1:off + 1 + tag].decode("utf-8"), off + 1 + tag
    if 0x20 <= tag <= 0x2F:                    # number, length packed in tag
        length = tag - 0x1F
        return decode_number(seg[off + 1:off + 1 + length]), off + 1 + length
    if tag == 0x30:
        return None, off + 1
    if tag == 0x31:
        return True, off + 1
    if tag == 0x32:
        return False, off + 1
    if tag == 0x33:                           # string, ub1 length prefix
        length = seg[off + 1]
        return seg[off + 2:off + 2 + length].decode("utf-8"), off + 2 + length
    if tag == 0x34:                           # number, ub1 length prefix
        length = seg[off + 1]
        return decode_number(seg[off + 2:off + 2 + length]), off + 2 + length
    # A container with > 255 entries / field-ids uses ub2 count + ub2 field-ids
    # (tag 0x08 bit); otherwise ub1. Value-offset width is per-image (off_size).
    csz = 2 if (tag & _TAG_WIDE_COUNT) else 1
    if (tag & 0xC0) == 0xC0:                   # array container
        count = _uint(seg, off + 1, csz)
        p = off + 1 + csz
        elem_offsets = [_uint(seg, p + off_size * i, off_size)
                        for i in range(count)]
        return ([_decode_node(tree, o, field_name, tree, off_size)[0]
                 for o in elem_offsets], p + off_size * count)
    if (tag & 0xC0) == 0x80:                   # object container
        count = _uint(seg, off + 1, csz)
        p = off + 1 + csz
        ids = [_uint(seg, p + csz * i, csz) for i in range(count)]
        p += csz * count
        val_offsets = [_uint(seg, p + off_size * i, off_size)
                       for i in range(count)]
        return ({field_name(i): _decode_node(tree, o, field_name, tree, off_size)[0]
                 for i, o in zip(ids, val_offsets)}, p + off_size * count)
    if tag in _EXT_SCALAR:                      # extended scalar (#69)
        length, dec = _EXT_SCALAR[tag]
        return dec(seg[off + 1:off + 1 + length]), off + 1 + length
    raise OsonError(f"unsupported OSON node tag 0x{tag:02x} at offset {off}")
