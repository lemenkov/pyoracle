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
_FLAG_UB4_TREE_SIZE = 0x1000  # tree-segment size is ub4, not ub2 (tree > 64 KiB);
                             # set on large documents (#88). fnames_size stays ub2.
_TAG_WIDE_COUNT = 0x08       # container count + field-ids are ub2, not ub1
_TAG_UB4_COUNT = 0x10        # container count + field-ids are ub4 (> 65535
                             # entries/keys, #88); takes precedence over 0x08.
_TAG_UB4_OFFSETS = 0x20      # this container's value-offsets are ub4 (a container
                             # whose values span a >64 KiB tree, #88), overriding
                             # the image-level offset width.


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


def _oson_scalar_node(value) -> bytes:
    from decimal import Decimal
    from oracle.tns import encode_token_num, encode_token_decimal
    if value is None:
        return b"\x30"
    if value is True:
        return b"\x31"
    if value is False:
        return b"\x32"
    if isinstance(value, str):
        b = value.encode("utf-8")
        if len(b) > 0xFF:
            raise OsonError("string too long for the native OSON encoder")
        return (bytes([len(b)]) + b) if len(b) <= 0x1F else b"\x33" + bytes([len(b)]) + b
    if isinstance(value, Decimal):
        nb = encode_token_decimal(value)
        return b"\x34" + bytes([len(nb)]) + nb
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        nb = encode_token_num(value)
        return b"\x34" + bytes([len(nb)]) + nb
    raise OsonError(f"cannot OSON-encode {type(value).__name__}")


def _oson_emit(value, buf: bytearray, fid) -> int:
    # Append `value`'s node to `buf`; return its start offset. Containers use
    # ub1 count + ub1 field-ids + ub2 value-offsets (matching the server's
    # compact small-document form, flag 0x04). > 255 entries would need ub2 —
    # raise so the caller falls back to the text cast.
    start = len(buf)
    if isinstance(value, dict):
        if len(value) > 0xFF:
            raise OsonError("object too wide for the native OSON encoder")
        items = list(value.items())
        buf += bytes([0x84, len(items)])
        for k in value:
            buf += bytes([fid(k)])
        off_pos = len(buf)
        buf += b"\x00\x00" * len(items)
        offs = [_oson_emit(v, buf, fid) for _, v in items]
        for i, o in enumerate(offs):
            buf[off_pos + 2 * i:off_pos + 2 * i + 2] = o.to_bytes(2, "big")
        return start
    if isinstance(value, list):
        if len(value) > 0xFF:
            raise OsonError("array too long for the native OSON encoder")
        buf += bytes([0xC4, len(value)])
        off_pos = len(buf)
        buf += b"\x00\x00" * len(value)
        offs = [_oson_emit(v, buf, fid) for v in value]
        for i, o in enumerate(offs):
            buf[off_pos + 2 * i:off_pos + 2 * i + 2] = o.to_bytes(2, "big")
        return start
    buf += _oson_scalar_node(value)
    return start


# Native JSON bind OAC (#70): like the VECTOR one (§18.1) but type 119 with a
# 32 MiB max length. Captured from python-oracledb on 21c.
JSON_BIND_OAC = bytes.fromhex(
    "77010000040200000000040200000000000000040200000000")


def encode_oson(value) -> bytes:
    """Encode a Python value to an OSON image (the inverse of decode_oson) for a
    native JSON bind (#70). Covers the common small-document shape — scalars,
    objects/arrays up to 255 entries, strings up to 255 bytes, segments up to
    64 KiB — and raises OsonError for anything larger so the bind path can fall
    back to the text cast (which the server parses just as well). Container
    value-offsets are ub2 (the compact 0x04 form); field-name hashes are sent as
    zero (the server accepts that — verified by round-trip on 21c)."""
    if not isinstance(value, (dict, list)):
        node = _oson_scalar_node(value)
        return b"\xff\x4a\x5a\x01" + b"\x00\x16\x00" + bytes([len(node)]) + node
    fnames = []
    ids = {}

    def fid(name):
        if not isinstance(name, str):
            raise OsonError("JSON object keys must be strings")
        if name not in ids:
            ids[name] = len(fnames) + 1
            fnames.append(name)
            if len(fnames) > 0xFF:
                raise OsonError("too many distinct keys for the native encoder")
        return ids[name]

    def walk(v):
        if isinstance(v, dict):
            for k, sub in v.items():
                fid(k)
                walk(sub)
        elif isinstance(v, list):
            for sub in v:
                walk(sub)
    walk(value)

    fnames_b = [n.encode("utf-8") for n in fnames]
    fnames_seg = b"".join(bytes([len(b)]) + b for b in fnames_b)
    off_arr = b""
    pos = 0
    for b in fnames_b:
        off_arr += pos.to_bytes(2, "big")
        pos += 1 + len(b)
    hash_arr = b"\x00" * len(fnames)
    tree = bytearray()
    _oson_emit(value, tree, fid)
    if len(fnames_seg) > 0xFFFF or len(tree) > 0xFFFF:
        raise OsonError("document too large for the native OSON encoder")
    header = (b"\xff\x4a\x5a\x01" + b"\x21\x06" + bytes([len(fnames)])
              + len(fnames_seg).to_bytes(2, "big") + len(tree).to_bytes(2, "big")
              + b"\x00\x00")
    return header + hash_arr + off_arr + fnames_seg + bytes(tree)


def _u16(buf: bytes, pos: int) -> int:
    return (buf[pos] << 8) | buf[pos + 1]


def _uint(buf: bytes, pos: int, size: int) -> int:
    return int.from_bytes(buf[pos:pos + size], "big")


def decode_oson(data: bytes) -> object:
    """Decode an OSON image to the corresponding Python value.

    A structurally short image (a header, node, or segment that indexes past
    the end) raises OsonError, honouring the module's "malformed -> OsonError"
    contract instead of leaking the raw IndexError of an out-of-range read.
    """
    if data[:3] != OSON_MAGIC:
        raise OsonError(f"not an OSON image (magic {data[:3].hex()})")
    try:
        return _decode_image(data)
    except IndexError as exc:
        raise OsonError("truncated or malformed OSON image") from exc


def _decode_image(data: bytes) -> object:
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
    if flags & _FLAG_UB4_TREE_SIZE:           # tree > 64 KiB (#88)
        tree_size = _uint(data, pos + 2, 4)
        pos += 8                              # fnames_size(2) + tree_size(4) + reserved(2)
    else:
        tree_size = _u16(data, pos + 2)
        pos += 6                              # fnames_size + tree_size + reserved
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


def _decode_child(tree: bytes, off: int, field_name, off_size: int,
                  memo: dict, stack: set):
    # Bounded recursion into a container value-offset. Memoise the decoded value
    # by offset so a shared child (a "diamond" of offsets) is decoded once rather
    # than exponentially, and reject an offset already on the current path (a
    # cycle) as OsonError rather than recursing forever. Together these cap the
    # total work at O(number of nodes) even for a crafted image: a malformed or
    # hostile OSON image must never hang the client (#165). Valid server images
    # are acyclic, so this only changes behaviour on bad input; a genuinely
    # shared subtree decodes to an equal (possibly aliased) value, which is fine
    # for JSON value semantics.
    if off in memo:
        return memo[off]
    if off in stack:
        raise OsonError(f"cyclic OSON node offset {off}")
    stack.add(off)
    value = _decode_node(tree, off, field_name, tree, off_size, memo, stack)[0]
    stack.discard(off)
    memo[off] = value
    return value


def _decode_node(seg: bytes, off: int, field_name, tree: bytes,
                 off_size: int = 2, memo: dict = None, stack: set = None):
    # Returns (python_value, next_offset). `tree` is the tree segment that
    # container value-offsets are relative to; `field_name` maps an object's
    # field id to its key (None for scalar-only images). `off_size` is the
    # width (2 or 4) of container value-offsets for this image (#69). `memo` /
    # `stack` bound the offset-following recursion (see _decode_child); they are
    # created on the top-level call and threaded through the descent.
    if memo is None:
        memo, stack = {}, set()
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
    if tag == 0x37:                           # string, ub2 length prefix (>255 B, #88)
        length = _u16(seg, off + 1)
        return seg[off + 3:off + 3 + length].decode("utf-8"), off + 3 + length
    if tag == 0x38:                           # string, ub4 length prefix (>64 KiB, #88)
        length = _uint(seg, off + 1, 4)
        return seg[off + 5:off + 5 + length].decode("utf-8"), off + 5 + length
    # A container with > 255 entries / field-ids uses ub2 count + ub2 field-ids
    # (tag 0x08 bit); otherwise ub1. The value-offset width is per-image
    # (off_size), but a large container overrides it to ub4 via the tag 0x20 bit
    # (#88) — its values span a >64 KiB tree so ub2 offsets can't address them.
    csz = 4 if (tag & _TAG_UB4_COUNT) else (2 if (tag & _TAG_WIDE_COUNT) else 1)
    osz = 4 if (tag & _TAG_UB4_OFFSETS) else off_size
    if (tag & 0xC0) == 0xC0:                   # array container
        count = _uint(seg, off + 1, csz)
        p = off + 1 + csz
        # The offset array (count * osz bytes) must fit in the image; a crafted
        # count (e.g. ub4 0xffffffff) would otherwise spin building a
        # multi-billion-entry list before any offset is followed (#165).
        if p + osz * count > len(seg):
            raise OsonError("OSON array count exceeds image")
        elem_offsets = [_uint(seg, p + osz * i, osz)
                        for i in range(count)]
        return ([_decode_child(tree, o, field_name, off_size, memo, stack)
                 for o in elem_offsets], p + osz * count)
    if (tag & 0xC0) == 0x80:                   # object container
        count = _uint(seg, off + 1, csz)
        p = off + 1 + csz
        # Field-id array (count * csz) + value-offset array (count * osz) must
        # fit in the image, else a crafted count spins as above (#165).
        if p + (csz + osz) * count > len(seg):
            raise OsonError("OSON object count exceeds image")
        ids = [_uint(seg, p + csz * i, csz) for i in range(count)]
        p += csz * count
        val_offsets = [_uint(seg, p + osz * i, osz)
                       for i in range(count)]
        return ({field_name(i): _decode_child(tree, o, field_name, off_size,
                                              memo, stack)
                 for i, o in zip(ids, val_offsets)}, p + osz * count)
    if tag in _EXT_SCALAR:                      # extended scalar (#69)
        length, dec = _EXT_SCALAR[tag]
        return dec(seg[off + 1:off + 1 + length]), off + 1 + length
    raise OsonError(f"unsupported OSON node tag 0x{tag:02x} at offset {off}")
