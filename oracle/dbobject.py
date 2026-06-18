# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# SQL OBJECT (ADT) value support (#115).
#
# Decoding a SQL object column is two-phase (mirrors python-oracledb's
# base.pyx _process_column_data -> read_dbobject):
#   1. DESCRIBE gives the column's type identity (owner + name, captured in the
#      DCB by oracle.tns). The ordered attribute layout is fetched separately
#      from the data dictionary (ALL_TYPE_ATTRS) and cached per connection.
#   2. ROW: the wire value carries a small framing wrapper plus a packed
#      "image"; the image is the attributes serialised length-prefixed in
#      declaration order behind a short header.
#
# This module owns the image walk (decode_object_image) and the surfaced
# Python value (DbObject). The wire-framing wrapper is read in oracle.tns
# (which hands us an ObjectImage placeholder); the layout fetch lives on the
# connection. Read-only here -- binding an object is #116, and VARRAY / nested
# table / REF are #117 / #118 / #119.

from oracle.exceptions import NotSupportedError
from oracle.tns_consts import (
    AL32UTF8_CHARSET,
    TNS_TYPE_BDOUBLE, TNS_TYPE_BFLOAT, TNS_TYPE_CHAR, TNS_TYPE_DATE,
    TNS_TYPE_INTERVALDS, TNS_TYPE_INTERVALYM, TNS_TYPE_NUMBER, TNS_TYPE_RAW,
    TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPLTZ, TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
)

# Object image header flags (python-oracledb constants.pxi "image flags").
_OBJ_IS_DEGENERATE = 0x10       # object stored in a LOB -- not supported here
_OBJ_NO_PREFIX_SEG = 0x04       # no prefix segment precedes the attributes

# Length markers inside the image (python-oracledb base_impl.pxd).
_LONG_LENGTH_INDICATOR = 254    # next 4 bytes are a big-endian length
_NULL_LENGTH_INDICATOR = 255    # NULL attribute (no bytes follow)

# Map an ALL_TYPE_ATTRS.attr_type_name to the TNS data type code that
# oracle.types.decode_value understands. The image stores each scalar with the
# same on-wire encoding the column form uses, so the existing scalar decoders
# apply unchanged. Timestamp variants all decode through decode_date (which
# keys on byte length), so collapsing them onto TNS_TYPE_TIMESTAMP is safe.
# A name we don't map (e.g. a nested object type -- #117/#118) yields None, and
# decode_value then returns the attribute's raw bytes rather than desyncing.
_TYPE_NAME_TO_TNS = {
    'VARCHAR2': TNS_TYPE_VARCHAR,
    'NVARCHAR2': TNS_TYPE_VARCHAR,
    'CHAR': TNS_TYPE_CHAR,
    'NCHAR': TNS_TYPE_CHAR,
    'NUMBER': TNS_TYPE_NUMBER,
    'FLOAT': TNS_TYPE_NUMBER,
    'RAW': TNS_TYPE_RAW,
    'DATE': TNS_TYPE_DATE,
    'TIMESTAMP': TNS_TYPE_TIMESTAMP,
    'TIMESTAMP WITH TIME ZONE': TNS_TYPE_TIMESTAMPTZ,
    'TIMESTAMP WITH LOCAL TIME ZONE': TNS_TYPE_TIMESTAMPLTZ,
    'BINARY_FLOAT': TNS_TYPE_BFLOAT,
    'BINARY_DOUBLE': TNS_TYPE_BDOUBLE,
    'INTERVAL DAY TO SECOND': TNS_TYPE_INTERVALDS,
    'INTERVAL YEAR TO MONTH': TNS_TYPE_INTERVALYM,
}


def type_name_to_tns(name: str | None) -> int | None:
    """TNS data type code for an ALL_TYPE_ATTRS attribute type name (or None).

    TIMESTAMP / INTERVAL names carry a precision suffix (e.g. ``TIMESTAMP(6)``);
    strip it before the lookup.
    """
    if not name:
        return None
    Key = name.split('(')[0].strip()
    return _TYPE_NAME_TO_TNS.get(Key)


class ObjectImage:
    """Placeholder for an object column value carried in a row.

    The row decoder produces this from the wire framing without needing the
    attribute layout (so the row stream stays in sync); the cursor turns it
    into a DbObject once the layout has been fetched.
    """

    __slots__ = ('type_oid', 'type_schema', 'type_name', 'charset', 'image')

    def __init__(self, type_oid, type_schema, type_name, charset, image):
        self.type_oid = type_oid
        self.type_schema = type_schema
        self.type_name = type_name
        self.charset = charset
        self.image = image


class DbObject:
    """A decoded SQL OBJECT (ADT) value.

    Attributes are read by name (``obj.STREET``) or item (``obj['STREET']``),
    in the order Oracle declared them. Read-only; oracledb-compatible enough
    for the common ``cursor.fetchone()`` use.
    """

    def __init__(self, type_name: str | None, attrs: list[tuple[str, object]]):
        # _ prefixes keep the namespace clear of attribute names.
        object.__setattr__(self, '_type_name', type_name)
        object.__setattr__(self, '_attrs', dict(attrs))
        object.__setattr__(self, '_order', [Name for Name, _ in attrs])

    @property
    def type_name(self) -> str | None:
        return self._type_name

    def __getattr__(self, name: str):
        try:
            return object.__getattribute__(self, '_attrs')[name]
        except KeyError:
            raise AttributeError(name)

    def __getitem__(self, name: str):
        return self._attrs[name]

    def aslist(self) -> list:
        """The attribute values in declaration order."""
        return [self._attrs[Name] for Name in self._order]

    def asdict(self) -> dict:
        """A name -> value mapping of the attributes."""
        return dict(self._attrs)

    def __eq__(self, other):
        if not isinstance(other, DbObject):
            return NotImplemented
        return (self._type_name == other._type_name
                and self._attrs == other._attrs)

    def __repr__(self):
        Body = ', '.join(f"{Name}={self._attrs[Name]!r}" for Name in self._order)
        Name = self._type_name or 'OBJECT'
        return f"<oracle.DbObject {Name}({Body})>"


def _read_length(Image: bytes, Pos: int) -> tuple[int | None, int]:
    # One attribute / segment length: a single byte, unless it is the long
    # indicator (then a 4-byte big-endian length follows) or the NULL marker.
    Length = Image[Pos]
    Pos += 1
    if Length == _NULL_LENGTH_INDICATOR:
        return (None, Pos)
    if Length == _LONG_LENGTH_INDICATOR:
        Length = int.from_bytes(Image[Pos:Pos + 4], 'big')
        Pos += 4
    return (Length, Pos)


def _read_image_header(Image: bytes) -> int:
    # Mirrors python-oracledb DbObjectPickleBuffer.read_header: flags + version,
    # the (skipped) image length, then -- unless the NO_PREFIX_SEG flag is set
    # -- a prefix segment that is read and skipped. Returns the offset of the
    # first attribute.
    Flags = Image[0]
    Pos = 2                                      # flags + version
    (_, Pos) = _read_length(Image, Pos)          # image length (unused here)
    if Flags & _OBJ_IS_DEGENERATE:
        raise NotSupportedError("decoding an object stored in a LOB is not supported")
    if not (Flags & _OBJ_NO_PREFIX_SEG):
        (PrefixLen, Pos) = _read_length(Image, Pos)
        Pos += PrefixLen or 0
    return Pos


def decode_object_image(Image: bytes, Layout: list[dict],
                        Charset: int = AL32UTF8_CHARSET) -> list[tuple[str, object]]:
    """Walk an object image into a list of (attr_name, value) pairs.

    ``Layout`` is the ordered attribute list from the data dictionary; each
    entry is ``{'name': str, 'data_type': int|None, 'charset': int|None}``.
    """
    from oracle.types import decode_value
    Pos = _read_image_header(Image)
    Attrs = []
    for Attr in Layout:
        (Length, Pos) = _read_length(Image, Pos)
        if Length is None or Length == 0:
            Attrs.append((Attr['name'], None))
            continue
        Raw = bytes(Image[Pos:Pos + Length])
        Pos += Length
        Col = {
            'data_type': Attr.get('data_type'),
            'charset': Attr.get('charset') or Charset,
        }
        Attrs.append((Attr['name'], decode_value(Col, Raw)))
    return Attrs
