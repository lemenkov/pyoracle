# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for decoding SQL OBJECT (ADT) values (#115).
#
# The wire bytes are not invented: they were captured from a live Oracle 21c
# (XEPDB1) selecting `addr` from a table whose column is
# ADDR_T(street VARCHAR2(40), zip NUMBER, code CHAR(2)) holding the row
# ('Main St', 12345, 'US'). The object value framing (read_dbobject) and the
# packed image are identical across 10g/11g/21c/23ai (fv 4/6/16/24), verified
# live, so a single fixture exercises every tier.

import unittest

from oracle.dbobject import (
    DbObject, ObjectImage, decode_object_image, type_name_to_tns,
)
from oracle.tns import _read_object_column
from oracle.tns_consts import (
    AL32UTF8_CHARSET, TNS_TYPE_CHAR, TNS_TYPE_NUMBER, TNS_TYPE_TIMESTAMP,
    TNS_TYPE_VARCHAR,
)

# The full on-wire object column value for ('Main St', 12345, 'US') plus four
# trailing bytes (the start of the next row) used as a desync sentinel.
_OBJ_COLUMN = bytes.fromhex(
    "01 24 24 00 22 02 08 54 88 dc 42 c0 05 09 31 e0 63 c0 00 a8 c0 9d 0b"
    "00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 01 00 00 00 01 13"
    "01 01 13"
    "84 01 13 07 4d 61 69 6e 20 53 74 04 c3 02 18 2e 02 55 53"
    "08 01 06 03".replace(" ", "")
)
_SENTINEL = bytes.fromhex("08010603")

# Just the packed image (header + attributes), as read_dbobject would hand it
# to the image walk.
_IMAGE = bytes.fromhex("840113" "07" "4d61696e205374" "04" "c302182e" "02" "5553")

_ADDR_LAYOUT = [
    {"name": "STREET", "data_type": TNS_TYPE_VARCHAR, "charset": None},
    {"name": "ZIP", "data_type": TNS_TYPE_NUMBER, "charset": None},
    {"name": "CODE", "data_type": TNS_TYPE_CHAR, "charset": None},
]


class TestObjectColumnFraming(unittest.TestCase):
    def test_read_object_column_keeps_stream_in_sync(self):
        Col = {"type_schema": "PYO", "type_name": "ADDR_T", "charset": 0}
        (Val, Rest) = _read_object_column(_OBJ_COLUMN, Col)
        self.assertIsInstance(Val, ObjectImage)
        self.assertEqual(Val.image, _IMAGE)
        self.assertEqual(Val.type_schema, "PYO")
        self.assertEqual(Val.type_name, "ADDR_T")
        # Exactly the object value is consumed; the next row's bytes remain.
        self.assertEqual(Rest, _SENTINEL)

    def test_null_object_consumes_no_image(self):
        # A NULL object: framing present but a zero image-gate, no image blob.
        # toid(empty) oid(empty) snapshot(empty) version(0) gate(0) flags(0).
        Null = bytes.fromhex("00 00 00 00 00 00".replace(" ", "")) + _SENTINEL
        (Val, Rest) = _read_object_column(Null, {})
        self.assertIsNone(Val)
        self.assertEqual(Rest, _SENTINEL)


class TestImageWalk(unittest.TestCase):
    def test_decode_addr_image(self):
        Attrs = decode_object_image(_IMAGE, _ADDR_LAYOUT)
        self.assertEqual(Attrs,
                         [("STREET", "Main St"), ("ZIP", 12345), ("CODE", "US")])

    def test_null_attribute(self):
        # STREET NULL (length 0), ZIP 12345, CODE 'US'.
        Image = bytes.fromhex("840113" "00" "04" "c302182e" "02" "5553")
        Attrs = decode_object_image(Image, _ADDR_LAYOUT)
        self.assertEqual(Attrs,
                         [("STREET", None), ("ZIP", 12345), ("CODE", "US")])


class TestDbObjectApi(unittest.TestCase):
    def setUp(self):
        Attrs = decode_object_image(_IMAGE, _ADDR_LAYOUT, AL32UTF8_CHARSET)
        self.obj = DbObject("PYO.ADDR_T", Attrs)

    def test_attribute_access(self):
        self.assertEqual(self.obj.STREET, "Main St")
        self.assertEqual(self.obj.ZIP, 12345)
        self.assertEqual(self.obj.CODE, "US")

    def test_item_access_and_views(self):
        self.assertEqual(self.obj["ZIP"], 12345)
        self.assertEqual(self.obj.aslist(), ["Main St", 12345, "US"])
        self.assertEqual(self.obj.asdict(),
                         {"STREET": "Main St", "ZIP": 12345, "CODE": "US"})
        self.assertEqual(self.obj.type_name, "PYO.ADDR_T")

    def test_unknown_attribute_raises(self):
        with self.assertRaises(AttributeError):
            _ = self.obj.NOPE

    def test_equality_and_repr(self):
        Twin = DbObject("PYO.ADDR_T", decode_object_image(_IMAGE, _ADDR_LAYOUT))
        self.assertEqual(self.obj, Twin)
        self.assertIn("STREET='Main St'", repr(self.obj))


class TestTypeNameMap(unittest.TestCase):
    def test_known_names(self):
        self.assertEqual(type_name_to_tns("VARCHAR2"), TNS_TYPE_VARCHAR)
        self.assertEqual(type_name_to_tns("NUMBER"), TNS_TYPE_NUMBER)
        self.assertEqual(type_name_to_tns("CHAR"), TNS_TYPE_CHAR)

    def test_precision_suffix_stripped(self):
        self.assertEqual(type_name_to_tns("TIMESTAMP(6)"), TNS_TYPE_TIMESTAMP)

    def test_unknown_name_is_none(self):
        # A nested object type (out of scope for #115) yields None, so the
        # attribute decodes to its raw bytes rather than desyncing.
        self.assertIsNone(type_name_to_tns("SOME_NESTED_TYPE"))
        self.assertIsNone(type_name_to_tns(None))


if __name__ == "__main__":
    unittest.main()
