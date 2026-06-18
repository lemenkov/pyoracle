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
    COLLECTION_NESTED_TABLE, COLLECTION_VARRAY, DbObject, DbObjectType,
    ObjectImage, decode_collection_image, decode_object_image, type_name_to_tns,
)
from oracle.tns import (
    _encode_object_bind_value, _read_object_column, encode_object_image,
)
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


_ADDR_TYPE = DbObjectType(
    "PYO", "ADDR_T", bytes.fromhex("00112233445566778899aabbccddeeff"), 1,
    _ADDR_LAYOUT)


class TestObjectBindEncode(unittest.TestCase):
    # The bind encode writes the image length long-form (0xFE + ub4), while the
    # server sends it short-form, so the encoder isn't byte-equal to a captured
    # image; the contract is that it round-trips back through the #115 decoders.

    def test_image_encode_decode_roundtrip(self):
        Obj = _ADDR_TYPE.newobject({"STREET": "Main St", "ZIP": 12345,
                                    "CODE": "US"})
        Image = encode_object_image(Obj)
        self.assertEqual(decode_object_image(Image, _ADDR_LAYOUT),
                         [("STREET", "Main St"), ("ZIP", 12345), ("CODE", "US")])

    def test_image_encode_null_attribute(self):
        Obj = _ADDR_TYPE.newobject({"STREET": None, "ZIP": 7, "CODE": None})
        Attrs = decode_object_image(encode_object_image(Obj), _ADDR_LAYOUT)
        self.assertEqual(Attrs, [("STREET", None), ("ZIP", 7), ("CODE", None)])

    def test_bind_value_framing_roundtrips(self):
        # The full write_dbobject framing must parse back through the row
        # decoder (with the next-row sentinel preserved).
        Obj = _ADDR_TYPE.newobject({"STREET": "Main St", "ZIP": 12345,
                                    "CODE": "US"})
        Wire = _encode_object_bind_value(Obj) + _SENTINEL
        Col = {"type_schema": "PYO", "type_name": "ADDR_T", "charset": 0}
        (Val, Rest) = _read_object_column(Wire, Col)
        self.assertIsInstance(Val, ObjectImage)
        self.assertEqual(Rest, _SENTINEL)
        self.assertEqual(decode_object_image(Val.image, _ADDR_LAYOUT),
                         [("STREET", "Main St"), ("ZIP", 12345), ("CODE", "US")])

    def test_bind_value_carries_type_oid(self):
        # The bind toid wraps the type's 16-byte OID (00 22 02 08 + oid + extent).
        Obj = _ADDR_TYPE.newobject()
        Wire = _encode_object_bind_value(Obj)
        # toid = 00 22 02 08 + the 16-byte type OID + the fixed extent OID.
        self.assertIn(b"\x00\x22\x02\x08" + _ADDR_TYPE.oid, Wire)


class TestDbObjectTypeApi(unittest.TestCase):
    def test_newobject_defaults_null(self):
        Obj = _ADDR_TYPE.newobject()
        self.assertEqual(Obj.aslist(), [None, None, None])
        self.assertIs(Obj._dbtype, _ADDR_TYPE)

    def test_newobject_seed_case_insensitive(self):
        Obj = _ADDR_TYPE.newobject({"street": "X", "Zip": 1, "CODE": "US"})
        self.assertEqual(Obj.STREET, "X")
        self.assertEqual(Obj.ZIP, 1)

    def test_set_and_reject_unknown(self):
        Obj = _ADDR_TYPE.newobject()
        Obj.STREET = "Main"
        self.assertEqual(Obj.STREET, "Main")
        with self.assertRaises(AttributeError):
            Obj.NOPE = 1
        with self.assertRaises(KeyError):
            Obj["NOPE"] = 1

    def test_seed_from_sequence(self):
        Obj = _ADDR_TYPE.newobject(["Main St", 12345, "US"])
        self.assertEqual(Obj.aslist(), ["Main St", 12345, "US"])

    def test_type_repr_and_names(self):
        self.assertEqual(_ADDR_TYPE.full_name, "PYO.ADDR_T")
        self.assertEqual(_ADDR_TYPE.attr_names, ["STREET", "ZIP", "CODE"])


_NUM_VA = DbObjectType(
    "PYO", "NUM_VA", bytes.fromhex("ffeeddccbbaa99887766554433221100"), 1, [],
    is_collection=True, collection_type=COLLECTION_VARRAY,
    element={"name": "element", "data_type": TNS_TYPE_NUMBER, "charset": None},
    max_elements=5)


class TestVarrayCollection(unittest.TestCase):
    def test_newobject_list_semantics(self):
        v = _NUM_VA.newobject([10, 20, 30])
        self.assertTrue(v.is_collection)
        self.assertEqual(list(v), [10, 20, 30])
        self.assertEqual(v[1], 20)
        self.assertEqual(len(v), 3)
        v.append(40)
        v.extend([50, 60])
        self.assertEqual(v.aslist(), [10, 20, 30, 40, 50, 60])
        v[0] = 99
        self.assertEqual(v[0], 99)

    def test_empty_and_default(self):
        self.assertEqual(_NUM_VA.newobject().aslist(), [])
        self.assertEqual(_NUM_VA.newobject([]).aslist(), [])

    def test_image_encode_decode_roundtrip(self):
        v = _NUM_VA.newobject([10, 20, 30])
        Image = encode_object_image(v)
        self.assertEqual(decode_collection_image(Image, _NUM_VA.element),
                         [10, 20, 30])

    def test_image_roundtrip_empty_and_null_element(self):
        self.assertEqual(
            decode_collection_image(encode_object_image(_NUM_VA.newobject([])),
                                    _NUM_VA.element), [])
        v = _NUM_VA.newobject([1, None, 3])
        self.assertEqual(
            decode_collection_image(encode_object_image(v), _NUM_VA.element),
            [1, None, 3])

    def test_bind_value_framing_roundtrips(self):
        v = _NUM_VA.newobject([7, 8, 9])
        Wire = _encode_object_bind_value(v) + _SENTINEL
        (Val, Rest) = _read_object_column(Wire, {"charset": 0})
        self.assertIsInstance(Val, ObjectImage)
        self.assertEqual(Rest, _SENTINEL)
        self.assertEqual(decode_collection_image(Val.image, _NUM_VA.element),
                         [7, 8, 9])

    def test_asdict_rejected_on_collection(self):
        with self.assertRaises(TypeError):
            _NUM_VA.newobject([1]).asdict()


class TestNestedTableCollection(unittest.TestCase):
    # A nested table (#118) shares the VARRAY image and bind framing exactly;
    # only collection_type differs (2 vs 3). These lock that in offline.
    _NT = DbObjectType(
        "PYO", "NUM_NT", bytes.fromhex("0102030405060708090a0b0c0d0e0f10"), 1,
        [], is_collection=True, collection_type=COLLECTION_NESTED_TABLE,
        element={"name": "element", "data_type": TNS_TYPE_NUMBER,
                 "charset": None})

    def test_collection_type_is_nested_table(self):
        self.assertEqual(self._NT.collection_type, COLLECTION_NESTED_TABLE)
        self.assertNotEqual(COLLECTION_NESTED_TABLE, COLLECTION_VARRAY)

    def test_image_encode_decode_roundtrip(self):
        v = self._NT.newobject([10, 20, 30])
        self.assertEqual(
            decode_collection_image(encode_object_image(v), self._NT.element),
            [10, 20, 30])

    def test_bind_value_framing_roundtrips(self):
        v = self._NT.newobject([1, None, 3])
        Wire = _encode_object_bind_value(v) + _SENTINEL
        (Val, Rest) = _read_object_column(Wire, {"charset": 0})
        self.assertEqual(Rest, _SENTINEL)
        self.assertEqual(decode_collection_image(Val.image, self._NT.element),
                         [1, None, 3])


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
