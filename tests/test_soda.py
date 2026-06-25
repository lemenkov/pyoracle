# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the SODA layer (#163, #199): the pure helpers and the
18c+ gate. The live collection round-trips are in test_integration.py."""

import unittest

from oracle.exceptions import NotSupportedError
from oracle.soda import (SodaDocument, _check_soda_supported,
                         _doc_to_bind, _encode_content, _names_query,
                         _norm_filter, _norm_metadata)


class _FakeConn:
    def __init__(self, major):
        self.server_version = major << 24


class TestSodaHelpers(unittest.TestCase):
    def test_norm_metadata(self):
        self.assertIsNone(_norm_metadata(None))
        self.assertEqual(_norm_metadata('{"a":1}'), '{"a":1}')   # str passthrough
        self.assertEqual(_norm_metadata({"a": 1}), '{"a": 1}')   # dict -> JSON

    def test_names_query_variants(self):
        sql, binds = _names_query(None, 0)
        self.assertNotIn("WHERE", sql)
        self.assertNotIn("FETCH", sql)
        self.assertEqual(binds, [])

        sql, binds = _names_query("abc", 0)
        self.assertIn("uri_name >= :start_name", sql)
        self.assertEqual(binds, ["abc"])

        sql, binds = _names_query(None, 5)
        self.assertIn("FETCH FIRST 5 ROWS ONLY", sql)
        self.assertEqual(binds, [])

        sql, _ = _names_query("abc", 3)
        self.assertIn("uri_name >= :start_name", sql)
        self.assertIn("FETCH FIRST 3 ROWS ONLY", sql)
        # ordered, and ':start' (reserved word) is never used as a bind name
        self.assertIn("ORDER BY uri_name", sql)
        self.assertNotIn(":start ", sql)

    def test_soda_gate(self):
        # SODA needs an 18c+ server (DBMS_SODA).
        for major in (9, 10, 11, 12):
            with self.assertRaises(NotSupportedError):
                _check_soda_supported(_FakeConn(major))
        for major in (18, 19, 21, 23):
            _check_soda_supported(_FakeConn(major))   # no raise


class TestSodaDocument(unittest.TestCase):
    def test_encode_content(self):
        self.assertEqual(_encode_content({"a": 1}), b'{"a": 1}')   # dict -> JSON
        self.assertEqual(_encode_content('{"a":1}'), b'{"a":1}')   # str -> utf8
        self.assertEqual(_encode_content(b'\x00\x01'), b'\x00\x01')  # bytes as-is
        self.assertEqual(_encode_content("é").decode("utf-8"), "é")

    def test_document_accessors(self):
        doc = SodaDocument(content=b'{"n": 5}', key="K1", version="V1")
        self.assertEqual(doc.getContentAsBytes(), b'{"n": 5}')
        self.assertEqual(doc.getContentAsString(), '{"n": 5}')
        self.assertEqual(doc.getContent(), {"n": 5})        # JSON -> dict
        self.assertEqual(doc.key, "K1")
        self.assertEqual(doc.mediaType, "application/json")
        # a non-JSON document returns its content as a string, not parsed
        txt = SodaDocument(content=b"hello", mediaType="text/plain")
        self.assertEqual(txt.getContent(), "hello")
        # an empty document
        self.assertIsNone(SodaDocument().getContent())
        self.assertIsNone(SodaDocument().getContentAsString())

    def test_doc_to_bind(self):
        # a SodaDocument keeps its key + media type
        doc = SodaDocument(content=b'{"a":1}', key="K", mediaType="application/json")
        self.assertEqual(_doc_to_bind(doc), ("K", b'{"a":1}', "application/json"))
        # a bare value gets no key and the default media type
        key, content, mt = _doc_to_bind({"a": 1})
        self.assertIsNone(key)
        self.assertEqual((content, mt), (b'{"a": 1}', "application/json"))

    def test_norm_filter(self):
        self.assertIsNone(_norm_filter(None))
        self.assertEqual(_norm_filter({"age": {"$gte": 30}}),
                         '{"age": {"$gte": 30}}')           # dict -> JSON
        self.assertEqual(_norm_filter('{"a":1}'), '{"a":1}')   # str passthrough


if __name__ == "__main__":
    unittest.main()
