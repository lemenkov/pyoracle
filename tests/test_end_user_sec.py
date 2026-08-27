# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""End-user security context (TTC func 205, #460).

The feature is tcps-only, so it cannot be captured on a cleartext transport;
these offline tests pin the byte layout reconstructed from the reference thin
client (docs/PROTOCOL.md §34) plus the connection-side negotiation guards.
"""

import unittest

import seerdb
from seerdb.client.connection import OracleConnect
from seerdb.common.end_user_sec import (
    EndUserSecurityContext,
    create_end_user_security_context,
)
from seerdb.common.exceptions import NotSupportedError, ProgrammingError
from seerdb.common.oson import decode_oson
from seerdb.common.tns import (
    _obj_two_lengths,
    encode_end_user_sec_piggyback,
    encode_sb4,
)

# compile_caps[45] (FEATURE_BACKPORT2) with the end-user-sec bit set, as 26ai
# advertises it.
_CAPS_WITH_EUC = bytes([0] * 45 + [0x03])
_CAPS_WITHOUT = bytes([0] * 45 + [0x00])


class TestCreateContext(unittest.TestCase):
    def test_token_path(self):
        ctx = create_end_user_security_context(
            end_user_identity='IAM-TOKEN', database_access_token='ACCESS'
        )
        self.assertIsInstance(ctx, EndUserSecurityContext)
        d = decode_oson(ctx.oson_bytes)
        self.assertEqual(
            d,
            {
                'ver': '1.0',
                'end_user_token': 'IAM-TOKEN',
                'database_access_token': 'ACCESS',
            },
        )

    def test_name_key_path_with_roles_and_attrs(self):
        ctx = create_end_user_security_context(
            end_user_identity=('BOB', 'KEY1'),
            database_access_token='ACCESS',
            data_roles=['R1', 'R2'],
            attributes={'dept': 'eng'},
        )
        d = decode_oson(ctx.oson_bytes)
        self.assertEqual(d['ver'], '1.0')
        self.assertEqual(d['end_user_name'], 'BOB')
        self.assertEqual(d['end_user_contextid'], 'KEY1')
        self.assertEqual(d['database_access_token'], 'ACCESS')
        self.assertEqual(d['data_roles'], ['R1', 'R2'])
        self.assertEqual(d['attributes'], [{'name': 'dept', 'values': 'eng'}])

    def test_key_order_matches_reference(self):
        # The OSON field table must list keys in the reference client's insertion
        # order so the server parses the image identically.
        ctx = create_end_user_security_context(
            end_user_identity=('BOB', 'KEY1'),
            database_access_token='ACCESS',
            data_roles=['R1'],
            attributes={'a': 'b'},
        )
        self.assertEqual(
            list(decode_oson(ctx.oson_bytes)),
            [
                'ver',
                'end_user_name',
                'end_user_contextid',
                'database_access_token',
                'data_roles',
                'attributes',
            ],
        )

    def test_invalid_identity(self):
        with self.assertRaises(ValueError):
            create_end_user_security_context(
                end_user_identity=123, database_access_token='A'
            )
        with self.assertRaises(ValueError):
            create_end_user_security_context(
                end_user_identity=('only-one',), database_access_token='A'
            )

    def test_empty_access_token(self):
        with self.assertRaises(ValueError):
            create_end_user_security_context(
                end_user_identity='T', database_access_token=''
            )


class TestEncodePiggyback(unittest.TestCase):
    def test_byte_layout_fv24(self):
        ctx = create_end_user_security_context(
            end_user_identity='T', database_access_token='A'
        )
        pb = encode_end_user_sec_piggyback(0x07, 24, ctx.oson_bytes)
        expect = bytes([0x11, 205, 0x07])  # PIGGYBACK, func 205, seq
        expect += encode_sb4(0)  # ub8 token (fv > 17)
        expect += encode_sb4(1)  # attach flag ub4 = 1
        expect += bytes([1])  # pointer(kpdkve)
        expect += encode_sb4(1)  # num key-value pairs = 1
        expect += encode_sb4(0)  # kv flags = 0
        expect += _obj_two_lengths(b'ORCL_XS_AUTHZ_CONTEXT')  # keyword
        expect += _obj_two_lengths(b'')  # text NULL
        expect += _obj_two_lengths(ctx.oson_bytes)  # value = OSON image
        self.assertEqual(pb, expect)

    def test_fv17_omits_token(self):
        ctx = create_end_user_security_context(
            end_user_identity='T', database_access_token='A'
        )
        pb = encode_end_user_sec_piggyback(0x07, 17, ctx.oson_bytes)
        # header then straight to the attach flag — no ub8 token byte.
        self.assertEqual(pb[:5], bytes([0x11, 205, 0x07, 0x01, 0x01]))

    def test_carries_keyword_and_oson(self):
        ctx = create_end_user_security_context(
            end_user_identity='T', database_access_token='A'
        )
        pb = encode_end_user_sec_piggyback(1, 24, ctx.oson_bytes)
        self.assertIn(b'ORCL_XS_AUTHZ_CONTEXT', pb)
        self.assertIn(b'\xff\x4a\x5a', pb)  # OSON magic


def _bare_conn(ssl, caps):
    conn = object.__new__(OracleConnect)
    conn.ssl = ssl
    conn._server_compile_caps = caps
    conn._end_user_sec_context = None
    conn.seq = 1
    conn.field_version = 24
    return conn


class TestConnectionGuards(unittest.TestCase):
    def setUp(self):
        self.ctx = create_end_user_security_context(
            end_user_identity='T', database_access_token='A'
        )

    def test_requires_tcps(self):
        conn = _bare_conn(ssl=None, caps=_CAPS_WITH_EUC)
        with self.assertRaises(ProgrammingError):
            conn.set_end_user_security_context(self.ctx)

    def test_requires_server_support(self):
        conn = _bare_conn(ssl=object(), caps=_CAPS_WITHOUT)
        with self.assertRaises(NotSupportedError):
            conn.set_end_user_security_context(self.ctx)

    def test_type_check(self):
        conn = _bare_conn(ssl=object(), caps=_CAPS_WITH_EUC)
        with self.assertRaises(TypeError):
            conn.set_end_user_security_context(object())

    def test_set_then_flush_then_clear(self):
        conn = _bare_conn(ssl=object(), caps=_CAPS_WITH_EUC)
        self.assertEqual(conn._flush_end_user_sec_bytes(), b'')  # nothing set
        conn.set_end_user_security_context(self.ctx)
        self.assertEqual(conn._end_user_sec_context, self.ctx.oson_bytes)
        first = conn._flush_end_user_sec_bytes()
        self.assertTrue(first.startswith(bytes([0x11, 205])))
        # Re-rides every call while set (not one-shot like the tracing piggyback).
        second = conn._flush_end_user_sec_bytes()
        self.assertTrue(second.startswith(bytes([0x11, 205])))
        conn.clear_end_user_security_context()
        self.assertEqual(conn._flush_end_user_sec_bytes(), b'')


class TestPackageExport(unittest.TestCase):
    def test_exported(self):
        self.assertIs(
            seerdb.create_end_user_security_context,
            create_end_user_security_context,
        )
        self.assertIn('create_end_user_security_context', seerdb.__all__)
        self.assertIn('EndUserSecurityContext', seerdb.__all__)


if __name__ == '__main__':
    unittest.main()
