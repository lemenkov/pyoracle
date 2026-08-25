# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Token-based authentication — OAuth2 / OCI IAM (#125).

The real Autonomous Database path needs cloud infra to test, so validation is a
round-trip against the Mirror: the client sends the token AUTH, the Mirror
verifies the OCI IAM signature (offline-checkable) and grants the session. The
crypto helpers and the AUTH-message codec are checked directly. The wire format
(AUTH_TOKEN + AUTH_HEADER + AUTH_SIGNATURE, the request header, the RSA-SHA256
signature) is re-expressed from the go-ora driver (MIT).
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import socket
import sys
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import seerdb
from seerdb.common.tns import DictionaryType, encode_dictionary_token_auth
from seerdb.common.token_auth import (
    TokenAuthError,
    normalize_access_token,
    sign_token_header,
    token_auth_header,
    token_subject,
    verify_token_header,
)
from seerdb.server import PacketStream, serve_session
from seerdb.server.auth import is_token_auth, parse_token_auth

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'examples'))
from sqlite_backend import SqliteBackend  # noqa: E402


def _keypair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub


def _jwt(sub: str) -> str:
    def seg(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b'=').decode()

    return f'{seg({"alg": "RS256"})}.{seg({"sub": sub})}.sig'


class TestTokenCrypto(unittest.TestCase):
    def test_header_format(self):
        h = token_auth_header(
            'db.example.com',
            'svc',
            1521,
            now=datetime.datetime(2024, 1, 2, 15, 4, 5, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(
            h,
            'date:Tue, 02 Jan 2024 15:04:05 GMT\n'
            '(request-target):svc\nhost:db.example.com:1521',
        )

    def test_sign_verify_roundtrip(self):
        priv, pub = _keypair()
        header = token_auth_header('h', 's', 1521)
        sig = sign_token_header(header, priv)
        self.assertTrue(verify_token_header(header, sig, pub))

    def test_verify_rejects_tampered_header_and_bad_signature(self):
        priv, pub = _keypair()
        header = token_auth_header('h', 's', 1521)
        sig = sign_token_header(header, priv)
        self.assertFalse(verify_token_header(header + 'x', sig, pub))
        self.assertFalse(verify_token_header(header, 'not-base64-!!', pub))
        _priv2, pub2 = _keypair()
        self.assertFalse(verify_token_header(header, sig, pub2))  # wrong key

    def test_normalize_access_token(self):
        self.assertEqual(normalize_access_token('jwt'), ('jwt', None))
        priv, _ = _keypair()
        tok, key = normalize_access_token(('jwt', priv))
        self.assertEqual((tok, key), ('jwt', priv))
        self.assertEqual(normalize_access_token(lambda: 'cb'), ('cb', None))
        with self.assertRaises(TokenAuthError):
            normalize_access_token(12345)

    def test_token_subject(self):
        self.assertEqual(token_subject(_jwt('scott@corp')), 'scott@corp')
        self.assertIsNone(token_subject('not-a-jwt'))


class TestTokenAuthCodec(unittest.TestCase):
    def _dict(self, **extra) -> dict:
        d = {
            'env': {
                'host': 'h',
                'port': 1521,
                'user': '',
                'password': '',
                'sid': '',
                'service_name': 'XE',
                'role': 0,
                'prelim': 0,
                'app_name': 'seerdb',
                'proxy_user': None,
                'cclass': None,
                'purity': 0,
                'conn_state': 1,
                'timeout': 5000,
                'autocommit': True,
                'fetch': 15,
                'charset': 'utf-8',
            },
            'sdu': 8192,
            'type': DictionaryType.description,
            'req': 'utf-8',
            'seq': 3,
            'field_version': 6,
            'supports_eor': False,
        }
        d.update(extra)
        return d

    def test_oauth2_message_parses(self):
        msg = encode_dictionary_token_auth(self._dict(token='a.b.c'))
        self.assertTrue(is_token_auth(msg))
        token, header, signature = parse_token_auth(msg)
        self.assertEqual(token, b'a.b.c')
        self.assertIsNone(header)
        self.assertIsNone(signature)

    def test_iam_message_carries_header_and_signature(self):
        # A 344-byte base64 signature exercises the chunked (>253) key/value form.
        priv, _ = _keypair()
        header = token_auth_header('h', 'XE', 1521)
        sig = sign_token_header(header, priv)
        self.assertGreater(len(sig), 255)
        msg = encode_dictionary_token_auth(
            self._dict(token='a.b.c', token_header=header, token_signature=sig)
        )
        self.assertTrue(is_token_auth(msg))
        got_token, got_header, got_sig = parse_token_auth(msg)
        self.assertEqual(got_token, b'a.b.c')
        self.assertEqual(got_header, header.encode())
        self.assertEqual(got_sig, sig.encode())

    def test_osesskey_is_not_token_auth(self):
        from seerdb.common.tns import encode_dictionary

        osesskey = encode_dictionary(self._dict(type=DictionaryType.sess))
        self.assertFalse(is_token_auth(osesskey))


def _serve(listen, result, pub):
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(
            PacketStream(conn),
            SqliteBackend(':memory:', credentials={}),
            token_public_key=pub,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def _mirror(pub):
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    result: dict = {}
    server = threading.Thread(target=_serve, args=(listen, result, pub), daemon=True)
    server.start()
    return listen, server, result


class TestTokenAuthRoundTrip(unittest.TestCase):
    def test_iam_signed_login(self):
        priv, pub = _keypair()
        listen, server, result = _mirror(pub)
        conn = seerdb.connect(
            host='127.0.0.1',
            port=listen.getsockname()[1],
            user='',
            password='',
            service_name='XE',
            access_token=(_jwt('iam-user'), priv),
            timeout=5000,
        )
        try:
            cur = conn.cursor()
            cur.execute('create table t (x number)')
            cur.execute('insert into t values (42)')
            cur.execute('select x from t')
            rows = cur.fetchall()
        finally:
            conn.close()
            server.join(timeout=5)
            listen.close()
        self.assertEqual(rows, [(42,)])
        self.assertEqual(result.get('user'), 'iam-user')

    def test_oauth2_bare_token_login(self):
        _priv, pub = _keypair()
        listen, server, result = _mirror(pub)
        conn = seerdb.connect(
            host='127.0.0.1',
            port=listen.getsockname()[1],
            user='',
            password='',
            service_name='XE',
            access_token=_jwt('oauth-user'),
            timeout=5000,
        )
        try:
            cur = conn.cursor()
            cur.execute('create table t (x number)')
            cur.execute('insert into t values (7)')
            cur.execute('select x from t')
            rows = cur.fetchall()
        finally:
            conn.close()
            server.join(timeout=5)
            listen.close()
        self.assertEqual(rows, [(7,)])
        self.assertEqual(result.get('user'), 'oauth-user')

    def test_wrong_key_signature_is_rejected(self):
        priv, _pub = _keypair()
        _priv2, pub2 = _keypair()  # the Mirror trusts a different key
        listen, server, result = _mirror(pub2)
        with self.assertRaises(seerdb.DatabaseError):
            seerdb.connect(
                host='127.0.0.1',
                port=listen.getsockname()[1],
                user='',
                password='',
                service_name='XE',
                access_token=(_jwt('x'), priv),
                timeout=5000,
            )
        server.join(timeout=5)
        listen.close()

    def test_iam_signed_login_async(self):
        priv, pub = _keypair()
        listen, server, result = _mirror(pub)

        async def run():
            conn = await seerdb.connect_async(
                host='127.0.0.1',
                port=listen.getsockname()[1],
                user='',
                password='',
                service_name='XE',
                access_token=(_jwt('async-user'), priv),
                timeout=5000,
            )
            cur = conn.cursor()
            await cur.execute('create table t (x number)')
            await cur.execute('insert into t values (5)')
            await cur.execute('select x from t')
            rows = await cur.fetchall()
            await conn.close()
            return rows

        try:
            rows = asyncio.run(run())
        finally:
            server.join(timeout=5)
            listen.close()
        self.assertEqual(rows, [(5,)])
        self.assertEqual(result.get('user'), 'async-user')


if __name__ == '__main__':
    unittest.main()
