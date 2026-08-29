# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""#311: select the O5LOGON key schedule by the AUTH_VFR_DATA verifier-type flag.

A modern server can choose an 11g SHA-1 verifier for an account with no SHA-2
verifier: it sends both salts, so salt-presence alone mis-selects the 256-bit
SHA-2 scheme. The verifier-type flag disambiguates.

Note: the new SHA-1-on-modern derivation is reverse-engineered from a public
reference and could not be validated against a live server (a modern DB won't
produce a SHA-1-only account). These fixtures pin the *selection* and the
deterministic key transforms; the exact bytes await a real capture.
"""

from __future__ import annotations

from hashlib import sha1

from Crypto.Cipher import AES

from seerdb.common.crypto import VFR_11G_SHA1, cat_key, conn_key, o5logon
from seerdb.common.tns import decode_token_rpa, encode_kv, encode_sb4


def test_decode_surfaces_the_verifier_type_flag() -> None:
    data = (
        encode_sb4(2)
        + encode_kv(b'AUTH_SESSKEY', b'AABBCC', 1)
        + encode_kv(b'AUTH_VFR_DATA', b'DDEEFF', VFR_11G_SHA1)
    )
    _kind, _sess, _salt, _derived, _vgen, _sder, vfr = decode_token_rpa(data, ())
    assert vfr == VFR_11G_SHA1


def test_192_with_derived_salt_is_additive() -> None:
    # These cases used to raise; now they produce the modern SHA-1 24-byte key.
    data, salt = b'\x11' * 48, b'\x22' * 16
    combined = cat_key(b'\xaa' * 48, b'\xbb' * 48, salt, 192)
    assert combined == b'\xbb' * 24 + b'\xaa' * 24  # Y[:24] + X[:24]
    key = conn_key(data, salt, 192, 3)
    assert len(key) == 24  # 192-bit


def test_o5logon_picks_192_for_sha1_verifier_on_a_modern_server() -> None:
    # With both salts present, the SHA-1 verifier-type flag selects the 192-bit
    # schedule (24-byte ConnKey); without it, salt-presence picks 256 (32 bytes).
    password, salt, derived = b'pyo123', bytes(16), bytes(16)
    key_sess = sha1(password + salt).digest() + bytes(4)  # 24-byte AES-192 key
    server_session = bytes(40) + bytes([8]) * 8  # 48 bytes, pad2(b'', 8) tail
    sess = AES.new(key_sess, AES.MODE_CBC, bytes(16)).encrypt(server_session)

    *_, conn_192 = o5logon(
        sess, salt, derived, b'PYO', password, None, None, VFR_11G_SHA1
    )
    assert len(conn_192) == 24

    *_, conn_256 = o5logon(sess, salt, derived, b'PYO', password, None, None, None)
    assert len(conn_256) == 32
