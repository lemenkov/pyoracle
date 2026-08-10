# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""#309: honour the server's AUTH_PBKDF2_VGEN_COUNT / SDER_COUNT.

The 256-bit O5LOGON key schedule uses two PBKDF2 iteration counts the server
advertises in the challenge. Hardcoding the defaults (4096 / 3) breaks auth
against a server configured with non-default counts.
"""

from __future__ import annotations

from seerdb.common.crypto import _clamp_count, conn_key
from seerdb.common.tns import decode_token_rpa, encode_kv, encode_sb4
from seerdb.common.tns_consts import TTI_SESS


def _challenge(*pairs: tuple[bytes, bytes, int]) -> bytes:
    body = encode_sb4(len(pairs))
    for key, val, pad in pairs:
        body += encode_kv(key, val, pad)
    return body


def test_decode_surfaces_pbkdf2_counts() -> None:
    data = _challenge(
        (b'AUTH_SESSKEY', b'AABBCC', 1),
        (b'AUTH_VFR_DATA', b'DDEEFF', 1),
        (b'AUTH_PBKDF2_VGEN_COUNT', b'8192', 0),
        (b'AUTH_PBKDF2_SDER_COUNT', b'5', 0),
    )
    kind, _sess, _salt, _derived, vgen, sder = decode_token_rpa(data, ())
    assert kind == TTI_SESS
    assert (vgen, sder) == (8192, 5)


def test_absent_counts_surface_as_none() -> None:
    data = _challenge(
        (b'AUTH_SESSKEY', b'AABBCC', 1),
        (b'AUTH_VFR_DATA', b'DDEEFF', 1),
    )
    _kind, _sess, _salt, _derived, vgen, sder = decode_token_rpa(data, ())
    assert vgen is None and sder is None


def test_conn_key_honours_sder_count() -> None:
    data, salt = b'\x11' * 24, b'\x22' * 16
    # A non-default SDER count changes the derived 256-bit connection key.
    assert conn_key(data, salt, 256, 3) != conn_key(data, salt, 256, 5)
    # The default is byte-for-byte the historical hardcoded behaviour.
    assert conn_key(data, salt, 256) == conn_key(data, salt, 256, 3)


def test_clamp_count_defaults_and_bounds() -> None:
    assert _clamp_count(None, 4096) == 4096  # absent → default
    assert _clamp_count(2000, 4096) == 4096  # below the floor → default
    assert _clamp_count(8192, 4096) == 8192  # a valid raised count → honoured
    assert _clamp_count(10**9, 4096) == 4096  # absurd → default
