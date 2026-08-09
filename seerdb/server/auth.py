# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side O5LOGON (11g, 192-bit salted path).

The encode side of the client crypto in :mod:`seerdb.crypto` (``o5logon`` /
``validate``). O5LOGON is *mutually* authenticated, so the server must hold the
account password — a configured credential for now; a backend-mapped auth API
comes later. The flow the server drives:

1. **Challenge** (:func:`make_challenge`): pick a salt and a server session key,
   derive ``key_sess = SHA1(password + salt) + 0x00000000``, and send
   ``AUTH_SESSKEY = AES-CBC(server_session, key_sess)`` with the salt
   (``AUTH_VFR_DATA``).
2. The client derives the same ``key_sess`` from the password it typed, recovers
   the server session key, mints its own session key, and returns it (its
   ``AUTH_SESSKEY``) plus ``AUTH_PASSWORD``.
3. **Derive** (:func:`derive_conn_key`): recover the client session key and
   combine both halves into the session ``ConnKey`` — identical to the one the
   client computed.
4. **Prove** (:func:`server_proof`): return ``AES-CBC(SERVER_TO_CLIENT, ConnKey)``
   — the token the client's ``validate()`` decrypts and checks, closing the
   mutual authentication.

This module is the crypto core; the RPA wire encode/parse that carries these
values is layered on top separately.
"""

from __future__ import annotations

from binascii import unhexlify
from dataclasses import dataclass
from hashlib import sha1
from secrets import token_bytes

from Crypto.Cipher import AES

from seerdb.crypto import cat_key, conn_key, pad2
from seerdb.exceptions import InterfaceError
from seerdb.tns import decode_kv, decode_ub4, encode_kv, encode_sb4
from seerdb.tns_consts import TTI_AUTH, TTI_FUN, TTI_RPA, TTI_SESS

# O5LOGON uses AES-CBC with an all-zero IV throughout.
_IV = bytes(16)
# 11g accounts carry the SHA1 verifier → the 192-bit AES key schedule.
_BITS_11G = 192
# The plaintext the server encrypts under ConnKey to prove it holds the session
# key. Exactly one AES block; the client's validate() looks for this substring.
_SERVER_PROOF = b'SERVER_TO_CLIENT'
# A server session key is 40 random bytes + an 8-byte pad2 tail, so the client
# recognises it and mints a matching 48-byte session key (see crypto.o5logon0).
_SERVER_SESSION_LEN = 40
# Packed server version returned in the auth result (AUTH_VERSION_NO), from a
# real XE 11.2 auth result: 186647040 = 11.2.0.x. On the wire all these values
# (session key, salt, proof) are uppercase-hex ASCII.
_SERVER_VERSION_NO = 186647040


def _key_sess(password: bytes, salt: bytes) -> bytes:
    # 11g 192-bit: SHA1(password + salt) (20 bytes) + 4 zero bytes = 24-byte
    # AES-192 key. Mirrors the salted branch of crypto.o5logon.
    return sha1(password + salt).digest() + bytes(4)


@dataclass(frozen=True)
class Challenge:
    """The per-connection O5LOGON challenge state, held until the response."""

    salt: bytes
    server_session: bytes
    key_sess: bytes
    auth_sesskey: bytes  # the AUTH_SESSKEY value put on the wire


def make_challenge(
    password: bytes,
    *,
    salt: bytes | None = None,
    server_session: bytes | None = None,
) -> Challenge:
    """Build the O5LOGON challenge for an account whose password is known.

    ``salt`` / ``server_session`` are injectable for deterministic tests; both
    default to fresh random values.
    """
    if salt is None:
        salt = token_bytes(16)
    if server_session is None:
        server_session = token_bytes(_SERVER_SESSION_LEN) + pad2(b'', 8)
    key_sess = _key_sess(password, salt)
    auth_sesskey = AES.new(key_sess, AES.MODE_CBC, _IV).encrypt(server_session)
    return Challenge(salt, server_session, key_sess, auth_sesskey)


def derive_conn_key(challenge: Challenge, client_auth_sesskey: bytes) -> bytes:
    """Derive the session ConnKey from the client's AUTH_SESSKEY response.

    Recovers the client session key and combines it with the server's — the
    result equals the ConnKey the client derived.
    """
    client_session = AES.new(challenge.key_sess, AES.MODE_CBC, _IV).decrypt(
        client_auth_sesskey
    )
    combined = cat_key(challenge.server_session, client_session, None, _BITS_11G)
    return conn_key(combined, None, _BITS_11G)


def server_proof(session_key: bytes) -> bytes:
    """The AUTH_SVR_RESPONSE value: SERVER_TO_CLIENT encrypted under ConnKey."""
    return AES.new(session_key, AES.MODE_CBC, _IV).encrypt(_SERVER_PROOF)


def _hexval(raw: bytes) -> bytes:
    # The wire form for AUTH_SESSKEY / AUTH_VFR_DATA / AUTH_SVR_RESPONSE: an
    # uppercase-hex ASCII string (the client bytes.fromhex()es it back).
    return raw.hex().upper().encode('ascii')


def encode_challenge(challenge: Challenge) -> bytes:
    """The auth-challenge RPA payload — AUTH_SESSKEY + the salt (AUTH_VFR_DATA).

    Returns the TTC payload starting at the TTI_RPA token, ready for
    ``PacketStream.write_packet(TNS_DATA, …)``. Decodes back through the
    client's ``decode_token_rpa`` as a ``TTI_SESS`` challenge.
    """
    return (
        bytes([TTI_RPA])
        + encode_sb4(2)
        + encode_kv(b'AUTH_SESSKEY', _hexval(challenge.auth_sesskey), 1)
        + encode_kv(b'AUTH_VFR_DATA', _hexval(challenge.salt), 1)
    )


def encode_result(
    session_key: bytes,
    *,
    session_id: int = 0,
    version_no: int = _SERVER_VERSION_NO,
) -> bytes:
    """The auth-result RPA payload — the server proof, version, and session id.

    Decodes back through ``decode_token_rpa`` as a ``TTI_AUTH`` result whose
    ``AUTH_SVR_RESPONSE`` the client's ``validate()`` accepts.
    """
    return (
        bytes([TTI_RPA])
        + encode_sb4(3)
        + encode_kv(b'AUTH_SVR_RESPONSE', _hexval(server_proof(session_key)), 1)
        + encode_kv(b'AUTH_VERSION_NO', str(version_no).encode('ascii'), 1)
        + encode_kv(b'AUTH_SESSION_ID', str(session_id).encode('ascii'), 1)
    )


def _parse_fun_auth(payload: bytes) -> tuple[int, bytes, dict[bytes, bytes | None]]:
    # Parse a client TTI_FUN auth message (OSESSKEY or AUTH), 11g/fv<12.1 shape:
    #   TTI_FUN, subtype, seq, 0x01, sb4(userlen), sb4(mode), 0x01,
    #   sb4(numpairs), 0x01, 0x01, user[userlen], <numpairs key-value pairs>
    if len(payload) < 4 or payload[0] != TTI_FUN:
        raise InterfaceError('not a TTI_FUN message')
    subtype = payload[1]
    rest = payload[4:]  # skip TTI_FUN, subtype, seq, 0x01
    userlen, rest = decode_ub4(rest)
    _mode, rest = decode_ub4(rest)
    rest = rest[1:]  # skip the 0x01 has-more byte
    numpairs, rest = decode_ub4(rest)
    rest = rest[2:]  # skip the 0x01 0x01 pointer pair
    user = rest[:userlen]
    kvs, _ = decode_kv(rest[userlen:], numpairs, [])
    return subtype, user, dict(kvs)


def parse_osesskey(payload: bytes) -> bytes:
    """Return the username from the client's OSESSKEY (phase-one) request."""
    subtype, user, _ = _parse_fun_auth(payload)
    if subtype != TTI_SESS:
        raise InterfaceError(f'expected OSESSKEY, got subtype {subtype}')
    return user


def parse_auth_response(payload: bytes) -> tuple[bytes, bytes]:
    """Return ``(username, client AUTH_SESSKEY bytes)`` from the phase-two AUTH.

    The client's session key is what the server needs to derive the shared
    ConnKey; AUTH_PASSWORD is ignored (the ConnKey agreement is the check).
    """
    subtype, user, kvs = _parse_fun_auth(payload)
    if subtype != TTI_AUTH:
        raise InterfaceError(f'expected AUTH, got subtype {subtype}')
    sesskey = kvs.get(b'AUTH_SESSKEY')
    if sesskey is None:
        raise InterfaceError('AUTH response missing AUTH_SESSKEY')
    return user, unhexlify(sesskey)
