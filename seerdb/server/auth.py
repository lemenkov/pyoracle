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

from dataclasses import dataclass
from hashlib import sha1
from secrets import token_bytes

from Crypto.Cipher import AES

from seerdb.crypto import cat_key, conn_key, pad2

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
