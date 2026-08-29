# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side O5LOGON (11g, 192-bit salted path).

The encode side of the client crypto in :mod:`seerdb.common.crypto` (``o5logon`` /
``validate``). O5LOGON is *mutually* authenticated, so the server must hold the
account password — supplied by ``backend.authenticate(user)`` (auth lives with
the backend). The flow the server drives:

1. **Challenge** (:func:`make_challenge`): pick a salt and a server session key,
   derive ``key_sess = SHA1(password + salt) + 0x00000000``, and send
   ``AUTH_SESSKEY = AES-CBC(server_session, key_sess)`` with the salt
   (``AUTH_VFR_DATA``).
2. The client derives the same ``key_sess`` from the password it typed, recovers
   the server session key, mints its own session key, and returns it (its
   ``AUTH_SESSKEY``) plus ``AUTH_PASSWORD``.
3. **Derive** (:func:`derive_conn_key`): recover the client session key and
   combine both halves into the session ``ConnKey`` — identical to the one the
   client computed *only if the passwords match*.
4. **Verify** (:func:`verify_password`): decrypt the client's ``AUTH_PASSWORD``
   under the ConnKey and confirm it proves the account password — the server
   half of the mutual auth, so a wrong password is rejected (ORA-01017) rather
   than served.
5. **Prove** (:func:`server_proof`): return ``AES-CBC(SERVER_TO_CLIENT, ConnKey)``
   — the token the client's ``validate()`` decrypts and checks, closing the
   mutual authentication.

This module is the crypto core; the RPA wire encode/parse that carries these
values is layered on top separately.
"""

from __future__ import annotations

import struct
from binascii import unhexlify
from dataclasses import dataclass
from hashlib import sha1
from secrets import token_bytes

from Crypto.Cipher import AES

from seerdb.common import oci
from seerdb.common.crypto import VFR_11G_SHA1, cat_key, conn_key, pad2
from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    decode_dalc,
    decode_kv,
    decode_ub4,
    encode_kv,
    encode_sb4,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_12_2,
    TTI_AUTH,
    TTI_FUN,
    TTI_RPA,
    TTI_SESS,
)

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


# The OCI dialect's AUTH_SVR_RESPONSE is 48 bytes, not the thin 16: the real 11g
# listener encrypts a 16-byte nonce, the SERVER_TO_CLIENT marker, and a full
# PKCS7 pad block (verified byte-exact against a live capture). The client finds
# the marker substring after decrypting, so the nonce is not checked.
_PROOF_NONCE_LEN = 16
_PKCS7_FULL_BLOCK = bytes([16]) * 16


def server_proof_oci(session_key: bytes, *, nonce: bytes | None = None) -> bytes:
    """The 48-byte OCI ``AUTH_SVR_RESPONSE`` (deadbeef dialect, #265).

    ``AES-CBC(nonce16 + SERVER_TO_CLIENT + PKCS7pad, ConnKey)`` — the classic
    O5LOGON server response the real 11g listener sends. ``nonce`` is injectable
    for deterministic tests; it defaults to a fresh random value and the client
    does not check it.
    """
    if nonce is None:
        nonce = token_bytes(_PROOF_NONCE_LEN)
    if len(nonce) != _PROOF_NONCE_LEN:
        raise InterfaceError(f'proof nonce must be {_PROOF_NONCE_LEN} bytes')
    plain = nonce + _SERVER_PROOF + _PKCS7_FULL_BLOCK
    return AES.new(session_key, AES.MODE_CBC, _IV).encrypt(plain)


def verify_password(
    session_key: bytes, auth_password: bytes | None, password: bytes
) -> bool:
    """True if the client's ``AUTH_PASSWORD`` proves it holds ``password``.

    ``AUTH_PASSWORD = AES-CBC(pad1(password), ConnKey)``, where ``pad1`` prepends
    a fixed 16-byte block the server discards. Decrypting with the server's
    ConnKey and comparing the payload past that block to ``pad2(password)``
    confirms both sides derived the same ConnKey — i.e. the client used the right
    password. A wrong password yields a different ConnKey, so the payload is
    garbage and the check fails. This is the server half of the mutual auth: it
    lets the Mirror *reject* a bad login (ORA-01017) rather than relying on the
    client to notice the server proof it can't validate.
    """
    if not auth_password or len(auth_password) % 16 != 0:
        return False
    plain = AES.new(session_key, AES.MODE_CBC, _IV).decrypt(auth_password)
    remainder = 16 - (len(password) % 16)
    return plain[16:] == pad2(password, remainder)


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


# --- Generating the sqlplus / thick-OCI (deadbeef dialect) O5LOGON packets ---
#
# The challenge and result are lists of AUTH_* key-value pairs in the OCI dialect
# (the read side is _oci_auth_value) behind the 10-byte TNS DATA header, followed
# by a fixed capability/status trailer. Everything except the crypto values and
# the salt is the Mirror's constant pinned-11g identity, captured once from a live
# XE 11.2 server. encode_kv_oci computes the framing so the packets are generated
# rather than replayed verbatim; the byte-for-byte match to the original captures
# is pinned by tests/test_oci_auth_generation.py (#265).

# The 11g SHA-1 password verifier type (crypto.VFR_11G_SHA1) is carried as
# AUTH_VFR_DATA's trailing flag.

# The Mirror's fixed 11g identity, from the live XE 11.2 capture. The
# session-identity fields (AUTH_SESSION_ID / _SERIAL_NUM / _SERVER_PID) are kept
# as captured — the client does not cryptographically check them. AUTH_SVR_RESPONSE
# is the one per-login value and is appended by encode_result_oci.
_RESULT_PARAMS: tuple[tuple[bytes, bytes], ...] = (
    (b'AUTH_VERSION_STRING', b'- 64bit Production'),
    (b'AUTH_VERSION_SQL', b'22'),
    (b'AUTH_XACTION_TRAITS', b'3'),
    (b'AUTH_VERSION_NO', str(_SERVER_VERSION_NO).encode('ascii')),
    (b'AUTH_VERSION_STATUS', b'0'),
    (b'AUTH_CAPABILITY_TABLE', b''),
    (b'AUTH_DBNAME', b'XE'),
    (b'AUTH_DB_MOUNT_ID\x00', b'3121942702'),
    (b'AUTH_DB_ID\x00', b'3115068141'),
    (b'AUTH_USER_ID', b'48'),
    (b'AUTH_SESSION_ID', b'59'),
    (b'AUTH_SERIAL_NUM', b'2021'),
    (b'AUTH_INSTANCE_NO', b'1'),
    (b'AUTH_FAILOVER_ID', b'1'),
    (b'AUTH_SERVER_PID', b'3327'),
    (b'AUTH_SC_SERVER_HOST', b'75106c7f39db'),
    (b'AUTH_SC_DBUNIQUE_NAME', b'XE'),
    (b'AUTH_SC_INSTANCE_NAME', b'XE'),
    (b'AUTH_SC_SERVICE_NAME', b'XE'),
    (b'AUTH_SC_INSTANCE_ID', b'1'),
    (b'AUTH_SC_INSTANCE_START_TIME', b'2026-08-09 16:48:44.000000000 +00:00'),
    (b'AUTH_SC_DB_DOMAIN', b''),
    (b'AUTH_SC_SVC_FLAGS', b'8'),
    (b'AUTH_INSTANCENAME', b'XE'),
    (b'AUTH_NLS_LXLAN\x00', b'AMERICAN'),
    (b'AUTH_NLS_LXCTERRITORY\x00', b'AMERICA'),
    (b'AUTH_NLS_LXCCURRENCY\x00', b'$'),
    (b'AUTH_NLS_LXCISOCURR\x00', b'AMERICA'),
    (b'AUTH_NLS_LXCNUMERICS\x00', b'.,'),
    (b'AUTH_NLS_LXCDATEFM\x00', b'DD-MON-RR'),
    (b'AUTH_NLS_LXCDATELANG\x00', b'AMERICAN'),
    (b'AUTH_NLS_LXCSORT\x00', b'BINARY'),
    (b'AUTH_NLS_LXCCALENDAR\x00', b'GREGORIAN'),
    (b'AUTH_NLS_LXCUNIONCUR\x00', b'$'),
    (b'AUTH_NLS_LXCTIMEFM\x00', b'HH.MI.SSXFF AM'),
    (b'AUTH_NLS_LXCSTMPFM\x00', b'DD-MON-RR HH.MI.SSXFF AM'),
    (b'AUTH_NLS_LXCTTZNFM\x00', b'HH.MI.SSXFF AM TZR'),
    (b'AUTH_NLS_LXCSTZNFM\x00', b'DD-MON-RR HH.MI.SSXFF AM TZR'),
)
_AUTH_GLOBALLY_UNIQUE_DBID = b'2C55FD5F1FE1101DA2455B7A62312B1D'

# The 136-byte capability/status block trailing the key-value list (an opaque
# OER-shaped status); challenge and result differ only in one subtype byte.
_CHALLENGE_TRAILER = bytes.fromhex(
    '04010000000200010000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000002000000000000360100000000000000000000'
    '0000000020f6310a0000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000'
)
_RESULT_TRAILER = bytes.fromhex(
    '04010000000300010000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000003000000000000360100000000000000000000'
    '0000000020f6310a0000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000'
)


def encode_kv_oci(key: bytes, val: bytes, flags: int = 0) -> bytes:
    """One OCI-dialect (deadbeef) key-value pair: a little-endian ub4 declared
    length + short DALC for the key and the value (an empty value is the ub4
    length 0 with no data byte), then a ub4 flags field (the verifier type for
    AUTH_VFR_DATA, else 0). The write inverse of :func:`_oci_auth_value`."""

    def field(data: bytes) -> bytes:
        if not data:
            return struct.pack('<I', 0)
        return struct.pack('<I', len(data)) + bytes([len(data)]) + data

    return field(key) + field(val) + struct.pack('<I', flags)


def _oci_auth_packet(pairs: list[tuple[bytes, bytes, int]], trailer: bytes) -> bytes:
    """Assemble a full deadbeef-dialect O5LOGON DATA packet from its key-value
    pairs and trailer: a TTI_RPA marker, the pair count, a zero lead byte, the
    pairs, and the trailer — behind the 10-byte TNS DATA header."""
    payload = bytes([TTI_RPA, len(pairs), 0])
    payload += b''.join(encode_kv_oci(k, v, f) for k, v, f in pairs)
    payload += trailer
    header = struct.pack('>H', len(payload) + 10) + bytes([0, 0, 6, 0, 0, 0, 0, 0])
    return header + payload


def encode_challenge_oci(challenge: Challenge) -> bytes:
    """Build the sqlplus / thick-OCI (deadbeef dialect) O5LOGON challenge (#265).

    Returns the **full TNS_DATA packet** (header included), ready for
    ``PacketStream.send_raw``. Requires an 11g-shaped challenge — a 48-byte
    encrypted server session (96 hex) and a 10-byte salt (20 hex): pass
    ``make_challenge(secret, salt=token_bytes(10))``. Validated against live
    sqlplus 11.2, which accepts it and proceeds to send AUTH.
    """
    sesskey = _hexval(challenge.auth_sesskey)
    salt = _hexval(challenge.salt)
    if len(sesskey) != oci.OCI_SESSKEY_HEXLEN or len(salt) != oci.OCI_SALT_HEXLEN:
        raise InterfaceError(
            'OCI challenge needs a 48-byte server session and a 10-byte salt, '
            f'got {len(challenge.auth_sesskey)}/{len(challenge.salt)} bytes'
        )
    pairs = [
        (b'AUTH_SESSKEY', sesskey, 0),
        (b'AUTH_VFR_DATA', salt, VFR_11G_SHA1),
        (b'AUTH_GLOBALLY_UNIQUE_DBID\x00', _AUTH_GLOBALLY_UNIQUE_DBID, 0),
    ]
    return _oci_auth_packet(pairs, _CHALLENGE_TRAILER)


def encode_result_oci(session_key: bytes, *, nonce: bytes | None = None) -> bytes:
    """Build the sqlplus / thick-OCI (deadbeef dialect) O5LOGON result (#265).

    Returns the **full TNS_DATA packet** (header included), ready for
    ``PacketStream.send_raw``. ``AUTH_SVR_RESPONSE`` (the freshly computed 48-byte
    server proof) is the one per-login value; every other field is the Mirror's
    fixed identity. ``nonce`` is forwarded to :func:`server_proof_oci` for
    deterministic tests.
    """
    proof = _hexval(server_proof_oci(session_key, nonce=nonce))
    pairs = [(k, v, 0) for k, v in _RESULT_PARAMS]
    pairs.append((b'AUTH_SVR_RESPONSE', proof, 0))
    return _oci_auth_packet(pairs, _RESULT_TRAILER)


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


# The classic sqlplus / thick-OCI (deadbeef dialect) OSESSKEY marshals its fixed
# header fields very differently from the thin form: an 8-byte 0xFE indicator
# (0xFFFFFFFFFFFFFFFE little-endian) stands in for thin's 0x01 pointer bytes, and
# lengths are fixed 4-byte little-endian ub4s. The layout up to the username is
# constant (confirmed against live sqlplus 11.2 for usernames of different
# lengths), so the ub1-length-prefixed username sits at a fixed offset (#265):
#   03(TTI_FUN) subtype seq | IND | ub4 ub4 | IND | ub4 ub4 | IND | IND | ub1+user
# The 8-byte indicator (0xFFFFFFFFFFFFFFFE LE) is the shared oci.OCI_INDICATOR.


def _parse_oci_fun_username(payload: bytes, subtype: int, what: str) -> bytes:
    # OSESSKEY and AUTH share the same TTI_FUN prefix in the deadbeef dialect:
    # only the subtype byte and the ub4 field values differ, so the username sits
    # at the same fixed offset in both. Validate every indicator so a
    # differently-shaped message surfaces as an error, not a garbage username.
    if len(payload) < 4 or payload[0] != TTI_FUN:
        raise InterfaceError('not a TTI_FUN message')
    if payload[1] != subtype:
        raise InterfaceError(f'expected {what}, got subtype {payload[1]}')
    # Indicators sit at these offsets; between the 1st/2nd and 3rd/4th come the
    # two ub4 length-field pairs that make up the gaps.
    for expected_ind_off in (3, 19, 35, 43):
        if payload[expected_ind_off : expected_ind_off + 8] != oci.OCI_INDICATOR:
            raise InterfaceError(
                f'OCI {what}: no indicator at offset {expected_ind_off}'
            )
    user_off = 51  # 3 + 8 + (4+4) + 8 + (4+4) + 8 + 8
    userlen = payload[user_off]
    return payload[user_off + 1 : user_off + 1 + userlen]


def parse_osesskey_oci(payload: bytes) -> bytes:
    """Return the username from a sqlplus / thick-OCI OSESSKEY (deadbeef dialect).

    Verified against live sqlplus 11.2 captures (usernames ``pyo`` and
    ``abcdefgh``). Raises :class:`InterfaceError` if the fixed indicator layout
    is not where the OCI OSESSKEY puts it.
    """
    return _parse_oci_fun_username(payload, TTI_SESS, 'OSESSKEY')


def _oci_auth_value(payload: bytes, key: bytes) -> bytes:
    # In the OCI AUTH, each key-value pair is ``<key> <ub4 declared-len> <DALC
    # value>``: a fixed 4-byte little-endian length precedes the DALC-chunked
    # value (0xFE-marked chunks — the same encoding seerdb's client decoder
    # reads). The value is uppercase-hex ASCII, so unhexlify recovers the bytes.
    i = payload.find(key)
    if i < 0:
        raise InterfaceError(f'OCI AUTH: missing {key.decode()}')
    hexval, _ = decode_dalc(payload[i + len(key) + 4 :])
    # decode_dalc reports an empty/null value as []; a real AUTH_SESSKEY /
    # AUTH_PASSWORD is always non-empty hex bytes.
    if not isinstance(hexval, bytes):
        raise InterfaceError(f'OCI AUTH: empty {key.decode()}')
    return unhexlify(hexval)


def parse_auth_response_oci(payload: bytes) -> tuple[bytes, bytes, bytes]:
    """Return ``(username, client AUTH_SESSKEY, AUTH_PASSWORD)`` from the OCI AUTH.

    The sqlplus / thick-OCI (deadbeef dialect) counterpart of
    :func:`parse_auth_response`. The client's session key derives the shared
    ConnKey (:func:`derive_conn_key`); ``AUTH_PASSWORD`` is the password proof
    that :func:`verify_password` checks. Verified against a live sqlplus 11.2
    AUTH: a 48-byte session key and a 32-byte proof.
    """
    user = _parse_oci_fun_username(payload, TTI_AUTH, 'AUTH')
    sesskey = _oci_auth_value(payload, b'AUTH_SESSKEY')
    password = _oci_auth_value(payload, b'AUTH_PASSWORD')
    return user, sesskey, password


def parse_auth_response(payload: bytes) -> tuple[bytes, bytes, bytes | None]:
    """Return ``(username, client AUTH_SESSKEY, AUTH_PASSWORD)`` from the AUTH.

    The client's session key derives the shared ConnKey; ``AUTH_PASSWORD`` (the
    client's password proof, ``None`` if absent) lets the server verify the
    password with :func:`verify_password`.
    """
    subtype, user, kvs = _parse_fun_auth(payload)
    if subtype != TTI_AUTH:
        raise InterfaceError(f'expected AUTH, got subtype {subtype}')
    sesskey = kvs.get(b'AUTH_SESSKEY')
    if sesskey is None:
        raise InterfaceError('AUTH response missing AUTH_SESSKEY')
    password = kvs.get(b'AUTH_PASSWORD')
    auth_password = unhexlify(password) if password else None
    return user, unhexlify(sesskey), auth_password


def parse_changepassword(payload: bytes) -> tuple[bytes, bytes, bytes]:
    """Return ``(username, AUTH_PASSWORD, AUTH_NEWPASSWORD)`` from a changepassword
    TTI_AUTH (#21/#486). Both password fields are the AES-CBC ciphertext (already
    un-hexed) the client encrypted under the login ConnKey — the session decrypts
    them with :func:`~seerdb.common.crypto.decrypt_password`. Unlike login this
    carries no ``AUTH_SESSKEY`` (the session already exists)."""
    subtype, user, kvs = _parse_fun_auth(payload)
    if subtype != TTI_AUTH:
        raise InterfaceError(f'expected AUTH, got subtype {subtype}')
    old_cipher = kvs.get(b'AUTH_PASSWORD')
    new_cipher = kvs.get(b'AUTH_NEWPASSWORD')
    if old_cipher is None or new_cipher is None:
        raise InterfaceError('changepassword missing AUTH_PASSWORD / AUTH_NEWPASSWORD')
    return user, unhexlify(old_cipher), unhexlify(new_cipher)


# Token auth is a modern feature: its long values (the RSA signature, and real
# JWTs) are written in the fv >= 12.2 chunked form (ub4-prefixed chunks). Decode
# them with that field version, not the Mirror's pinned-11g default of 6.
_TOKEN_DECODE_FV = FIELD_VERSION_12_2


def is_token_auth(payload: bytes) -> bool:
    """Whether a post-DTY auth message is a token AUTH (#125) rather than the
    O5LOGON OSESSKEY (which is a ``TTI_SESS`` subtype). A token AUTH is a
    ``TTI_AUTH`` carrying an ``AUTH_TOKEN`` pair, sent in place of OSESSKEY."""
    if len(payload) < 2 or payload[0] != TTI_FUN or payload[1] != TTI_AUTH:
        return False
    _DECODE_FIELD_VERSION.set(_TOKEN_DECODE_FV)
    try:
        _subtype, _user, kvs = _parse_fun_auth(payload)
    except InterfaceError:
        return False
    return b'AUTH_TOKEN' in kvs


def parse_token_auth(payload: bytes) -> tuple[bytes, bytes | None, bytes | None]:
    """Return ``(token, header, signature)`` from a token AUTH (#125).

    ``header`` / ``signature`` are the OCI IAM signed-request pair (both ``None``
    for the OAuth2 bare-token variant).
    """
    _DECODE_FIELD_VERSION.set(_TOKEN_DECODE_FV)
    subtype, _user, kvs = _parse_fun_auth(payload)
    if subtype != TTI_AUTH:
        raise InterfaceError(f'expected token AUTH, got subtype {subtype}')
    token = kvs.get(b'AUTH_TOKEN')
    if token is None:
        raise InterfaceError('token AUTH missing AUTH_TOKEN')
    return token, kvs.get(b'AUTH_HEADER'), kvs.get(b'AUTH_SIGNATURE')


def encode_token_result(
    *, session_id: int = 0, version_no: int = _SERVER_VERSION_NO
) -> bytes:
    """The token-auth result RPA — version + session id, and no server proof
    (token auth has no ConnKey, so there is nothing for the client to validate)."""
    return (
        bytes([TTI_RPA])
        + encode_sb4(2)
        + encode_kv(b'AUTH_VERSION_NO', str(version_no).encode('ascii'), 1)
        + encode_kv(b'AUTH_SESSION_ID', str(session_id).encode('ascii'), 1)
    )
