# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side O5LOGON crypto, checked against seerdb's own client crypto.

seerdb.common.crypto.o5logon / validate are validated against real Oracle, so a
round-trip agreement between them and the server side is a strong conformance
signal without needing a live server.
"""

from __future__ import annotations

from binascii import unhexlify

import pytest

from seerdb.common.crypto import o5logon, validate
from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import (
    decode_token_rpa,
    encode_dictionary_auth,
    encode_dictionary_sess,
)
from seerdb.common.tns_consts import TTI_AUTH, TTI_SESS
from seerdb.server.auth import (
    derive_conn_key,
    encode_challenge,
    encode_result,
    make_challenge,
    parse_auth_response,
    parse_osesskey,
    server_proof,
    verify_password,
)


def _client_login(challenge, user: bytes, password: bytes):
    # Run seerdb's client O5LOGON against our challenge; returns the client's
    # AUTH_SESSKEY response and the ConnKey it derived.
    auth_pass, auth_sess, _speedy, _ind, conn = o5logon(
        challenge.auth_sesskey, challenge.salt, None, user, password
    )
    return auth_sess, auth_pass, conn


def test_both_sides_derive_the_same_session_key() -> None:
    password = b'pyo123'
    challenge = make_challenge(password)
    client_auth_sess, _pass, client_conn = _client_login(challenge, b'PYO', password)
    server_conn = derive_conn_key(challenge, client_auth_sess)
    # The crux: server and client independently arrive at the same ConnKey.
    assert server_conn == client_conn


def test_client_accepts_the_server_proof() -> None:
    password = b'pyo123'
    challenge = make_challenge(password)
    client_auth_sess, _pass, client_conn = _client_login(challenge, b'PYO', password)
    server_conn = derive_conn_key(challenge, client_auth_sess)
    # The client's validate() must accept our AUTH_SVR_RESPONSE — mutual auth.
    assert validate(server_proof(server_conn), client_conn)


def test_wrong_password_breaks_the_agreement() -> None:
    # A client that typed a different password derives a different ConnKey, so
    # mutual auth fails — the server proof is rejected.
    challenge = make_challenge(b'pyo123')
    client_auth_sess, _pass, client_conn = _client_login(challenge, b'PYO', b'wrongpw')
    server_conn = derive_conn_key(challenge, client_auth_sess)
    assert server_conn != client_conn
    assert not validate(server_proof(server_conn), client_conn)


def test_challenge_is_deterministic_when_seeded() -> None:
    a = make_challenge(b'pyo123', salt=bytes(16), server_session=bytes(48))
    b = make_challenge(b'pyo123', salt=bytes(16), server_session=bytes(48))
    assert a == b


# --- RPA wire layer ---


def test_encode_challenge_decodes_as_a_sess_challenge() -> None:
    challenge = make_challenge(b'pyo123')
    payload = encode_challenge(challenge)
    kind, sesskey, salt, derived, _vgen, _sder, _vfr = decode_token_rpa(payload[1:], ())
    assert kind == TTI_SESS
    assert unhexlify(sesskey) == challenge.auth_sesskey
    assert unhexlify(salt) == challenge.salt


def test_encode_result_decodes_as_an_auth_result() -> None:
    payload = encode_result(bytes(24), session_id=59)
    kind, resp, version, session_id = decode_token_rpa(payload[1:], ())
    assert kind == TTI_AUTH
    assert version == 186647040
    assert session_id == b'59'


def test_parse_osesskey_recovers_the_username() -> None:
    request = encode_dictionary_sess(
        {'seq': 1, 'field_version': 6, 'env': {'user': 'PYO'}}
    )
    assert parse_osesskey(request) == b'PYO'


def test_parse_osesskey_oci_recovers_the_username() -> None:
    # sqlplus / thick-OCI (deadbeef dialect) OSESSKEY payloads captured from live
    # sqlplus 11.2 — two username lengths pin the fixed-offset layout (#265).
    from seerdb.server.auth import parse_osesskey_oci

    pyo = bytes.fromhex(
        '037602feffffffffffffff0900000001000000feffffffffffffff05000000'
        '00000000fefffffffffffffffeffffffffffffff0370796f270000000d4155'
        '54485f5445524d494e414c'
    )
    abcdefgh = bytes.fromhex(
        '037602feffffffffffffff1800000001000000feffffffffffffff05000000'
        '00000000fefffffffffffffffeffffffffffffff08616263646566676827'
        '0000000d415554485f5445524d494e414c'
    )
    assert parse_osesskey_oci(pyo) == b'pyo'
    assert parse_osesskey_oci(abcdefgh) == b'abcdefgh'


def test_encode_challenge_oci_substitutes_the_crypto_values() -> None:
    # The OCI challenge is the captured 390-byte template with AUTH_SESSKEY and
    # the salt substituted in place (#265). Validated live: sqlplus accepts it
    # and sends AUTH.
    import secrets

    from seerdb.server.auth import encode_challenge_oci, make_challenge

    challenge = make_challenge(b'pyo123', salt=secrets.token_bytes(10))
    packet = encode_challenge_oci(challenge)
    assert len(packet) == 390  # fixed-size values keep the packet length
    # the fresh crypto values are present where the template had the captured ones
    i_sk = packet.index(b'AUTH_SESSKEY') + len(b'AUTH_SESSKEY') + 5
    i_vfr = packet.index(b'AUTH_VFR_DATA') + len(b'AUTH_VFR_DATA') + 5
    assert packet[i_sk : i_sk + 96] == challenge.auth_sesskey.hex().upper().encode()
    assert packet[i_vfr : i_vfr + 20] == challenge.salt.hex().upper().encode()


def test_encode_challenge_oci_rejects_wrong_sizes() -> None:
    from seerdb.server.auth import encode_challenge_oci, make_challenge

    # A 16-byte salt (the thin default) doesn't fit the OCI template's 20-hex slot.
    with pytest.raises(InterfaceError):
        encode_challenge_oci(make_challenge(b'pyo123'))


def test_full_auth_roundtrip_through_seerdb_client_encoders() -> None:
    # End-to-end: our challenge -> seerdb's client AUTH message -> our parse +
    # ConnKey derivation -> our result -> the client's validate() accepts it.
    password = 'pyo123'
    challenge = make_challenge(password.encode())
    request, client_conn = encode_dictionary_auth(
        {
            'seq': 1,
            'field_version': 6,
            'auth': {
                'sess': challenge.auth_sesskey,
                'salt': challenge.salt,
                'derived_salt': None,
            },
            'env': {'user': 'PYO', 'password': password},
        }
    )
    user, client_auth_sesskey, auth_password = parse_auth_response(request)
    assert user == b'PYO'
    server_conn = derive_conn_key(challenge, client_auth_sesskey)
    assert server_conn == client_conn

    # The server verifies the client's AUTH_PASSWORD proof against the account
    # secret: the right password passes, a wrong one is rejected.
    assert verify_password(server_conn, auth_password, b'pyo123')
    assert not verify_password(server_conn, auth_password, b'wrongpass')

    # The result the server sends back, validated by the client's own check.
    _, resp, _, _ = decode_token_rpa(encode_result(server_conn)[1:], ())
    assert validate(unhexlify(resp), client_conn)
