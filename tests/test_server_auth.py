# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side O5LOGON crypto, checked against seerdb's own client crypto.

seerdb.crypto.o5logon / validate are validated against real Oracle, so a
round-trip agreement between them and the server side is a strong conformance
signal without needing a live server.
"""

from __future__ import annotations

from seerdb.crypto import o5logon, validate
from seerdb.server.auth import derive_conn_key, make_challenge, server_proof


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
