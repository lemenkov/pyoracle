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


# A live sqlplus 11.2 OCI AUTH, captured in reply to a *seeded* Mirror challenge
# (make_challenge(b'pyo123', salt=bytes(10), server_session=bytes(48))) so the
# whole crypto round-trip can be replayed and verified offline (#265). Carries
# the client's 48-byte AUTH_SESSKEY and its 32-byte AUTH_PASSWORD proof, both
# DALC-chunked uppercase-hex.
_OCI_AUTH_SEEDED = bytes.fromhex(
    '037303feffffffffffffff0900000001010000feffffffffffffff1200000000000000'
    'fefffffffffffffffeffffffffffffff0370796f240000000c415554485f534553534b'
    '455920010000fe40433044343734333430333531413144314237453646323138443537'
    '3734353246304441464139333041324232454636453146374538334446363141413434'
    '3436204237363142443545303830443336373239423138393336393036313332463430'
    '0001000000270000000d415554485f50415353574f5244c00000004034463144464434'
    '4436373242383342354233354131453833363131434246344342384243344330313239'
    '4235313735343935383134413131333344324636463500000000180000000841555448'
    '5f5254540c000000043232373300000000270000000d415554485f434c4e545f4d454d'
    '0c000000043430393600000000270000000d415554485f5445524d494e414c00000000'
    '000000002d0000000f415554485f50524f4752414d5f4e4d600000002073716c706c75'
    '73403735313036633766333964622028544e532056312d56332900000000240000000c'
    '415554485f4d414348494e45240000000c373531303663376633396462000000001800'
    '000008415554485f5049440c0000000433323630000000001800000008415554485f53'
    '494412000000066f7261636c6500000000420000001653455353494f4e5f434c49454e'
    '545f4348415253455403000000013100000000450000001753455353494f4e5f434c49'
    '454e545f4c49425f54595045030000000131000000004e0000001a53455353494f4e5f'
    '434c49454e545f4452495645525f4e414d451b0000000953514c2a504c555320000000'
    '00420000001653455353494f4e5f434c49454e545f56455253494f4e1b000000093138'
    '3636343730343000000000420000001653455353494f4e5f434c49454e545f4c4f4241'
    '545452030000000131000000001800000008415554485f41434c0c0000000438303030'
    '000000003600000012415554485f414c5445525f53455353494f4e6f00000025414c54'
    '45522053455353494f4e205345542054494d455f5a4f4e453d272b30303a3030270001'
    '0000004500000017415554485f4c4f474943414c5f53455353494f4e5f494460000000'
    '2035384238464533453933303344453938453036304138433043303030304342430000'
    '00003000000010415554485f4641494c4f5645525f49440000000000000000'
)


def test_parse_auth_response_oci_recovers_the_secrets() -> None:
    from seerdb.server.auth import parse_auth_response_oci

    user, sesskey, password = parse_auth_response_oci(_OCI_AUTH_SEEDED)
    assert user == b'pyo'
    assert len(sesskey) == 48  # client AUTH_SESSKEY, 96 hex on the wire
    assert len(password) == 32  # AUTH_PASSWORD proof, 64 hex on the wire


def test_server_proof_oci_is_the_48_byte_deadbeef_form() -> None:
    from seerdb.server.auth import server_proof_oci

    conn = bytes(24)  # any 192-bit ConnKey
    proof = server_proof_oci(conn, nonce=bytes(16))
    assert len(proof) == 48  # nonce(16) + SERVER_TO_CLIENT(16) + PKCS7 pad(16)
    assert validate(proof, conn)  # decrypts to contain the SERVER_TO_CLIENT marker
    with pytest.raises(InterfaceError):
        server_proof_oci(conn, nonce=bytes(8))  # wrong nonce size


def test_encode_result_oci_validates_against_the_client() -> None:
    # The result the Mirror sends after verifying the OCI AUTH: reconstruct the
    # ConnKey from the seeded challenge + the live AUTH, encode the result, and
    # confirm the substituted AUTH_SVR_RESPONSE validates (#265).
    from binascii import unhexlify

    from seerdb.server.auth import (
        derive_conn_key,
        encode_result_oci,
        parse_auth_response_oci,
    )

    challenge = make_challenge(b'pyo123', salt=bytes(10), server_session=bytes(48))
    _user, sesskey, _password = parse_auth_response_oci(_OCI_AUTH_SEEDED)
    conn = derive_conn_key(challenge, sesskey)

    packet = encode_result_oci(conn, nonce=bytes(16))
    assert len(packet) == 1762  # fixed-size proof keeps the template length
    i = packet.find(b'AUTH_SVR_RESPONSE') + len(b'AUTH_SVR_RESPONSE') + 5
    proof = unhexlify(packet[i : i + 96])
    # if the write offset and the value framing disagreed, this proof would be
    # the template's stale one and fail against the reconstructed ConnKey.
    assert validate(proof, conn)


def test_full_oci_auth_verifies_against_live_sqlplus() -> None:
    # The OCI counterpart of the thin round-trip below, but the AUTH is REAL
    # sqlplus 11.2 bytes (not seerdb's own client encoder). Reconstruct the exact
    # seeded challenge sqlplus answered, parse its AUTH, and drive the full mutual
    # auth: the ConnKey derives, the right password verifies (a wrong one does
    # not), and our server proof validates. End-to-end conformance, offline (#265).
    from seerdb.server.auth import derive_conn_key, parse_auth_response_oci

    challenge = make_challenge(b'pyo123', salt=bytes(10), server_session=bytes(48))
    user, sesskey, password = parse_auth_response_oci(_OCI_AUTH_SEEDED)
    assert user == b'pyo'
    server_conn = derive_conn_key(challenge, sesskey)
    assert verify_password(server_conn, password, b'pyo123')
    assert not verify_password(server_conn, password, b'wrongpass')
    assert validate(server_proof(server_conn), server_conn)


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


def test_parse_changepassword_and_decrypt_roundtrip() -> None:
    # A changepassword TTI_AUTH round-trips: the server parser recovers the user
    # and the two AES ciphertexts, and decrypt_password (the inverse of the
    # client's encrypt_password) recovers the plaintext passwords under the
    # login ConnKey (#21/#486).
    from seerdb.common.crypto import decrypt_password
    from seerdb.common.tns import encode_dictionary_chgpwd
    from seerdb.server.auth import parse_changepassword

    conn_key = bytes(range(24))  # a 24-byte 11g session ConnKey
    msg = encode_dictionary_chgpwd(
        {
            'seq': 1,
            'field_version': 6,
            'env': {'user': 'PYO'},
            'auth': {
                'conn_key': conn_key,
                'old_password': 'pyo123',
                'new_password': 'pyo123_chg9',
            },
        }
    )
    user, old_cipher, new_cipher = parse_changepassword(msg)
    assert user == b'PYO'
    assert decrypt_password(conn_key, old_cipher) == b'pyo123'
    assert decrypt_password(conn_key, new_cipher) == b'pyo123_chg9'
