# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Drive the server side of a login over a :class:`PacketStream`.

Sequences the 11g handshake and O5LOGON built up across the handshake/auth
modules, so a real client (seerdb, python-oracledb thin, ...) that speaks the
``TTI_PRO`` dialect authenticates against the Mirror:

    CONNECT → ACCEPT → PRO → DTY → OSESSKEY → challenge → AUTH → result

The Mirror holds account passwords in a configured credential map (Oracle
usernames match case-insensitively); a backend-mapped auth API comes later.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns_consts import (
    TNS_CONNECT,
    TNS_DATA,
    TTI_ALL8,
    TTI_FUN,
    TTI_LOGOFF,
)
from seerdb.server.auth import (
    derive_conn_key,
    encode_challenge,
    encode_result,
    make_challenge,
    parse_auth_response,
    parse_osesskey,
)
from seerdb.server.backend import Backend, BackendError
from seerdb.server.framing import PacketStream
from seerdb.server.handshake import (
    encode_accept,
    encode_dty_reply,
    encode_pro_reply,
    parse_connect,
)
from seerdb.server.query import (
    ExecRequest,
    encode_error,
    encode_query_response,
    encode_status,
    parse_exec,
)

logger = logging.getLogger('seerdb.server')

# username → password. Lookups are case-insensitive (Oracle folds unquoted
# identifiers to upper-case).
Credentials = Mapping[str, str]

# A generic backend failure that leaked past the Backend contract still becomes
# a clean ORA error rather than a wire desync (ORA-00600, internal error).
_INTERNAL_ERROR = 600


def _expect(stream: PacketStream, want: int, what: str) -> bytes:
    received = stream.read_packet()
    if received is None:
        raise InterfaceError(f'client closed during login (expected {what})')
    packet_type, body = received
    if packet_type != want:
        raise InterfaceError(
            f'expected {what} (packet type {want}), got type {packet_type}'
        )
    return body


def _password_for(credentials: Credentials, user: str) -> str:
    for name, password in credentials.items():
        if name.upper() == user.upper():
            return password
    raise InterfaceError(f'unknown user: {user!r}')


def handle_login(stream: PacketStream, credentials: Credentials) -> str:
    """Run the server side of the handshake + O5LOGON; return the username.

    Raises :class:`InterfaceError` on a protocol desync, an unknown user, or a
    client that gives up. A wrong password is not rejected here — the client's
    own ``validate()`` fails on the mismatched session key (mutual auth).
    """
    # --- Handshake (§2, §4.1/§4.2) ---
    request = parse_connect(_expect(stream, TNS_CONNECT, 'CONNECT'))
    stream.send_raw(encode_accept(request))
    _expect(stream, TNS_DATA, 'PRO')
    stream.send_raw(encode_pro_reply())
    _expect(stream, TNS_DATA, 'DTY')
    stream.send_raw(encode_dty_reply())

    # --- O5LOGON (§4) ---
    user = parse_osesskey(_expect(stream, TNS_DATA, 'OSESSKEY')).decode('utf-8')
    challenge = make_challenge(_password_for(credentials, user).encode('utf-8'))
    stream.write_packet(TNS_DATA, encode_challenge(challenge))

    _, client_sesskey = parse_auth_response(_expect(stream, TNS_DATA, 'AUTH'))
    conn_key = derive_conn_key(challenge, client_sesskey)
    stream.write_packet(TNS_DATA, encode_result(conn_key))

    logger.info('login OK: %s', user)
    return user


def serve_session(
    stream: PacketStream, credentials: Credentials, backend: Backend
) -> str:
    """Log a client in, then answer its queries until it disconnects.

    After :func:`handle_login`, each OALL8 execute is parsed, handed to
    ``backend.execute``, and answered with a describe + rows response — or, if
    the backend refuses (:class:`BackendError` / :class:`UnsupportedFeature`) or
    fails, with an ORA error that leaves the connection usable. A logoff (or
    EOF) ends the session and returns the authenticated username.
    """
    user = handle_login(stream, credentials)
    while True:
        received = stream.read_packet()
        if received is None:
            return user
        packet_type, body = received
        if packet_type != TNS_DATA or len(body) < 2 or body[0] != TTI_FUN:
            continue
        if body[1] == TTI_ALL8:
            _answer_query(stream, backend, parse_exec(body))
        elif body[1] == TTI_LOGOFF:
            return user


def _answer_query(stream: PacketStream, backend: Backend, request: ExecRequest) -> None:
    # Run the query and reply. Any failure becomes an ORA error on a healthy
    # connection — the Mirror must never desync, so even a backend that leaks a
    # native exception is caught and reported rather than dropping the wire.
    try:
        result = backend.execute(request.sql)
    except BackendError as err:
        logger.info('query refused: %s', err.ora_message)
        response = encode_error(err.ora_code, err.ora_message)
    except Exception as exc:
        logger.warning('backend raised a non-ORA error: %s', exc)
        response = encode_error(_INTERNAL_ERROR, f'ORA-00600: backend error: {exc}')
    else:
        # A query carries result columns (even with zero rows); a DDL/DML
        # statement carries none and gets a bare success status instead of a
        # describe — the client expects one or the other, not both.
        if result.columns:
            response = encode_query_response(result.columns, result.rows)
        else:
            response = encode_status(result.rowcount)
    stream.write_packet(TNS_DATA, response)
