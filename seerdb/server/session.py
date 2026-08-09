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
from collections.abc import Callable, Mapping

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
from seerdb.server.framing import PacketStream
from seerdb.server.handshake import (
    encode_accept,
    encode_dty_reply,
    encode_pro_reply,
    parse_connect,
)
from seerdb.server.query import ColumnMeta, encode_query_response, parse_exec

logger = logging.getLogger('seerdb.server')

# username → password. Lookups are case-insensitive (Oracle folds unquoted
# identifiers to upper-case).
Credentials = Mapping[str, str]

# A backend answers a SQL string with its result columns and rows. This is the
# seam a PostgreSQL-backed demo implements; the DUAL milestone uses a trivial one.
Backend = Callable[[str], 'tuple[list[ColumnMeta], list[tuple]]']


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
    ``backend`` for its columns and rows, and answered with a full describe +
    rows + end-of-fetch response. A logoff (or EOF) ends the session and
    returns the authenticated username.
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
            request = parse_exec(body)
            columns, rows = backend(request.sql)
            stream.write_packet(TNS_DATA, encode_query_response(columns, rows))
        elif body[1] == TTI_LOGOFF:
            return user
