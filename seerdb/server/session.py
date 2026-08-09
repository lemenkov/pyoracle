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
from seerdb.common.tns import decode_ub4
from seerdb.common.tns_consts import (
    TNS_CONNECT,
    TNS_DATA,
    TTI_ALL8,
    TTI_COMMIT,
    TTI_FUN,
    TTI_LOGOFF,
    TTI_MSG_TYPE_PIGGYBACK,
    TTI_OCCA,
    TTI_ROLLBACK,
)
from seerdb.server.auth import (
    derive_conn_key,
    encode_challenge,
    encode_result,
    make_challenge,
    parse_auth_response,
    parse_osesskey,
)
from seerdb.server.backend import Backend, BackendError, Result
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
        if packet_type != TNS_DATA:
            continue
        body = _skip_piggybacks(body)  # e.g. CLOSE_CURSORS after a drained fetch
        if len(body) < 2 or body[0] != TTI_FUN:
            continue
        if body[1] == TTI_ALL8:
            _answer_query(stream, backend, parse_exec(body))
        elif body[1] == TTI_COMMIT:
            _answer_txn(stream, backend, commit=True)
        elif body[1] == TTI_ROLLBACK:
            _answer_txn(stream, backend, commit=False)
        elif body[1] == TTI_LOGOFF:
            return user


def _skip_piggybacks(body: bytes) -> bytes:
    # A call can be preceded by piggybacks — most commonly CLOSE_CURSORS, which
    # a client sends to free the cursors it drained on the previous fetch. The
    # Mirror keeps no cursor/session state, so it skips them and processes the
    # trailing function. Only the shapes clients actually send are handled; an
    # unknown piggyback is left in place (the caller then ignores the message
    # rather than mis-parsing it).
    while len(body) >= 3 and body[0] == TTI_MSG_TYPE_PIGGYBACK:
        if body[1] != TTI_OCCA:  # CLOSE_CURSORS (105)
            break
        rest = body[3:]  # skip the piggyback token, function code, sequence
        rest = rest[1:]  # pointer byte
        count, rest = decode_ub4(rest)
        for _ in range(count):
            _, rest = decode_ub4(rest)  # each closed cursor id (ignored)
        body = rest
    return body


def _answer_query(stream: PacketStream, backend: Backend, request: ExecRequest) -> None:
    # Run the query and reply. Any failure becomes an ORA error on a healthy
    # connection — the Mirror must never desync, so even a backend that leaks a
    # native exception is caught and reported rather than dropping the wire.
    try:
        if len(request.bind_rows) > 1:
            # Array DML (executemany): apply each bind row and report the total
            # affected-row count — one execute message, one aggregated reply.
            affected = 0
            for row in request.bind_rows:
                affected += backend.execute(request.sql, row).rowcount
            result = Result(rowcount=affected)
        else:
            result = backend.execute(request.sql, request.binds)
        # Autocommit mode: the client set the commit-on-success option, so
        # persist this statement before replying (an explicit-transaction client
        # leaves the bit clear and drives commit/rollback itself).
        if request.autocommit:
            backend.commit()
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


def _answer_txn(stream: PacketStream, backend: Backend, *, commit: bool) -> None:
    # Explicit transaction control: the client's commit() / rollback() each send
    # a bare function message and block for a reply. Drive the backend and answer
    # with a success status; a backend failure is reported as an ORA error rather
    # than dropped (same never-desync rule as the query path).
    try:
        if commit:
            backend.commit()
        else:
            backend.rollback()
    except BackendError as err:
        response = encode_error(err.ora_code, err.ora_message)
    except Exception as exc:
        logger.warning('backend raised a non-ORA error: %s', exc)
        response = encode_error(_INTERNAL_ERROR, f'ORA-00600: backend error: {exc}')
    else:
        response = encode_status(0)
    stream.write_packet(TNS_DATA, response)
