# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Drive the server side of a login over a :class:`PacketStream`.

Sequences the 11g handshake and O5LOGON built up across the handshake/auth
modules, so a real client authenticates against the Mirror in either PRO
dialect — the thin ``TTI_PRO`` form (seerdb, python-oracledb thin) or the classic
``deadbeef``/OCI form (sqlplus, thick OCI), which runs an extra data-type round
and marshals auth from captured 11g templates (#265):

    CONNECT → ACCEPT → PRO → DTY → [TYPE] → OSESSKEY → challenge → AUTH → result

The Mirror holds account passwords in a configured credential map (Oracle
usernames match case-insensitively); a backend-mapped auth API comes later.
"""

from __future__ import annotations

import logging
from secrets import token_bytes
from typing import NoReturn

from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import decode_ub4
from seerdb.common.tns_consts import (
    TNS_CONNECT,
    TNS_DATA,
    TTI_ALL8,
    TTI_COMMIT,
    TTI_FETCH,
    TTI_FUN,
    TTI_LOGOFF,
    TTI_MSG_TYPE_PIGGYBACK,
    TTI_OCCA,
    TTI_ROLLBACK,
)
from seerdb.server.auth import (
    derive_conn_key,
    encode_challenge,
    encode_challenge_oci,
    encode_result,
    encode_result_oci,
    make_challenge,
    parse_auth_response,
    parse_auth_response_oci,
    parse_osesskey,
    parse_osesskey_oci,
    verify_password,
)
from seerdb.server.backend import Backend, BackendError, Result
from seerdb.server.framing import PacketStream
from seerdb.server.handshake import (
    encode_accept,
    encode_dty_reply,
    encode_pro_reply,
    encode_type_reply_sqlplus,
    parse_connect,
    pro_is_sqlplus,
)
from seerdb.server.query import (
    ColumnMeta,
    ExecRequest,
    FetchRequest,
    encode_describe_oci,
    encode_error,
    encode_fetch_response,
    encode_query_response,
    encode_status,
    encode_version_banner_oci,
    is_version_call_oci,
    parse_exec,
    parse_exec_oci,
    parse_fetch,
)

logger = logging.getLogger('seerdb.server')

# A generic backend failure that leaked past the Backend contract still becomes
# a clean ORA error rather than a wire desync (ORA-00600, internal error).
_INTERNAL_ERROR = 600

# A fetch count of 0 or less means "no limit" — deliver the whole remainder.
_ALL_ROWS = 2**31


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


def handle_login(stream: PacketStream, backend: Backend) -> tuple[str, bool]:
    """Run the server side of the handshake + O5LOGON.

    Returns ``(username, is_sqlplus)`` — the second flag says whether the client
    speaks the classic sqlplus / thick-OCI (deadbeef) dialect, so the query loop
    can answer it in the right marshalling (#265).

    The O5LOGON secret comes from ``backend.authenticate(user)`` — auth lives
    with the backend, not the Mirror. Raises :class:`InterfaceError` on a
    protocol desync, an unknown/rejected user, or a client that gives up. A wrong
    password is not rejected here — the client's own ``validate()`` fails on the
    mismatched session key (mutual auth).
    """
    # --- Handshake (§2, §4.1/§4.2) ---
    request = parse_connect(_expect(stream, TNS_CONNECT, 'CONNECT'))
    stream.send_raw(encode_accept(request))
    # A thin (oracledb/seerdb) client leads its PRO with TTI_PRO; classic
    # sqlplus / thick OCI leads with the `deadbeef` magic and needs the matching
    # reply dialect (#265). Decide on the PRO request and hold it for the DTY
    # reply so both halves speak one dialect.
    sqlplus = pro_is_sqlplus(_expect(stream, TNS_DATA, 'PRO'))
    stream.send_raw(encode_pro_reply(sqlplus=sqlplus))
    _expect(stream, TNS_DATA, 'DTY')
    stream.send_raw(encode_dty_reply(sqlplus=sqlplus))
    if sqlplus:
        # sqlplus / thick OCI runs a third data-type negotiation round after DTY
        # (a `ttc=02` request) before it sends OSESSKEY; a thin client skips it
        # (#265).
        _expect(stream, TNS_DATA, 'TYPE')
        stream.send_raw(encode_type_reply_sqlplus())

    # --- O5LOGON (§4) ---
    # The same mutual-auth crypto drives both dialects; only the wire marshalling
    # differs. The thin form carries each phase as an RPA payload
    # (write_packet); the deadbeef/OCI form (#265) exchanges full packets built
    # from captured 11g templates (send_raw), so sqlplus / thick OCI logs in too.
    osesskey = _expect(stream, TNS_DATA, 'OSESSKEY')
    parse_osesskey_fn = parse_osesskey_oci if sqlplus else parse_osesskey
    user = parse_osesskey_fn(osesskey).decode('utf-8')
    secret = backend.authenticate(user)
    if secret is None:
        _deny_login(stream, f'unknown user: {user!r}')

    # The thin AUTH may omit AUTH_PASSWORD (bytes | None); the OCI AUTH always
    # carries it. Declare the wider type so both branches unpack cleanly.
    auth_password: bytes | None
    if sqlplus:
        # The OCI challenge template carries a 10-byte salt slot (thin uses 16).
        challenge = make_challenge(secret.encode('utf-8'), salt=token_bytes(10))
        stream.send_raw(encode_challenge_oci(challenge))
        _, client_sesskey, auth_password = parse_auth_response_oci(
            _expect(stream, TNS_DATA, 'AUTH')
        )
    else:
        challenge = make_challenge(secret.encode('utf-8'))
        stream.write_packet(TNS_DATA, encode_challenge(challenge))
        _, client_sesskey, auth_password = parse_auth_response(
            _expect(stream, TNS_DATA, 'AUTH')
        )

    conn_key = derive_conn_key(challenge, client_sesskey)
    # Verify the client's password proof (AUTH_PASSWORD) against the account
    # secret — the server half of O5LOGON's mutual auth. Without it the Mirror
    # would serve any client that ignores the server proof it can't validate.
    if not verify_password(conn_key, auth_password, secret.encode('utf-8')):
        _deny_login(stream, f'wrong password for user: {user!r}')
    if sqlplus:
        stream.send_raw(encode_result_oci(conn_key))
    else:
        stream.write_packet(TNS_DATA, encode_result(conn_key))

    logger.info('login OK: %s', user)
    return user, sqlplus


def _deny_login(stream: PacketStream, reason: str) -> NoReturn:
    # Reject a login the way Oracle does — an ORA-01017 OER in place of the next
    # auth reply, which the client raises out of connect() — then drop the
    # connection. (Without this the client would connect() cleanly and fail
    # later.) The message is deliberately generic (user vs password not
    # distinguished) as Oracle's ORA-01017 is.
    stream.write_packet(
        TNS_DATA,
        encode_error(1017, 'ORA-01017: invalid username/password; logon denied'),
    )
    raise InterfaceError(f'authentication rejected — {reason}')


def serve_session(stream: PacketStream, backend: Backend) -> str:
    """Log a client in, then answer its queries until it disconnects.

    After :func:`handle_login`, each OALL8 execute is parsed, handed to
    ``backend.execute``, and answered with a describe + rows response — or, if
    the backend refuses (:class:`BackendError` / :class:`UnsupportedFeature`) or
    fails, with an ORA error that leaves the connection usable. A result set
    larger than the requested fetch count is returned in batches: the first on
    the execute, the rest on follow-up ``TTI_FETCH`` calls (:class:`_Cursors`
    holds the undelivered rows). A logoff (or EOF) ends the session and returns
    the authenticated username.
    """
    user, sqlplus = handle_login(stream, backend)
    if sqlplus:
        return _serve_oci_session(stream, backend, user)
    cursors = _Cursors()
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
            _answer_query(stream, backend, parse_exec(body), cursors)
        elif body[1] == TTI_FETCH:
            _answer_fetch(stream, parse_fetch(body), cursors)
        elif body[1] == TTI_COMMIT:
            _answer_txn(stream, backend, commit=True)
        elif body[1] == TTI_ROLLBACK:
            _answer_txn(stream, backend, commit=False)
        elif body[1] == TTI_LOGOFF:
            return user


# The banner sqlplus prints after "Connected to:". The Mirror emulates an 11g
# listener, so it reports the matching version string (naming is a later
# discussion, like the Mirror's own name).
_OCI_BANNER = (
    b'Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production'
)


def _serve_oci_session(stream: PacketStream, backend: Backend, user: str) -> str:
    # The sqlplus / thick-OCI query loop (#265), built up one message shape at a
    # time. So far: the post-login version call (-> banner, which lets sqlplus
    # print "Connected to:") and the OCI execute (-> describe). The rows/fetch
    # response and the remaining OCI calls (piggybacks, commit) are follow-ups;
    # an unhandled call ends the session cleanly rather than desyncing.
    while True:
        received = stream.read_packet()
        if received is None:
            return user
        packet_type, body = received
        if packet_type != TNS_DATA:
            continue
        if is_version_call_oci(body):
            stream.write_packet(TNS_DATA, encode_version_banner_oci(_OCI_BANNER))
            continue
        if len(body) >= 2 and body[0] == TTI_FUN:
            if body[1] == TTI_ALL8:
                try:
                    request = parse_exec_oci(body)
                except InterfaceError:
                    logger.info('OCI: unsupported execute shape; ending session')
                    return user
                result = backend.execute(request.sql, request.binds)
                if result.columns:
                    stream.write_packet(TNS_DATA, encode_describe_oci(result.columns))
                    continue
                return user  # OCI DDL/DML status is a later increment
            if body[1] == TTI_LOGOFF:
                return user
        logger.info('OCI: unhandled call ttc=%s; ending session', body[:2].hex())
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


class _Cursors:
    # Undelivered rows for result sets not yet drained, keyed by a per-session
    # cursor id. A query whose result exceeds the requested fetch count parks the
    # remainder here and hands it out on later TTI_FETCH calls (the Mirror's only
    # cross-call state). Cursor ids start at 1 — 0 means "no cursor" on the wire.
    def __init__(self) -> None:
        self._next = 1
        self._open: dict[int, tuple[list[ColumnMeta], list[tuple]]] = {}

    def open(self, columns: list[ColumnMeta], rows: list[tuple]) -> int:
        cursor_id = self._next
        self._next += 1
        self._open[cursor_id] = (columns, rows)
        return cursor_id

    def take(self, cursor_id: int, count: int) -> tuple[list[ColumnMeta], list[tuple]]:
        # Return (columns, next batch) and either keep the remainder or, once the
        # cursor is drained, forget it. An unknown cursor yields an empty batch.
        state = self._open.get(cursor_id)
        if state is None:
            return [], []
        columns, remaining = state
        batch, rest = remaining[:count], remaining[count:]
        if rest:
            self._open[cursor_id] = (columns, rest)
        else:
            del self._open[cursor_id]
        return columns, batch

    def has(self, cursor_id: int) -> bool:
        return cursor_id in self._open


def _answer_query(
    stream: PacketStream, backend: Backend, request: ExecRequest, cursors: _Cursors
) -> None:
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
            rows = list(result.rows)
            # Send the first `fetch` rows now; park any remainder on a cursor for
            # the client's follow-up TTI_FETCH calls. A non-positive fetch (or a
            # result that fits) is delivered whole, ending with ORA-01403.
            batch_size = request.fetch if request.fetch > 0 else len(rows)
            first, remaining = rows[:batch_size], rows[batch_size:]
            if remaining:
                cursor_id = cursors.open(result.columns, remaining)
                response = encode_query_response(
                    result.columns, first, cursor_id=cursor_id, more=True
                )
            else:
                response = encode_query_response(result.columns, first)
        else:
            response = encode_status(result.rowcount)
    stream.write_packet(TNS_DATA, response)


def _answer_fetch(
    stream: PacketStream, request: FetchRequest, cursors: _Cursors
) -> None:
    # Deliver the next batch of a parked result set. `take` hands back the
    # columns (the wire needs their types to encode values, though no describe is
    # sent) and the next `fetch` rows, dropping the cursor once it drains; `has`
    # then reports whether more remain. An unknown cursor yields an empty batch
    # terminated by ORA-01403.
    count = request.fetch if request.fetch > 0 else _ALL_ROWS
    columns, batch = cursors.take(request.cursor, count)
    response = encode_fetch_response(
        columns, batch, cursor_id=request.cursor, more=cursors.has(request.cursor)
    )
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
