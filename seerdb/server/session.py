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
from dataclasses import replace
from secrets import token_bytes
from typing import NoReturn

from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import decode_ub4
from seerdb.common.tns_consts import (
    TNS_CONNECT,
    TNS_DATA,
    TNS_TYPE_BLOB,
    TNS_TYPE_CLOB,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TTI_ALL8,
    TTI_COMMIT,
    TTI_FETCH,
    TTI_FUN,
    TTI_LOBOPS,
    TTI_LOGOFF,
    TTI_MSG_TYPE_PIGGYBACK,
    TTI_OCCA,
    TTI_PING,
    TTI_ROLLBACK,
)
from seerdb.server.auth import (
    derive_conn_key,
    encode_challenge,
    encode_challenge_oci,
    encode_result,
    encode_result_oci,
    encode_token_result,
    is_token_auth,
    make_challenge,
    parse_auth_response,
    parse_auth_response_oci,
    parse_osesskey,
    parse_osesskey_oci,
    parse_token_auth,
    verify_password,
)
from seerdb.server.backend import Backend, BackendError, Result
from seerdb.server.framing import PacketStream
from seerdb.server.handshake import (
    encode_accept,
    encode_ano_null_reply,
    encode_dty_reply,
    encode_pro_reply,
    encode_type_reply_sqlplus,
    is_ano_negotiation,
    parse_connect,
    pro_is_sqlplus,
)
from seerdb.server.query import (
    ColumnMeta,
    ExecRequest,
    FetchRequest,
    TempLobRef,
    ddl_command_type,
    encode_commit_status_oci,
    encode_create_temp_response,
    encode_ddl_status_oci,
    encode_dml_status_oci,
    encode_error,
    encode_error_oci,
    encode_fetch_batch_oci,
    encode_fetch_response,
    encode_fetch_terminator_oci,
    encode_lob_describe_oci,
    encode_lob_fetch_rows_oci,
    encode_lob_read_response_oci,
    encode_lob_read_response_thin,
    encode_lobops_ack,
    encode_logoff_status_oci,
    encode_long_fetch_row_oci,
    encode_out_bind_response_oci,
    encode_query_response,
    encode_query_response_oci,
    encode_reexec_row_oci,
    encode_scroll_open_response,
    encode_scroll_response,
    encode_status,
    encode_status_oci,
    encode_version_banner_oci,
    is_reexecute_oci,
    is_version_call_oci,
    mint_temp_lob_locator,
    oci_lob_contents,
    parse_exec,
    parse_exec_oci,
    parse_fetch,
    parse_lobops_read,
    parse_lobops_request,
    scroll_start_row,
    strip_oci_piggyback,
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


# The Mirror's algorithm preference, strongest first — intersected with what the
# client offered. Only the AES ciphers and SHA-2 checksums are implemented.
_SERVER_ENC_PREF = ('AES256', 'AES192', 'AES128')
_SERVER_INT_PREF = ('SHA256', 'SHA384', 'SHA512')


def _select_algorithm(
    offered: list[int], preference: tuple[str, ...], table: dict
) -> int:
    # The first of our preferences the client also offered; 0 (null) if none.
    offered_set = set(offered)
    for name in preference:
        if table[name] in offered_set:
            return table[name]
    return 0


def _negotiate_ano_server(
    stream: PacketStream, request_body: bytes, encryption: str
) -> None:
    # Server half of the ANO negotiation (#448). `request_body` is the client's
    # round-1 container (already read). Select a cipher per our stance; when one
    # is chosen, emit the DH exchange, take the client's public key, derive the
    # shared secret, and switch the stream to encrypted framing.
    from seerdb.common import ano
    from seerdb.common.ano_session import AnoChannel

    if encryption not in ('requested', 'required'):
        # Plaintext stance: the null-algorithm reply, session stays clear.
        stream.send_raw(encode_ano_null_reply(sdu=stream.sdu))
        return
    request = ano.decode_ano(request_body[request_body.index(b'\xde\xad\xbe\xef') :])
    enc_id = _select_algorithm(
        ano.offered_algorithm_ids(request, ano.SERVICE_ENCRYPTION),
        _SERVER_ENC_PREF,
        ano.ENCRYPTION_ALGO_IDS,
    )
    if enc_id == 0:
        # The client offered nothing we implement. REQUIRED can't proceed;
        # REQUESTED falls back to plaintext.
        if encryption == 'required':
            raise InterfaceError('ANO: no mutually supported encryption algorithm')
        stream.send_raw(encode_ano_null_reply(sdu=stream.sdu))
        return
    int_id = _select_algorithm(
        ano.offered_algorithm_ids(request, ano.SERVICE_DATA_INTEGRITY),
        _SERVER_INT_PREF,
        ano.INTEGRITY_ALGO_IDS,
    )
    sdh = ano.server_dh_keypair()
    stream.write_packet(
        TNS_DATA, ano.encode_ano_response(enc_id, int_id, sdh.public_key)
    )
    round2 = stream.read_packet()
    if round2 is None:
        raise InterfaceError('client closed during ANO key exchange')
    (_type, r2_body) = round2
    client_pub = ano.client_public_key(
        ano.decode_ano(r2_body[r2_body.index(b'\xde\xad\xbe\xef') :])
    )
    shared = sdh.derive(client_pub)
    stream.activate_ano(
        AnoChannel(enc_id, int_id, shared, ano.DH_SERVER_IV, ClientSide=False)
    )
    logger.debug(
        'handle_login (server): ANO active (enc=%d integrity=%d)', enc_id, int_id
    )


def _handle_token_login(
    stream: PacketStream, payload: bytes, token_public_key: bytes
) -> str:
    # Server half of token auth (#125): verify the OCI IAM request-header
    # signature (offline-checkable), then grant the session. The JWT itself is
    # validated by the real IAM service — the Mirror accepts it and labels the
    # session by its subject claim. Returns the username.
    from seerdb.common.token_auth import token_subject, verify_token_header

    token, header, signature = parse_token_auth(payload)
    if header is not None and signature is not None:
        if not verify_token_header(
            header.decode('utf-8'), signature.decode('utf-8'), token_public_key
        ):
            _deny_login(stream, 'token signature verification failed')
    stream.write_packet(TNS_DATA, encode_token_result())
    return token_subject(token.decode('utf-8')) or 'TOKEN_USER'


def handle_login(
    stream: PacketStream,
    backend: Backend,
    *,
    encryption: str = 'accepted',
    token_public_key: bytes | None = None,
) -> tuple[str, bool]:
    """Run the server side of the handshake + O5LOGON.

    Returns ``(username, is_sqlplus)`` — the second flag says whether the client
    speaks the classic sqlplus / thick-OCI (deadbeef) dialect, so the query loop
    can answer it in the right marshalling (#265).

    ``encryption`` is the Mirror's ANO stance (§33): ``'accepted'`` (default)
    stays plaintext unless the client forces it; ``'required'`` selects AES + a
    SHA-2 checksum and encrypts every DATA packet from PRO onward (#448).

    The O5LOGON secret comes from ``backend.authenticate(user)`` — auth lives
    with the backend, not the Mirror. Raises :class:`InterfaceError` on a
    protocol desync, an unknown/rejected user, or a client that gives up. A wrong
    password is not rejected here — the client's own ``validate()`` fails on the
    mismatched session key (mutual auth).
    """
    # --- Handshake (§2, §4.1/§4.2) ---
    request = parse_connect(_expect(stream, TNS_CONNECT, 'CONNECT'))
    stream.send_raw(encode_accept(request))
    # A modern thin client (seerdb/go-ora/oracledb) runs an ANO negotiation
    # before PRO now that our ACCEPT advertises ANO-capable (#437). Run the server
    # half (#448): select a cipher per our stance — or the null algorithm — and,
    # when a cipher is selected, run the DH exchange and switch the stream to
    # encrypted framing before reading the (now encrypted) PRO. The sqlplus/OCI
    # client's ANO uses a different version and is handled inline by the
    # `deadbeef` dialect path below, so it is left alone.
    first = _expect(stream, TNS_DATA, 'PRO')
    if is_ano_negotiation(first):
        _negotiate_ano_server(stream, first, encryption)
        first = _expect(stream, TNS_DATA, 'PRO')
    # A thin (oracledb/seerdb) client leads its PRO with TTI_PRO; classic
    # sqlplus / thick OCI leads with the `deadbeef` magic and needs the matching
    # reply dialect (#265). Decide on the PRO request and hold it for the DTY
    # reply so both halves speak one dialect.
    sqlplus = pro_is_sqlplus(first)
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
    # Token auth (#125): a thin client with an access token sends a single token
    # AUTH here instead of OSESSKEY. When the Mirror is configured to accept
    # tokens, verify the OCI IAM signature (offline-checkable) and grant the
    # session — there is no O5LOGON challenge, proof, or ConnKey.
    if token_public_key is not None and is_token_auth(osesskey):
        return _handle_token_login(stream, osesskey, token_public_key), sqlplus
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


def serve_session(
    stream: PacketStream,
    backend: Backend,
    *,
    encryption: str = 'accepted',
    token_public_key: bytes | None = None,
) -> str:
    """Log a client in, then answer its queries until it disconnects.

    After :func:`handle_login`, each OALL8 execute is parsed, handed to
    ``backend.execute``, and answered with a describe + rows response — or, if
    the backend refuses (:class:`BackendError` / :class:`UnsupportedFeature`) or
    fails, with an ORA error that leaves the connection usable. A result set
    larger than the requested fetch count is returned in batches: the first on
    the execute, the rest on follow-up ``TTI_FETCH`` calls (:class:`_Cursors`
    holds the undelivered rows). A logoff (or EOF) ends the session and returns
    the authenticated username. ``encryption`` is the Mirror's ANO stance,
    forwarded to :func:`handle_login` (§33 / #448).
    """
    user, sqlplus = handle_login(
        stream, backend, encryption=encryption, token_public_key=token_public_key
    )
    if sqlplus:
        return _serve_oci_session(stream, backend, user)
    cursors = _Cursors()
    # LOB contents (wire bytes + is_clob) the current statement's rows carry, in
    # the order their locators went out; the thin client drains them with
    # TTI_LOBOPS reads (it reads each LOB whole, row-major) (#413).
    lobs: list[tuple[bytes, bool]] = []
    # Bytes streamed into each session temp LOB via TTI_LOBOPS WRITE, keyed by the
    # locator the Mirror minted on CREATE_TEMP; resolved into the bind value on the
    # following execute (#412).
    temp_lobs: dict[bytes, bytearray] = {}
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
            request = _resolve_temp_lob_binds(parse_exec(body), temp_lobs)
            if request.scrollable:
                lobs = _answer_scroll(stream, backend, request, cursors)
            else:
                lobs = _answer_query(stream, backend, request, cursors)
        elif body[1] == TTI_LOBOPS:
            lobs = _answer_lobops(stream, body, lobs, temp_lobs)
        elif body[1] == TTI_FETCH:
            _answer_fetch(stream, parse_fetch(body), cursors)
        elif body[1] == TTI_COMMIT:
            _answer_txn(stream, backend, commit=True)
        elif body[1] == TTI_ROLLBACK:
            _answer_txn(stream, backend, commit=False)
        elif body[1] == TTI_PING:
            # A keepalive / pool health check (conn.ping()): no state to touch,
            # just acknowledge with a success status so the client round-trip
            # completes instead of hanging.
            stream.write_packet(TNS_DATA, encode_status(0))
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
    # time. So far: the post-login version call (-> banner), the OCI execute
    # (-> describe + rows + status), and the follow-up fetch (-> end-of-fetch
    # terminator). The PL/SQL / setup-query calls sqlplus sends before the prompt
    # (piggyback-wrapped) are follow-ups; an unhandled call ends the session
    # cleanly rather than desyncing.
    # Rows a multi-row execute delivered only the first of; the rest wait here
    # for the follow-up fetch (the OCI analogue of the thin _Cursors).
    parked: tuple[list[ColumnMeta], list[tuple]] | None = None
    # LOB contents (wire bytes + is_clob) the current statement's rows carry, in the
    # order their locators went out; sqlplus drains them with TTI_LOBOPS reads,
    # slicing the current LOB per each read's offset/amount (#405).
    lobs: list[tuple[bytes, bool]] = []
    current_lob: tuple[bytes, bool] | None = None
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
        # Every statement past the first arrives wrapped in an OCCA close-cursors
        # piggyback; unwrap it to reach the execute.
        body = strip_oci_piggyback(body)
        if len(body) >= 2 and body[0] == TTI_FUN:
            if body[1] == TTI_ALL8:
                if parked is not None and is_reexecute_oci(body):
                    # sqlplus re-executes the described cursor to pull LONG rows
                    # once its streaming define is set up. LONG rows stream one per
                    # reply: deliver the first now, re-park the rest for the
                    # follow-up fetches (#407).
                    parked = _serve_oci_long_row(stream, parked, reexecute=True)
                    continue
                parked, lobs = _answer_query_oci(stream, backend, body)
                current_lob = None
                continue
            if body[1] == TTI_LOBOPS:
                # sqlplus reads a LOB column's content, looping over the LOB in
                # SET LONGCHUNKSIZE-sized slices. A read that starts at offset 1 is
                # the first read of the next LOB (row-major); later offsets continue
                # the current one. Serve exactly the slice requested so the client's
                # read loop terminates when a read returns less than it asked (#405).
                offset, amount = parse_lobops_read(body)
                if offset <= 1 or current_lob is None:
                    current_lob = lobs.pop(0) if lobs else (b'', True)
                content, is_clob = current_lob
                unit = 2 if is_clob else 1  # bytes per counted unit (CLOB is UTF-16)
                total = len(content) // unit
                start = offset - 1
                count = max(0, min(amount, total - start))
                chunk = content[start * unit : (start + count) * unit]
                stream.write_packet(
                    TNS_DATA,
                    encode_lob_read_response_oci(
                        chunk, count, len(content), is_clob=is_clob
                    ),
                )
                continue
            if body[1] == TTI_FETCH:
                if parked is not None and _is_long_result(parked[0]):
                    # A LONG result drains one row per fetch (each with "more"),
                    # the last fetch drawing the 1403 terminator below (#407).
                    parked = _serve_oci_long_row(stream, parked, reexecute=False)
                elif parked is not None and _is_lob_result(parked[0]):
                    # A LOB result streams ONE row per fetch (sqlplus reads that
                    # row's LOB locators over TTI_LOBOPS before fetching the next —
                    # delivering every row at once desyncs it once a row carries
                    # more than one LOB column). Each row ends with a non-terminator
                    # status; the final empty fetch draws the 1403 terminator. The
                    # row-major LOB queue drains in the order the locators go out (#405).
                    columns, rows = parked
                    stream.write_packet(
                        TNS_DATA, encode_lob_fetch_rows_oci(columns, rows[:1])
                    )
                    parked = (columns, rows[1:]) if len(rows) > 1 else None
                elif parked is not None:
                    columns, rows = parked
                    stream.write_packet(TNS_DATA, encode_fetch_batch_oci(columns, rows))
                    parked = None
                else:
                    # Nothing parked — the execute already delivered every row;
                    # the fetch just wants the end-of-fetch terminator (ORA-01403).
                    stream.write_packet(TNS_DATA, encode_fetch_terminator_oci())
                continue
            if body[1] in (TTI_COMMIT, TTI_ROLLBACK):
                stream.write_packet(TNS_DATA, encode_commit_status_oci())
                continue
            if body[1] == TTI_LOGOFF:
                stream.write_packet(TNS_DATA, encode_logoff_status_oci())
                return user
        logger.info('OCI: unhandled call ttc=%s; ending session', body[:2].hex())
        return user


_OCI_DML_KEYWORDS = ('INSERT', 'UPDATE', 'DELETE', 'MERGE')


def _is_long_result(columns: list[ColumnMeta]) -> bool:
    # A result that carries a LONG / LONG RAW column, which sqlplus streams one
    # row per reply over the re-execute / fetch flow (#407).
    return any(col.data_type in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW) for col in columns)


def _is_lob_result(columns: list[ColumnMeta]) -> bool:
    # A result that carries a CLOB / BLOB column, whose locator row is fetched with
    # a non-terminator status and whose content follows over TTI_LOBOPS (#405).
    return any(col.data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB) for col in columns)


def _serve_oci_long_row(
    stream: PacketStream,
    parked: tuple[list[ColumnMeta], list[tuple]],
    *,
    reexecute: bool,
) -> tuple[list[ColumnMeta], list[tuple]] | None:
    # Deliver one LONG row and re-park the remainder (LONG streams a row per
    # reply). The re-execute reply ends with the execute row-status; a fetch reply
    # ends with the "more rows" OER status. Either way the drained state (None)
    # makes the next fetch return the 1403 terminator (#407).
    columns, rows = parked
    if reexecute:
        reply = encode_reexec_row_oci(columns, rows[:1], more=len(rows) > 1)
    else:
        reply = encode_long_fetch_row_oci(columns, rows[0])
    stream.write_packet(TNS_DATA, reply)
    return (columns, rows[1:]) if len(rows) > 1 else None


def _oci_no_row_status(sql: str, rowcount: int) -> bytes:
    # Pick the OCI success reply for a statement that returned no columns, so
    # sqlplus renders the right message (#348 / #349): DML carries the affected row
    # count ("N rows created/updated/deleted"); DDL / session verbs (CREATE / DROP
    # / ALTER / TRUNCATE / GRANT / … on TABLE / INDEX / VIEW / SEQUENCE / …) carry a
    # V$SQL command type sqlplus turns into "Table created.", "Index dropped.",
    # "Table truncated.", "Grant succeeded.", etc.; anything else (PL/SQL blocks,
    # session bootstrap) gets the generic "PL/SQL procedure successfully completed".
    keyword = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ''
    if keyword in _OCI_DML_KEYWORDS:
        return encode_dml_status_oci(keyword, rowcount)
    command_type = ddl_command_type(sql)
    if command_type is not None:
        return encode_ddl_status_oci(command_type)
    return encode_status_oci()


def _answer_query_oci(
    stream: PacketStream, backend: Backend, body: bytes
) -> tuple[tuple[list[ColumnMeta], list[tuple]] | None, list[tuple[bytes, bool]]]:
    # Answer one sqlplus / thick-OCI execute. sqlplus fires a chain of setup
    # statements (PL/SQL blocks, PRODUCT_PRIVS selects) before the user's query;
    # each needs an acceptable reply or sqlplus never reaches the prompt. Returns
    # ``(parked, lobs)``: the rows held for a follow-up fetch (or None), and the
    # LOB contents the result's rows carry for the follow-up TTI_LOBOPS reads.
    try:
        request = parse_exec_oci(body)
    except InterfaceError:
        # A shape not parsed yet (e.g. a bound PL/SQL setup call) — acknowledge
        # success so sqlplus proceeds; the backend never sees it.
        stream.write_packet(TNS_DATA, encode_status_oci())
        return None, []
    try:
        result = backend.execute(request.sql, request.binds)
    except BackendError as err:
        # A statement the backend can't run. A failed SELECT (e.g. sqlplus's
        # PRODUCT_PRIVS lookup) must come back as an ORA error — sqlplus expects
        # a query reply for a query and tolerates the error — while a non-query
        # (PL/SQL / DDL it can't do) gets a success status so the session
        # continues.
        if request.sql.lstrip().upper().startswith('SELECT'):
            stream.write_packet(TNS_DATA, encode_error_oci(err.ora_code, str(err)))
        else:
            stream.write_packet(TNS_DATA, encode_status_oci())
        return None, []
    if result.out_binds:
        # A PL/SQL block that assigned OUT binds (sqlplus VARIABLE / EXEC) — return
        # the values so the client reads them back into its bound buffers.
        stream.write_packet(TNS_DATA, encode_out_bind_response_oci(result.out_binds))
        return None, []
    if not result.columns:
        stream.write_packet(TNS_DATA, _oci_no_row_status(request.sql, result.rowcount))
        return None, []
    rows = list(result.rows)
    # Every LOB cell across the whole result queues its content now, row-major, so
    # the follow-up TTI_LOBOPS reads drain it in the order the locators went out.
    lobs = oci_lob_contents(result.columns, rows)
    has_long = any(
        col.data_type in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW) for col in result.columns
    )
    has_lob = any(
        col.data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB) for col in result.columns
    )
    if has_lob and rows:
        # A LOB result: sqlplus sets up its LOB define from the describe, then
        # fetches the locator rows. The LOB describe reply has its own shape (a
        # 33-byte tail + a LOB execute status, not the ordinary inline-row DCB
        # tail) — matching it is what makes sqlplus accept the locator row rather
        # than break (#405).
        stream.write_packet(TNS_DATA, encode_lob_describe_oci(result.columns))
        return (result.columns, rows), lobs
    if has_long and rows:
        # sqlplus fetches a LONG / LONG RAW row separately from the describe — it
        # sets up the streaming define buffer on the describe, then issues a fetch
        # — so deliver no row inline (an inline LONG row segfaults it): describe +
        # "more rows", then the row in the follow-up fetch (#407).
        stream.write_packet(
            TNS_DATA, encode_query_response_oci(result.columns, [], more=True)
        )
        return (result.columns, rows), lobs
    if len(rows) <= 1:
        # 0 or 1 row fits in the execute reply; sqlplus won't fetch further.
        stream.write_packet(TNS_DATA, encode_query_response_oci(result.columns, rows))
        return None, lobs
    # Deliver the first row now and park the rest — sqlplus reads the "more rows"
    # status and issues a fetch for the remainder.
    stream.write_packet(
        TNS_DATA, encode_query_response_oci(result.columns, rows[:1], more=True)
    )
    return (result.columns, rows[1:]), lobs


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
        # Scrollable cursors (#181/#485) keep their FULL materialised row set
        # keyed by cursor id and stay open across scroll re-executes (a scroll
        # can revisit any row), unlike `_open`, which hands out and forgets
        # batches. Shares the `_next` id space so ids never collide.
        self._scroll: dict[int, tuple[list[ColumnMeta], list[tuple]]] = {}

    def open(self, columns: list[ColumnMeta], rows: list[tuple]) -> int:
        cursor_id = self._next
        self._next += 1
        self._open[cursor_id] = (columns, rows)
        return cursor_id

    def open_scroll(self, columns: list[ColumnMeta], rows: list[tuple]) -> int:
        cursor_id = self._next
        self._next += 1
        self._scroll[cursor_id] = (columns, list(rows))
        return cursor_id

    def scroll_state(
        self, cursor_id: int
    ) -> tuple[list[ColumnMeta], list[tuple]] | None:
        # The (columns, all rows) of a kept-open scrollable cursor, or None if
        # the id isn't a scrollable cursor.
        return self._scroll.get(cursor_id)

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


def _answer_lobops(
    stream: PacketStream,
    body: bytes,
    lobs: list[tuple[bytes, bool]],
    temp_lobs: dict[bytes, bytearray],
) -> list[tuple[bytes, bool]]:
    # Dispatch a thin TTI_LOBOPS message. CREATE_TEMP / WRITE drive the temp-LOB
    # write flow (#412); FREE_TEMP / OPEN / CLOSE / TRIM / GET_CHUNK_SIZE are
    # acknowledged so a programmatic client doesn't desync (#417); a plain READ
    # drains the content of a column locator the Mirror emitted (#413). Returns
    # the (possibly shortened) read queue.
    request = parse_lobops_request(body)
    if request.kind == 'create_temp':
        locator = mint_temp_lob_locator(len(temp_lobs), request.is_blob)
        temp_lobs[bytes(locator)] = bytearray()
        stream.write_packet(TNS_DATA, encode_create_temp_response(locator))
        return lobs
    if request.kind == 'write':
        # Append at the write offset the client streamed (it writes from the
        # start and appends, so a plain concat matches every real client).
        temp_lobs.setdefault(bytes(request.locator), bytearray()).extend(
            request.payload
        )
        stream.write_packet(TNS_DATA, encode_lobops_ack(request.locator))
        return lobs
    if request.kind == 'free_temp':
        # Release the temp LOB now rather than at session end; the buffer may not
        # exist (a client can free a locator we never saw written) — that's fine.
        temp_lobs.pop(bytes(request.locator), None)
        stream.write_packet(TNS_DATA, encode_lobops_ack(request.locator))
        return lobs
    if request.kind == 'ack':
        # OPEN / CLOSE / TRIM / GET_CHUNK_SIZE: acknowledge with the content-free
        # reply the client accepts. The value-returning form (a real chunk size,
        # applying TRIM's length) is deferred (#421) — no test client needs it.
        stream.write_packet(TNS_DATA, encode_lobops_ack(request.locator))
        return lobs
    # A READ of an emitted column locator: hand back the next queued LOB whole,
    # row-major, matching the order the locators went out (#413).
    content, _is_clob = lobs.pop(0) if lobs else (b'', True)
    stream.write_packet(TNS_DATA, encode_lob_read_response_thin(content))
    return lobs


def _resolve_temp_lob_binds(
    request: ExecRequest, temp_lobs: dict[bytes, bytearray]
) -> ExecRequest:
    # Swap any temp-LOB locator bind for the bytes streamed into it over
    # TTI_LOBOPS WRITE, so the backend sees a plain str / bytes value (#412). A
    # CLOB's content is UTF-16BE on the wire; a BLOB's is raw.
    def resolve(value: object) -> object:
        if isinstance(value, TempLobRef):
            data = bytes(temp_lobs.get(bytes(value.locator), b''))
            return data if value.is_blob else data.decode('utf-16-be')
        return value

    if not any(isinstance(v, TempLobRef) for row in request.bind_rows for v in row):
        return request
    rows = [[resolve(v) for v in row] for row in request.bind_rows]
    return replace(request, binds=rows[0], bind_rows=rows)


def _answer_query(
    stream: PacketStream, backend: Backend, request: ExecRequest, cursors: _Cursors
) -> list[tuple[bytes, bool]]:
    # Run the query and reply. Any failure becomes an ORA error on a healthy
    # connection — the Mirror must never desync, so even a backend that leaks a
    # native exception is caught and reported rather than dropping the wire.
    # Returns the LOB contents the result's rows carry (row-major), which the thin
    # loop drains as the client issues its TTI_LOBOPS reads (#413).
    lobs: list[tuple[bytes, bool]] = []
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
            # A LOB result's rows carry locators; the client reads their content
            # row-major over TTI_LOBOPS, so queue every cell's content in that
            # order for the loop to drain (#413).
            lobs = oci_lob_contents(result.columns, rows)
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
    return lobs


def _answer_scroll(
    stream: PacketStream, backend: Backend, request: ExecRequest, cursors: _Cursors
) -> list[tuple[bytes, bool]]:
    # Serve a server-side scrollable cursor (#181/#485). Two shapes arrive on the
    # same SCROLLABLE-flagged execute: the opening execute (a new cursor, real
    # SQL) runs the query, parks the full result set, and returns describe + the
    # prefetched first batch; a scroll re-execute (an open scroll cursor id, no
    # SQL) repositions within the parked rows per the fetch orientation + 1-based
    # position and returns just that batch. The client places its buffer window
    # from the cumulative row number the terminator carries.
    state = cursors.scroll_state(request.cursor)
    if state is not None:
        # Reposition: slice the parked rows and reply with no describe.
        columns, rows = state
        total = len(rows)
        start = scroll_start_row(
            request.scroll_orientation, request.scroll_position, total
        )
        size = request.fetch if request.fetch > 0 else total
        if start < 1 or start > total:
            # Scrolled off either end: an empty batch ending in ORA-01403.
            stream.write_packet(
                TNS_DATA, encode_scroll_response([], [], server_rowcount=0, eof=True)
            )
            return []
        batch = rows[start - 1 : start - 1 + size]
        last_abs = start - 1 + len(batch)
        stream.write_packet(
            TNS_DATA,
            encode_scroll_response(
                columns, batch, server_rowcount=last_abs, eof=last_abs >= total
            ),
        )
        return oci_lob_contents(columns, batch)
    # Opening execute: run the query and park the whole result for later scrolls.
    try:
        result = backend.execute(request.sql, request.binds)
        if request.autocommit:
            backend.commit()
    except BackendError as err:
        logger.info('scrollable query refused: %s', err.ora_message)
        stream.write_packet(TNS_DATA, encode_error(err.ora_code, err.ora_message))
        return []
    except Exception as exc:
        logger.warning('backend raised a non-ORA error: %s', exc)
        stream.write_packet(
            TNS_DATA, encode_error(_INTERNAL_ERROR, f'ORA-00600: backend error: {exc}')
        )
        return []
    columns = result.columns
    rows = list(result.rows)
    cursor_id = cursors.open_scroll(columns, rows)
    size = request.fetch if request.fetch > 0 else len(rows)
    batch = rows[:size]
    last_abs = len(batch)
    stream.write_packet(
        TNS_DATA,
        encode_scroll_open_response(
            columns,
            batch,
            cursor_id,
            server_rowcount=last_abs,
            eof=last_abs >= len(rows),
        ),
    )
    return oci_lob_contents(columns, batch)


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
