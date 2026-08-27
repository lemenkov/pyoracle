# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A live seerdb client logs into the Mirror end-to-end.

The Mirror's own client is an independent implementation of the same protocol,
so a successful login exercises the whole server login path (handshake +
O5LOGON) against a real client.
"""

from __future__ import annotations

import socket
import threading

import pytest

import seerdb
from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
from seerdb.server.backend import Result, UnsupportedFeature, credential_lookup
from seerdb.server.framing import PacketStream
from seerdb.server.query import ColumnMeta
from seerdb.server.session import handle_login, serve_session

_CREDS = {'PYO': 'pyo123'}


class _DualBackend:
    # A trivial Backend: DUAL returns 'X'; anything else is refused with a clean
    # ORA error (so the Mirror answers, never desyncs).
    capabilities = frozenset()

    def authenticate(self, username: str) -> str | None:
        return credential_lookup(_CREDS, username)

    def execute(self, sql: str, binds=()) -> Result:
        if 'dual' in sql.lower():
            col = ColumnMeta(
                name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
            )
            return Result(columns=[col], rows=[('X',)])
        raise UnsupportedFeature(f'the DUAL backend only knows DUAL: {sql!r}')

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass


def _run_mirror(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    stream = PacketStream(conn)
    try:
        result['user'], _sqlplus = handle_login(stream, _DualBackend())
        # Block on the client's logoff / EOF so the socket stays open until the
        # client has read the auth result and returned from connect().
        stream.read_packet()
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def test_live_seerdb_login() -> None:
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(target=_run_mirror, args=(listen, result), daemon=True)
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        # A live connection whose field version negotiated down to 11g (6).
        assert conn is not None
        assert conn.field_version == 6
        assert conn.server_version == 186647040
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert result.get('user') == 'PYO'


def _run_mirror_session(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(PacketStream(conn), _DualBackend())
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def test_live_seerdb_dual_query() -> None:
    # The 2.1.0 capstone: a real client runs SELECT * FROM DUAL against the
    # Mirror (no Oracle, no Postgres) and gets the DUMMY 'X' row back.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_session, args=(listen, result), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        row = cursor.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('X',)


def test_live_seerdb_ping() -> None:
    # A real client's ping() (keepalive / pool health check) round-trips against
    # the Mirror and the session stays usable for a following query.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_session, args=(listen, result), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        conn.ping()  # must not hang
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        row = cursor.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('X',)


def test_unsupported_query_errors_but_keeps_connection() -> None:
    # The cardinal rule: a refused query is an ORA error on a HEALTHY
    # connection — never a desync. After the error, the connection still works.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_session, args=(listen, result), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        cursor = conn.cursor()
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            cursor.execute('select * from something_the_backend_refuses')
        assert 'ORA-03001' in str(excinfo.value)
        # The connection survived the error — a valid query still works.
        cursor.execute('select * from dual')
        row = cursor.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('X',)


def test_free_temp_drops_the_buffer_and_state_ops_ack() -> None:
    # A programmatic client's FREE_TEMP releases the temp LOB (the Mirror drops
    # its buffer) and OPEN / CLOSE / TRIM / GET_CHUNK_SIZE are acknowledged rather
    # than mis-routed to the read path — no desync (#417). Driven at the handler
    # level: no client in the matrix sends these against the Mirror.
    import struct

    from seerdb.common.tns import _fun_header, decode_lobops_oer, encode_sb4
    from seerdb.common.tns_consts import (
        FIELD_VERSION_11_2,
        TNS_DATA,
        TNS_LOB_OP_FREE_TEMP,
        TNS_LOB_OP_OPEN,
        TTI_LOBOPS,
    )
    from seerdb.server.session import _answer_lobops

    def op_request(operation: int, locator: bytes) -> bytes:
        body = _fun_header(TTI_LOBOPS, 1, FIELD_VERSION_11_2)
        body += bytes([1]) + encode_sb4(len(locator) + 2) + bytes([0])
        body += encode_sb4(0) * 3 + bytes([0, 0, 0]) + encode_sb4(operation)
        body += bytes([0, 0]) + encode_sb4(0) * 2 + bytes([0])
        body += struct.pack('>HHH', 0, 0, 0)
        body += struct.pack('>H', len(locator)) + locator
        return body

    class _FakeStream:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        def write_packet(self, packet_type: int, body: bytes) -> None:
            assert packet_type == TNS_DATA
            self.sent.append(body)

    locator = b'\x00seerdb-mirror-temp-lob-\x00\x00\x00\x00\x01'
    temp_lobs = {bytes(locator): bytearray(b'written-bytes')}
    stream = _FakeStream()

    # FREE_TEMP drops the buffer and replies with a success ack.
    _answer_lobops(stream, op_request(TNS_LOB_OP_FREE_TEMP, locator), [], temp_lobs)
    assert bytes(locator) not in temp_lobs
    assert decode_lobops_oer(stream.sent[-1], 6)[0] in (0, 1403)

    # A state op (OPEN) is acknowledged, buffer untouched, no desync.
    temp_lobs[bytes(locator)] = bytearray(b'x')
    _answer_lobops(stream, op_request(TNS_LOB_OP_OPEN, locator), [], temp_lobs)
    assert bytes(locator) in temp_lobs  # OPEN doesn't free
    assert decode_lobops_oer(stream.sent[-1], 6)[0] in (0, 1403)
