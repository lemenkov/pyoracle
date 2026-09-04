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
from seerdb.common.tns import ColumnMeta
from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
from seerdb.server.backend import Result, UnsupportedFeature, credential_lookup
from seerdb.server.framing import PacketStream
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

    def set_end_to_end(self, attrs: dict) -> None:
        # Record what the Mirror hands over from a tracing piggyback.
        self.tracing = {**getattr(self, 'tracing', {}), **attrs}

    def sessionless_begin(self, transaction_id: bytes, timeout: int) -> None:
        self.sessionless = ('begin', transaction_id, timeout)

    def sessionless_resume(self, transaction_id: bytes, timeout: int) -> None:
        self.sessionless = ('resume', transaction_id, timeout)

    def sessionless_suspend(self) -> None:
        self.sessionless = ('suspend', None, 0)


def _run_mirror(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    stream = PacketStream(conn)
    try:
        result['user'], _sqlplus, _conn_key = handle_login(stream, _DualBackend())
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


class _BadOutBindBackend(_DualBackend):
    # A PL/SQL block returns an OUT-bind value the wire cannot encode (a bare
    # object has no _encode_value branch), standing in for a backend that hands
    # back a value the Mirror can't represent — e.g. an INTERVAL YEAR TO MONTH that
    # a foreign backend surfaces as a plain timedelta. Everything else behaves like
    # _DualBackend.
    def execute(self, sql: str, binds=()) -> Result:
        if sql.lstrip().upper().startswith('BEGIN'):
            return Result(out_binds=[object()])
        return super().execute(sql, binds)


def _run_bad_out_bind_session(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(PacketStream(conn), _BadOutBindBackend())
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def _run_mirror_login_at(listen: socket.socket, result: dict, version: int) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(
            PacketStream(conn), _DualBackend(), field_version=version
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


@pytest.mark.parametrize('version', [7, 8, 16, 17])  # 12.1, 12.2, 21c, 23ai
def test_live_seerdb_login_at_a_higher_field_version(version: int) -> None:
    # A Mirror advertising a 12c+ field version: the real client negotiates to it
    # and logs in — a 12.1+ client length-prefixes the username in OSESSKEY /
    # AUTH, which the auth parsers must honour for that version. The O5LOGON
    # crypto itself is the same 11g SHA-1 verifier scheme at every version.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_login_at, args=(listen, result, version), daemon=True
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
        assert conn.field_version == version
        # …and the query round-trip in that version's request / describe / OER
        # layouts, with and without a bind (12.2+ reshapes all three).
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        assert cursor.fetchone() == ('X',)
        cursor.execute('select :b from dual', ['abc'])
        assert cursor.fetchone() == ('X',)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert result.get('user') == 'PYO'


def _exec_body() -> bytes:
    from seerdb.common.tns import encode_dictionary_exec

    return encode_dictionary_exec(
        {
            'field_version': 17,
            'seq': 5,
            'query': {
                'type': 'select',
                'auto': 0,
                'fetch': 15,
                'server_version': 0,
                'cursor': 0,
                'query': 'select * from dual',
                'bind': [],
                'batch': [],
                'def': [],
                'batcherrors': None,
                'arraydmlrowcounts': None,
                'return_binds': None,
                'scrollable': False,
                'scroll': None,
            },
        }
    )


@pytest.mark.parametrize(
    'attrs',
    [
        {'module': 'm'},
        {
            'client_identifier': 'c',
            'module': 'mod',
            'action': 'a',
            'client_info': 'i',
            'dbop': 'd',
        },
        {'module': None, 'action': 'act'},  # a cleared attribute carries no value
        {'client_info': 'x' * 300},  # a long value rides the chunked DALC form
    ],
)
def test_skip_piggybacks_walks_the_12c_tracing_and_session_state(attrs: dict) -> None:
    # The 12.1+ client puts the end-to-end tracing (135) and request-boundary
    # session-state (176) piggybacks in front of a call; the Mirror keeps no such
    # state and must land exactly on the call that follows.
    from seerdb.common.tns import (
        _DECODE_FIELD_VERSION,
        encode_close_cursors_piggyback,
        encode_end_to_end_piggyback,
        encode_session_state_piggyback,
    )
    from seerdb.server.session import _skip_piggybacks

    body = _exec_body()
    token = _DECODE_FIELD_VERSION.set(17)
    try:
        e2e = encode_end_to_end_piggyback(4, 17, attrs)
        state = encode_session_state_piggyback(4, 17, 0x44)
        close = encode_close_cursors_piggyback(4, 17, [3, 9])
        backend = _DualBackend()
        assert _skip_piggybacks(e2e + body, backend) == body
        # …and the attributes (a cleared one as None) reach the backend.
        assert backend.tracing == dict(attrs)
        assert _skip_piggybacks(state + body) == body
        assert _skip_piggybacks(close + e2e + state + body) == body
        # an unknown piggyback is left in place, as before
        assert (
            _skip_piggybacks(bytes([0x11, 0xCD, 4]) + body)
            == bytes([0x11, 0xCD, 4]) + body
        )
    finally:
        _DECODE_FIELD_VERSION.reset(token)


def test_live_seerdb_tracing_attributes_at_a_higher_field_version() -> None:
    # A real 23ai-negotiated client sets tracing attributes; the next execute
    # carries the SET_END_TO_END_ATTR piggyback, and the query still answers.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]
    result: dict = {}
    backend = _DualBackend()

    def run() -> None:
        conn, _ = listen.accept()
        try:
            result['user'] = serve_session(
                PacketStream(conn), backend, field_version=17
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
            result['error'] = exc
        finally:
            conn.close()

    server = threading.Thread(target=run, daemon=True)
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
        conn.module = 'seerdb-test'
        conn.client_identifier = 'tracer'
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        assert cursor.fetchone() == ('X',)
        assert backend.tracing == {
            'module': 'seerdb-test',
            'action': None,
            'client_identifier': 'tracer',
        }
        conn.module = None  # a clear rides the next call too
        cursor.execute('select * from dual')
        assert cursor.fetchone() == ('X',)
        assert backend.tracing['module'] is None
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()
    assert result.get('error') is None, result.get('error')


def test_live_seerdb_sessionless_transaction_at_23ai() -> None:
    # A real 23ai-negotiated client begins a sessionless transaction, runs a
    # statement, suspends it, and each TPC switch reaches the backend.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]
    result: dict = {}
    backend = _DualBackend()

    def run() -> None:
        conn, _ = listen.accept()
        try:
            result['user'] = serve_session(
                PacketStream(conn), backend, field_version=17
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
            result['error'] = exc
        finally:
            conn.close()

    server = threading.Thread(target=run, daemon=True)
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
        txnid = conn.begin_sessionless_transaction('sl-live', timeout=45)
        assert backend.sessionless == ('begin', txnid, 45)
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        assert cursor.fetchone() == ('X',)
        conn.suspend_sessionless_transaction()
        assert backend.sessionless[0] == 'suspend'
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()
    assert result.get('error') is None, result.get('error')


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


def test_unencodable_out_bind_errors_but_keeps_connection() -> None:
    # The never-desync rule extends to encoding the reply: a backend that returns
    # an OUT-bind value the wire can't carry must surface a clean ORA error on a
    # HEALTHY connection, not drop it mid-response. The OUT-bind encode step used
    # to run outside the guard, so it desynced (#535).
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_bad_out_bind_session, args=(listen, result), daemon=True
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
            cursor.callproc('P', [cursor.var(seerdb.DB_TYPE_NUMBER)])
        assert 'ORA-00600' in str(excinfo.value)
        # The connection survived the encoding failure — a valid query still works.
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


# --- PL/SQL OUT-bind helpers (#483) --------------------------------------------


def test_is_plsql_block_detects_begin_and_declare() -> None:
    from seerdb.server.session import _is_plsql_block

    assert _is_plsql_block('BEGIN p(:1); END;')
    assert _is_plsql_block('  declare x number; begin null; end;')
    assert not _is_plsql_block('SELECT 1 FROM dual')
    assert not _is_plsql_block('INSERT INTO t VALUES (:1)')


def test_plsql_bind_vars_wraps_block_binds_with_type_and_size() -> None:
    from seerdb.common.tns import ExecRequest
    from seerdb.common.tns_consts import (
        TNS_TYPE_NUMBER,
        TNS_TYPE_REFCURSOR,
        TNS_TYPE_VARCHAR,
    )
    from seerdb.server.backend import BindVar
    from seerdb.server.session import _plsql_bind_vars

    block = ExecRequest(
        sql='BEGIN p(:1, :2); END;',
        cursor=0,
        bind_count=2,
        fetch=0,
        binds=[7, None],
        bind_meta=[(TNS_TYPE_NUMBER, 22), (TNS_TYPE_VARCHAR, 32767)],
    )
    wrapped = _plsql_bind_vars(block)
    assert all(isinstance(b, BindVar) for b in wrapped)
    assert (wrapped[0].value, wrapped[0].tns_type, wrapped[0].max_size) == (
        7,
        TNS_TYPE_NUMBER,
        22,
    )
    assert wrapped[1].max_size == 32767  # the OUT VARCHAR buffer size

    # A non-block statement passes its plain values through unchanged.
    dml = ExecRequest(
        sql='INSERT INTO t VALUES (:1)',
        cursor=0,
        bind_count=1,
        fetch=0,
        binds=[7],
        bind_meta=[(TNS_TYPE_NUMBER, 22)],
    )
    assert _plsql_bind_vars(dml) == [7]

    # A REF CURSOR bind also rides the OUT path — the backend opens the cursor
    # and its rows come back on a parked cursor id (#483).
    refc = ExecRequest(
        sql='BEGIN p(:1); END;',
        cursor=0,
        bind_count=1,
        fetch=0,
        binds=[None],
        bind_meta=[(TNS_TYPE_REFCURSOR, 1)],
    )
    wrapped_rc = _plsql_bind_vars(refc)
    assert len(wrapped_rc) == 1
    assert wrapped_rc[0].tns_type == TNS_TYPE_REFCURSOR


def test_oci_sequence_advances_per_reply() -> None:
    # The per-session OER end-to-end sequence counter yields a fresh, advancing
    # value on each call, starting at 1 — the Mirror threads seq.next() into every
    # OCI status reply so the field advances like a real server's instead of
    # repeating the frozen capture constant (§36).
    from seerdb.common.tns import encode_status_oci
    from seerdb.server.session import _OciSequence

    seq = _OciSequence()
    assert [seq.next() for _ in range(4)] == [1, 2, 3, 4]

    # Threading one counter through consecutive status replies advances the OER
    # sequence byte (frame offset 40: the compact OER sits at offset 32 with three
    # leading pad bytes, and the sequence is at the OER's own offset 5) reply over
    # reply — and nothing else in the frame changes.
    seq2 = _OciSequence()
    first = encode_status_oci(seq2.next())
    second = encode_status_oci(seq2.next())
    assert first[40] == 1
    assert second[40] == 2
    assert [i for i in range(len(first)) if first[i] != second[i]] == [40]


# --- sqlplus PASSWORD / OCI changepassword (#21) ------------------------------


def _oci_changepassword_frame(
    conn_key: bytes, user: bytes, old: str, new: str
) -> bytes:
    """Build a synthetic OCI (deadbeef) changepassword TTI_AUTH, as sqlplus's
    PASSWORD sends inside its TTI_80SES piggyback (unwrapped): AUTH_PASSWORD
    (current) + AUTH_NEWPASSWORD (new), each hex(AES-cipher under conn_key)."""
    from seerdb.common import oci
    from seerdb.common.crypto import encrypt_password
    from seerdb.server.auth import encode_kv_oci

    ind = oci.OCI_INDICATOR
    # header: TTI_FUN + AUTH subtype, indicators at offsets 3/19/35/43, then the
    # ub1-length username at offset 51 (see auth._parse_oci_fun_username).
    header = (
        b'\x03\x73\x00'
        + ind
        + b'\x00' * 8
        + ind
        + b'\x00' * 8
        + ind
        + ind
        + bytes([len(user)])
        + user
    )
    old_hex = encrypt_password(conn_key, old.encode()).hex().upper().encode()
    new_hex = encrypt_password(conn_key, new.encode()).hex().upper().encode()
    return (
        header
        + encode_kv_oci(b'AUTH_PASSWORD', old_hex)
        + encode_kv_oci(b'AUTH_NEWPASSWORD', new_hex)
    )


def test_is_version_call_oci_distinguishes_changepassword() -> None:
    # The version call and the changepassword both arrive as a TTI_80SES
    # (0x11 0x6b) piggyback with the same 15-byte prefix; only the wrapped TTI
    # function differs (0x3b version vs. TTI_AUTH). is_version_call_oci must key
    # on the inner function, else a changepassword is answered with the banner.
    from seerdb.common.tns import is_version_call_oci, strip_oci_piggyback

    prefix = bytes.fromhex('116b043b000000e507000001000000')
    version = prefix + bytes.fromhex('033b') + b'\x00' * 4
    change = prefix + bytes.fromhex('0373') + b'\x00' * 4
    assert is_version_call_oci(version)
    assert not is_version_call_oci(change)
    # strip_oci_piggyback unwraps the TTI_80SES wrapper to the inner TTI_FUN call.
    assert strip_oci_piggyback(change)[:2] == bytes.fromhex('0373')
    assert strip_oci_piggyback(version)[:2] == bytes.fromhex('033b')


def test_oci_changepassword_decrypts_and_applies() -> None:
    from seerdb.common.tns import encode_changepassword_status_oci
    from seerdb.server.auth import parse_changepassword_oci
    from seerdb.server.session import _answer_changepassword_oci

    conn_key = bytes(range(24))
    frame = _oci_changepassword_frame(conn_key, b'PWTEST', 'oldpw', 'newpw')

    # The parser recovers the two ciphertexts (un-hexed).
    from seerdb.common.crypto import encrypt_password

    user, old_c, new_c = parse_changepassword_oci(frame)
    assert user == b'PWTEST'
    assert old_c == encrypt_password(conn_key, b'oldpw')
    assert new_c == encrypt_password(conn_key, b'newpw')

    calls: list = []

    class _Backend:
        def change_password(self, u: str, old: str, new: str) -> None:
            calls.append((u, old, new))

    class _Stream:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        def write_packet(self, ptype: int, body: bytes) -> None:
            self.sent.append(body)

    class _Seq:
        def next(self) -> int:
            return 1

    stream = _Stream()
    _answer_changepassword_oci(stream, _Backend(), frame, conn_key, 'PWTEST', _Seq())
    # decrypted the pair and drove the backend change, then acked with the
    # OCIPasswordChange success frame sqlplus renders as "Password changed".
    assert calls == [('PWTEST', 'oldpw', 'newpw')]
    assert stream.sent[-1] == encode_changepassword_status_oci()


def test_oci_changepassword_unsupported_backend_replies_ora_error() -> None:
    from seerdb.server.session import _answer_changepassword_oci

    conn_key = bytes(range(24))
    frame = _oci_changepassword_frame(conn_key, b'PWTEST', 'oldpw', 'newpw')

    class _Stream:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        def write_packet(self, ptype: int, body: bytes) -> None:
            self.sent.append(body)

    class _Seq:
        def next(self) -> int:
            return 1

    stream = _Stream()
    # A backend with no change_password: reply with an ORA error, never desync.
    _answer_changepassword_oci(stream, object(), frame, conn_key, 'PWTEST', _Seq())
    assert stream.sent, 'must answer even when unsupported'
    assert b'ORA-01031' in stream.sent[-1]


class _LeakyBackend(_DualBackend):
    # A backend that embeds a seerdb client talking to a NEWER Oracle (the
    # passthrough in front of a 23ai) leaves the codec's field-version context
    # variables at the upstream's version after every call — decode_packet /
    # encode_dictionary_exec set them per message in the calling thread. This
    # stand-in does exactly that on each execute and records the binds it got.
    def __init__(self) -> None:
        self.binds: list = []

    def execute(self, sql: str, binds=()) -> Result:
        from seerdb.common.tns import _DECODE_FIELD_VERSION, _ENCODE_FIELD_VERSION
        from seerdb.common.tns_consts import FIELD_VERSION_23_1

        self.binds.append(list(binds))
        _DECODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
        _ENCODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
        if sql.lstrip().upper().startswith('INSERT'):
            return Result(rowcount=1)
        return super().execute(sql, binds)


def test_backend_codec_context_does_not_leak_into_the_session() -> None:
    # A 32K+ string bind goes out in the 11g chunked LONG layout. If the backend's
    # own codec state (field version 23ai) leaked into the session thread, the
    # Mirror would decode the client's 11g chunks with the 12.2+ framing and hand
    # the backend a garbled value (observed live: 51951 chars for 51200, first
    # character dropped). The backend must see the client's exact value.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    backend = _LeakyBackend()
    result: dict = {}

    def run() -> None:
        conn, _ = listen.accept()
        try:
            result['user'] = serve_session(PacketStream(conn), backend)
        except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
            result['error'] = exc
        finally:
            conn.close()

    server = threading.Thread(target=run, daemon=True)
    server.start()

    text = '0123456789abcdef' * (50 * 1024 // 16)  # 51200 chars, chunked on the wire
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
        cursor.execute('select * from dual')  # the backend pollutes the context
        cursor.execute('INSERT INTO t (c) VALUES (:c)', {'c': text})
        cursor.execute('select * from dual')  # and the response path still works
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
    assert backend.binds[1] == [text]


def test_oci_loop_answers_a_break_marker() -> None:
    """A break / reset marker gets a marker back, not silence.

    The thick-OCI client sends one to resynchronise the line and then blocks
    until the server answers; ignoring it wedged the session until the client
    timed out.
    """
    from seerdb.common.tns_consts import TNS_MARKER, TNS_MARKER_TYPE_RESET
    from seerdb.server.session import _serve_oci_session

    class _Stream:
        def __init__(self) -> None:
            self.inbox = [(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET])), None]
            self.sent: list[tuple[int, bytes]] = []

        def read_packet(self):
            return self.inbox.pop(0)

        def write_packet(self, ptype: int, body: bytes, **_kw) -> None:
            self.sent.append((ptype, body))

    stream = _Stream()
    assert _serve_oci_session(stream, object(), 'PYO') == 'PYO'
    # Exactly one reply, and it is a reset marker: replying to every marker
    # ping-pongs the two ends into a reset storm.
    assert stream.sent == [(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))]
