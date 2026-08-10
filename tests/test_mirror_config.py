# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The config-driven Mirror runner (examples/mirror.py)."""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

import seerdb

_EXAMPLES = Path(__file__).resolve().parent.parent / 'examples'
sys.path.insert(0, str(_EXAMPLES))
from mirror import load_config  # noqa: E402

_SQLITE_INI = """\
[server]
host = 127.0.0.1
port = 0

[clients]
PYO = pyo123

[backend]
type = sqlite
database = :memory:
"""


def _write(tmp_path, text: str) -> str:
    path = tmp_path / 'mirror.ini'
    path.write_text(text)
    return str(path)


def test_load_config_builds_a_working_sqlite_factory(tmp_path) -> None:
    host, port, factory = load_config(_write(tmp_path, _SQLITE_INI))
    assert (host, port) == ('127.0.0.1', 0)
    backend = factory()
    try:
        assert backend.authenticate('PYO') == 'pyo123'
        assert backend.authenticate('pyo') == 'pyo123'  # case-insensitive
        assert backend.authenticate('nobody') is None
    finally:
        backend.close()


def test_unknown_backend_type_raises(tmp_path) -> None:
    ini = '[clients]\nPYO = pyo123\n\n[backend]\ntype = mysql\n'
    with pytest.raises(ValueError, match='unknown backend type'):
        load_config(_write(tmp_path, ini))


def test_missing_backend_section_raises(tmp_path) -> None:
    with pytest.raises(ValueError, match='backend'):
        load_config(_write(tmp_path, '[clients]\nPYO = pyo123\n'))


def test_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        load_config('/no/such/mirror.ini')


def test_shipped_sample_config_loads() -> None:
    # The example config committed alongside the runner must actually load.
    host, port, factory = load_config(str(_EXAMPLES / 'mirror.example.ini'))
    assert (host, port) == ('127.0.0.1', 1521)
    backend = factory()
    try:
        assert backend.authenticate('PYO') == 'pyo123'
    finally:
        backend.close()


def test_end_to_end_a_client_runs_sql_via_the_config(tmp_path) -> None:
    # The whole runner path: config → factory → serve → a real client query.
    host, port, factory = load_config(_write(tmp_path, _SQLITE_INI))
    server = seerdb.Server(host=host, port=port, backend_factory=factory)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = seerdb.connect(
            host='127.0.0.1',
            port=server.port,
            user='PYO',
            password='pyo123',
            service_name='XE',
            timeout=5000,
        )
        cur = conn.cursor()
        cur.execute('create table t (n number)')
        cur.execute('insert into t values (7)')
        cur.execute('select n from t')
        row = cur.fetchone()
        conn.close()
    finally:
        server.close()
        thread.join(timeout=5)

    assert row == (7,)
