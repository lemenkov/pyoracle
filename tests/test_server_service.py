# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""seerdb.Server / seerdb.serve — the top-level Mirror entry point."""

from __future__ import annotations

import threading

import seerdb
from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
from seerdb.server import (
    ColumnMeta,
    Result,
    UnsupportedFeature,
    credential_lookup,
)
from seerdb.server.backend import Capability


class _DualBackend:
    # A fresh instance is created per session by the factory below.
    capabilities: frozenset[Capability] = frozenset()

    def authenticate(self, username: str) -> str | None:
        return credential_lookup({'PYO': 'pyo123'}, username)

    def execute(self, sql: str, binds=()) -> Result:
        if 'dual' in sql.lower():
            col = ColumnMeta(
                name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
            )
            return Result(columns=[col], rows=[('X',)])
        raise UnsupportedFeature(sql)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass


def test_seerdb_server_serves_a_client() -> None:
    # port=0 binds an ephemeral port, readable before serving.
    server = seerdb.Server(
        host='127.0.0.1',
        port=0,
        backend_factory=_DualBackend,
    )
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
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        row = cursor.fetchone()
        conn.close()
    finally:
        server.close()
        thread.join(timeout=5)

    assert row == ('X',)
