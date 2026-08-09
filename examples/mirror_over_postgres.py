# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Run a Mirror backed by PostgreSQL — Oracle clients, a PostgreSQL database.

    python examples/mirror_over_postgres.py [CONNINFO] [PORT]

CONNINFO is a libpq connection string (default reads the ``MIRROR_PG`` env var,
falling back to ``host=127.0.0.1 port=5432 user=pyo password=pyo123
dbname=mirror``); PORT defaults to 1521.

Then point a thin-dialect Oracle client at ``127.0.0.1:PORT`` as ``PYO`` /
``pyo123`` (service ``XE``) and run PostgreSQL-flavoured SQL, e.g.:

    cur.execute('create table t (id integer, name varchar(20))')
    cur.execute("insert into t values (1, 'alice')")
    cur.execute('select * from t')     # -> [(1, 'alice')]

Requires the ``psycopg`` package.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading

from postgres_backend import PostgresBackend

from seerdb.server import PacketStream, serve_session

_CREDENTIALS = {'PYO': 'pyo123'}
_DEFAULT_CONNINFO = 'host=127.0.0.1 port=5432 user=pyo password=pyo123 dbname=mirror'


def main() -> None:
    conninfo = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.environ.get('MIRROR_PG', _DEFAULT_CONNINFO)
    )
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1521
    logging.basicConfig(
        level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s'
    )
    log = logging.getLogger('mirror')

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', port))
    server.listen(5)
    log.info('Mirror over PostgreSQL listening on 127.0.0.1:%d', port)

    def handle(client: socket.socket) -> None:
        # One PostgreSQL session per client connection.
        try:
            serve_session(PacketStream(client), _CREDENTIALS, PostgresBackend(conninfo))
        except Exception:
            log.exception('session error')
        finally:
            client.close()

    try:
        while True:
            client, addr = server.accept()
            log.info('connection from %s:%d', *addr)
            threading.Thread(target=handle, args=(client,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()


if __name__ == '__main__':
    main()
