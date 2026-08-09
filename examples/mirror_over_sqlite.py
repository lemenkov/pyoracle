# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Run a Mirror backed by SQLite — Oracle clients, a SQLite database.

    python examples/mirror_over_sqlite.py [DB] [PORT]

Defaults: a shared file ``/tmp/mirror.db`` (data persists across connections)
on port 1521. Pass ``:memory:`` for a fresh isolated database per connection.

Then point any thin-dialect Oracle client at ``127.0.0.1:PORT`` as
``PYO`` / ``pyo123`` (service ``XE``) and run SQL, e.g. with seerdb:

    import seerdb
    c = seerdb.connect(host='127.0.0.1', port=1521, user='PYO',
                       password='pyo123', service_name='XE')
    cur = c.cursor()
    cur.execute('create table t (id number, name varchar2(20))')
    cur.execute("insert into t values (1, 'alice')")
    cur.execute('select * from t')
    print(cur.fetchall())            # -> [(1, 'alice')]
"""

from __future__ import annotations

import logging
import socket
import sys
import threading

from sqlite_backend import SqliteBackend

from seerdb.server import PacketStream, serve_session

_CREDENTIALS = {'PYO': 'pyo123'}


def main() -> None:
    database = sys.argv[1] if len(sys.argv) > 1 else '/tmp/mirror.db'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1521
    logging.basicConfig(
        level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s'
    )
    log = logging.getLogger('mirror')

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', port))
    server.listen(5)
    log.info('Mirror over SQLite %r listening on 127.0.0.1:%d', database, port)

    def handle(client: socket.socket) -> None:
        # One SQLite session per client connection (thread-affine).
        try:
            serve_session(PacketStream(client), _CREDENTIALS, SqliteBackend(database))
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
