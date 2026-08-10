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
import sys

from sqlite_backend import SqliteBackend

import seerdb


def main() -> None:
    database = sys.argv[1] if len(sys.argv) > 1 else '/tmp/mirror.db'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1521
    logging.basicConfig(
        level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s'
    )
    # A fresh SQLite session per client connection (sqlite3 objects are
    # thread-affine, so the backend must be built inside its own session).
    seerdb.serve(
        '127.0.0.1',
        port,
        backend_factory=lambda: SqliteBackend(database, credentials={'PYO': 'pyo123'}),
    )


if __name__ == '__main__':
    main()
