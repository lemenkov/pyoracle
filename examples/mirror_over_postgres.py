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
import sys

from oracle_compat_backend import OracleCompatBackend
from postgres_backend import PostgresBackend

import seerdb

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
    # One shared credential map across every session's backend, so a
    # changepassword on one connection is visible to the next (#515).
    credentials = {'PYO': 'pyo123'}
    # One PostgreSQL session per client connection, behind the OracleCompatBackend
    # so a real sqlplus can bootstrap its session (thin clients pass through).
    seerdb.serve(
        '127.0.0.1',
        port,
        backend_factory=lambda: OracleCompatBackend(
            PostgresBackend(conninfo, credentials=credentials)
        ),
    )


if __name__ == '__main__':
    main()
