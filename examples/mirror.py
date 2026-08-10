# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Run a Mirror from a config file — the whole thing in one command.

    python examples/mirror.py examples/mirror.example.ini

The config declares (a) the Oracle-client logins the Mirror accepts and (b) the
backend it puts them in front of. Any Oracle client — seerdb, python-oracledb,
SeerODBC — can then connect to the listening port and run real SQL against the
backend, thinking it reached Oracle.

The format here (INI, via the stdlib ``configparser``) is this example's choice,
not the library's: ``seerdb`` core exposes ``seerdb.serve`` and the backend's
``authenticate`` hook and dictates no config format. INI keeps it dependency-free
(no Python version dropped for a TOML parser).

    [server]
    host = 127.0.0.1
    port = 1521

    [clients]           ; Oracle logins the Mirror accepts (O5LOGON secrets)
    PYO = pyo123

    [backend]           ; the data source behind the Mirror
    type = sqlite       ; sqlite | postgres
    database = :memory: ; sqlite: a path or :memory:
    ; conninfo = host=... port=... user=... password=... dbname=...   ; postgres
"""

from __future__ import annotations

import configparser
import sys
from collections.abc import Callable

import seerdb
from seerdb.server import Backend

BackendFactory = Callable[[], Backend]


def _backend_factory(
    section: configparser.SectionProxy, credentials: dict
) -> BackendFactory:
    # Build a per-session backend factory from the [backend] section. Backend
    # modules are imported lazily by type, so the sqlite path needs no psycopg.
    kind = section.get('type', '').strip().lower()
    if kind == 'sqlite':
        from sqlite_backend import SqliteBackend

        database = section.get('database', ':memory:')
        return lambda: SqliteBackend(database, credentials=credentials)
    if kind == 'postgres':
        from postgres_backend import PostgresBackend

        conninfo = section.get('conninfo', '')
        return lambda: PostgresBackend(conninfo, credentials=credentials)
    raise ValueError(f"unknown backend type {kind!r} (expected 'sqlite' or 'postgres')")


def load_config(path: str) -> tuple[str, int, BackendFactory]:
    """Parse a Mirror config file into ``(host, port, backend_factory)``.

    Raises :class:`FileNotFoundError` if the file is missing and
    :class:`ValueError` for a missing/unknown backend.
    """
    # interpolation=None so a libpq conninfo with '%' or '=' is taken verbatim.
    parser = configparser.ConfigParser(interpolation=None)
    if not parser.read(path):
        raise FileNotFoundError(path)
    host = parser.get('server', 'host', fallback='127.0.0.1')
    port = parser.getint('server', 'port', fallback=1521)
    credentials = dict(parser['clients']) if parser.has_section('clients') else {}
    if not parser.has_section('backend'):
        raise ValueError('config is missing a [backend] section')
    return host, port, _backend_factory(parser['backend'], credentials)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print('usage: python examples/mirror.py <config.ini>', file=sys.stderr)
        return 2
    host, port, backend_factory = load_config(argv[0])
    print(f'Mirror listening on {host}:{port} — connect any Oracle client')
    seerdb.serve(host, port, backend_factory=backend_factory)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
