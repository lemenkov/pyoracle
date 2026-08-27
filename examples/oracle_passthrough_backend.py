# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A Mirror backend that relays to a real Oracle database via seerdb thin.

Turns the Mirror into a transparent Oracle-to-Oracle relay: a client speaks to
the Mirror, the Mirror runs each statement on a real Oracle and returns the real
results. Its purpose is conformance testing — running the integration suite
against the Mirror so that any failure isolates a *Mirror protocol* gap rather
than a backend SQL-dialect limitation (which is what the SQLite backend hits).

One backend (and one upstream Oracle connection) per Mirror session; the
credential map supplies the O5LOGON secret the Mirror needs to authenticate the
client, and the same credentials open the upstream connection.
"""

from __future__ import annotations

from collections.abc import Sequence

import seerdb
from seerdb.server.backend import BackendError, Result
from seerdb.server.query import ColumnMeta


class OraclePassthroughBackend:
    """Relays statements to a real Oracle at ``(host, port, service)``."""

    capabilities = frozenset()

    def __init__(
        self,
        *,
        host: str,
        port: int,
        service: str,
        credentials: dict[str, str],
    ) -> None:
        self._host = host
        self._port = port
        self._service = service
        self._credentials = {u.upper(): p for u, p in credentials.items()}
        self._conn = None

    def authenticate(self, username: str) -> str | None:
        password = self._credentials.get(username.upper())
        if password is None:
            return None
        # Open the upstream connection now, with the same credentials, so the
        # session is ready by the time the client runs its first statement.
        self._conn = seerdb.connect(
            host=self._host,
            port=self._port,
            user=username,
            password=password,
            service_name=self._service,
        )
        return password

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        cursor = self._conn.cursor()
        try:
            cursor.execute(sql, list(binds))
        except seerdb.DatabaseError as exc:
            code = getattr(exc, 'code', None) or 900
            raise BackendError(str(exc), ora_code=code) from exc
        if cursor.description:
            columns = [_to_column_meta(desc) for desc in cursor.description]
            rows = cursor.fetchall()
            return Result(columns=columns, rows=rows)
        return Result(rowcount=cursor.rowcount or 0)

    def commit(self) -> None:
        if self._conn is not None:
            self._conn.commit()

    def rollback(self) -> None:
        if self._conn is not None:
            self._conn.rollback()

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None


def _to_column_meta(desc: tuple) -> ColumnMeta:
    # PEP-249 description tuple: (name, type_code, display_size, internal_size,
    # precision, scale, null_ok). type_code is a seerdb DB_TYPE carrying the raw
    # wire tns_type; the sizes give the declared/buffer length.
    name, type_code, display_size, internal_size, precision, scale, null_ok = desc
    tns_type = getattr(type_code, 'tns_type', type_code)
    size = internal_size or display_size or 0
    return ColumnMeta(
        name=name.encode('utf-8'),
        data_type=int(tns_type),
        data_length=size,
        max_size=size,
        precision=precision or 0,
        scale=scale or 0,
        null_ok=int(bool(null_ok)),
    )
