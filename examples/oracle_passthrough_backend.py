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

import re
from collections.abc import Sequence
from dataclasses import replace

import seerdb
from seerdb.common.datatypes import dbtype_for_oracle_type
from seerdb.common.tns import AL16UTF16_CHARSET, ColumnMeta
from seerdb.common.tns_consts import TNS_TYPE_REF, TNS_TYPE_REFCURSOR
from seerdb.server.backend import BackendError, BindVar, CursorResult, Result


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
        # Held by reference (not copied) so a changepassword updates the same map
        # every session's backend authenticates against — a fresh connection then
        # sees the new password (#21/#486). Keys are upper-cased in place.
        self._credentials = credentials
        for name in list(self._credentials):
            if name != name.upper():
                self._credentials[name.upper()] = self._credentials.pop(name)
        self._conn = None

    def authenticate(self, username: str) -> str | None:
        password = self._credentials.get(username.upper())
        if password is None:
            return None
        # Open the upstream connection now, with the same credentials, so the
        # session is ready by the time the client runs its first statement.
        # autocommit=False so the client drives the upstream transaction through
        # the Mirror: an explicit commit / rollback reaches the backend, and an
        # autocommit client still commits because the Mirror calls backend.commit()
        # per statement. With the driver default (autocommit=True) every statement
        # would commit upstream and a client rollback would be a no-op.
        self._conn = seerdb.connect(
            host=self._host,
            port=self._port,
            user=username,
            password=password,
            service_name=self._service,
            autocommit=False,
        )
        return password

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        cursor = self._conn.cursor()
        # A PL/SQL block hands its binds over as BindVar (value + type + buffer
        # size) so OUT binds can be registered correctly (#483). Bind each as an
        # OUT-capable Var seeded with the input value, run, and return every Var's
        # value; the Mirror marks them OUT and the client keeps its own positions.
        if any(isinstance(b, BindVar) for b in binds):
            return self._execute_plsql(cursor, sql, binds)
        try:
            cursor.execute(sql, list(binds))
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc
        if cursor.description:
            columns = [_to_column_meta(desc) for desc in cursor.description]
            rows = cursor.fetchall()
            columns = _enrich_ref_columns(columns, rows)
            return Result(columns=columns, rows=rows)
        return Result(rowcount=cursor.rowcount or 0)

    def execute_many(self, sql: str, rows: Sequence[Sequence]) -> int:
        # Array DML (executemany): send the whole batch upstream in one round-trip
        # through seerdb's own cursor.executemany — one parse, len(rows) iterations
        # — instead of the Mirror's per-row fallback (one upstream round-trip per
        # bind row, which paid the network latency once per row). Returns the total
        # affected-row count. The Mirror calls this only for the non-batcherrors
        # path, where an upstream failure aborts the whole batch — exactly Oracle's
        # own non-batcherrors semantics.
        assert self._conn is not None  # authenticate() ran before any execute
        cursor = self._conn.cursor()
        try:
            cursor.executemany(sql, [list(row) for row in rows])
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc
        return cursor.rowcount or 0

    def execute_many_rowcounts(
        self, sql: str, rows: Sequence[Sequence]
    ) -> tuple[int, list[int]]:
        # Array DML with the per-iteration affected-row counts (arraydmlrowcounts,
        # #18): run the batch upstream asking for them, and return the total plus
        # the count list the client reads back through getarraydmlrowcounts().
        assert self._conn is not None  # authenticate() ran before any execute
        cursor = self._conn.cursor()
        try:
            cursor.executemany(sql, [list(row) for row in rows], arraydmlrowcounts=True)
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc
        return cursor.rowcount or 0, list(cursor.getarraydmlrowcounts())

    def _execute_plsql(self, cursor, sql: str, binds: Sequence) -> Result:
        variables = []
        for bind in binds:
            dbtype = dbtype_for_oracle_type(bind.tns_type, 1)
            if bind.tns_type == TNS_TYPE_REFCURSOR:
                # A REF CURSOR OUT param: the DB opens the cursor, so bind a
                # cursor var and don't seed it.
                var = cursor.var(seerdb.DB_TYPE_CURSOR)
            else:
                size = bind.max_size if bind.max_size and bind.max_size > 0 else None
                var = (
                    cursor.var(dbtype, size) if dbtype is not None else cursor.var(str)
                )
                if bind.value is not None:
                    var.setvalue(0, bind.value)
            variables.append(var)
        try:
            cursor.execute(sql, variables)
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc
        return Result(out_binds=[_out_value(var.getvalue()) for var in variables])

    def change_password(
        self, username: str, old_password: str, new_password: str
    ) -> None:
        # ALTER USER ... REPLACE validates the old password and sets the new one
        # on the real Oracle; the live upstream session stays authenticated. Then
        # update the shared credential map so a fresh Mirror session authenticates
        # (O5LOGON) with the new password and the old one is rejected (#21/#486).
        cursor = self._conn.cursor()
        quoted = new_password.replace('"', '""')
        old_quoted = old_password.replace('"', '""')
        try:
            cursor.execute(
                f'ALTER USER {username} IDENTIFIED BY "{quoted}" REPLACE "{old_quoted}"'
            )
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc
        self._credentials[username.upper()] = new_password

    # The client's attribute names for the end-to-end tracing slots the Mirror
    # hands over; client_info is spelled clientinfo on the connection.
    _END_TO_END_ATTR = {'client_info': 'clientinfo'}

    def set_end_to_end(self, attrs: dict[str, str | None]) -> None:
        # Apply the session's end-to-end tracing attributes (module, action,
        # client_identifier, client_info, dbop) to the upstream connection, so
        # SYS_CONTEXT('USERENV', …) on the real Oracle reflects what the client
        # set through the Mirror. An upstream below 12.1 has no way to carry them
        # (the client raises NotSupportedError); that is a limit of the upstream,
        # not a Mirror failure, so it is ignored.
        assert self._conn is not None  # authenticate() ran before any call
        for name, value in attrs.items():
            try:
                setattr(self._conn, self._END_TO_END_ATTR.get(name, name), value)
            except seerdb.NotSupportedError:
                return

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


# Oracle's own error text already begins with "ORA-NNNNN: "; the Mirror
# (BackendError) re-adds that prefix from the code, so relaying str(exc) verbatim
# doubles it ("ORA-00904: ORA-00904: ..."). Strip the leading prefix and take the
# code from it (falling back to exc.code, then ORA-00900) so the Mirror emits
# exactly one, matching a real server.
_ORA_PREFIX = re.compile(r'^ORA-(\d{5}):\s*')


def _relay_error(exc: 'seerdb.DatabaseError') -> BackendError:
    text = str(exc)
    match = _ORA_PREFIX.match(text)
    code = getattr(exc, 'code', None)
    if code is None and match is not None:
        code = int(match.group(1))
    if match is not None:
        text = text[match.end() :]
    # Relay the parse offset (oracledb's DatabaseError.offset) so the Mirror draws
    # the error caret under the same column the real server flagged.
    return BackendError(
        text, ora_code=code or 900, error_offset=getattr(exc, 'offset', None)
    )


def _enrich_ref_columns(columns: list, rows: list) -> list:
    # A REF column's type identity (type_name / schema / OID) is not in the
    # PEP-249 description — only in the DbRef values — so copy it from the first
    # non-null value into the ColumnMeta the describe carries (#494).
    out = list(columns)
    for idx, col in enumerate(out):
        if col.data_type != TNS_TYPE_REF:
            continue
        for row in rows:
            ref = row[idx]
            if ref is not None and hasattr(ref, 'type_name'):
                out[idx] = replace(
                    col,
                    type_name=(ref.type_name or '').encode('ascii'),
                    type_schema=(ref.type_schema or '').encode('ascii'),
                    type_oid=getattr(ref, 'type_oid', b'') or b'',
                )
                break
    return out


def _out_value(value: object) -> object:
    # A REF CURSOR OUT param resolves to a nested cursor; drain its describe +
    # rows into a CursorResult the Mirror can park and hand back. Any other OUT
    # value is a plain scalar the Mirror encodes by the bind's declared type.
    if hasattr(value, 'description') and hasattr(value, 'fetchall'):
        columns = [_to_column_meta(desc) for desc in value.description]
        return CursorResult(columns=columns, rows=value.fetchall())
    return value


def _to_column_meta(desc: tuple) -> ColumnMeta:
    # PEP-249 description tuple: (name, type_code, display_size, internal_size,
    # precision, scale, null_ok). type_code is a seerdb DB_TYPE carrying the raw
    # wire tns_type; the sizes give the declared/buffer length.
    name, type_code, display_size, internal_size, precision, scale, null_ok = desc
    tns_type = getattr(type_code, 'tns_type', type_code)
    csfrm = getattr(type_code, 'csfrm', 1)
    byte_size = internal_size or display_size or 0
    if csfrm == 2:
        # National char (NCHAR / NVARCHAR2): UTF-16BE in AL16UTF16. data_length is
        # the byte buffer (internal_size), max_size the declared character length.
        data_length, max_size = byte_size, (display_size or byte_size)
        charset = AL16UTF16_CHARSET
    else:
        data_length = max_size = byte_size
        charset = ColumnMeta.charset
    return ColumnMeta(
        name=name.encode('utf-8'),
        data_type=int(tns_type),
        data_length=data_length,
        max_size=max_size,
        precision=precision or 0,
        scale=scale or 0,
        charset=charset,
        csfrm=csfrm,
        null_ok=int(bool(null_ok)),
    )
