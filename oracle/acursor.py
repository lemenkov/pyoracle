# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Async PEP 249-style cursor. Mirrors `oracle.cursor.Cursor` but with
`async def` for every method that touches the wire."""

from oracle.cursor import (
    _assign_out_binds,
    _col_annotations,
    _check_object_bind_support,
    _column_description,
    _is_plsql,
    _resolve_parameters,
)
from oracle.datatypes import TempLob, Var
from oracle.exceptions import (
    DatabaseError, InterfaceError, NotSupportedError, ProgrammingError,
    from_ora_code,
)
from oracle.tns_consts import AL32UTF8_CHARSET, FIELD_VERSION_12_1


class AsyncCursor:
    """Async equivalent of `oracle.cursor.Cursor`.

    Result-set handling is the same: the rows the server sends back in
    the EXEC / FETCH response are buffered locally, and fetchone /
    fetchmany / fetchall walk the buffer. `async for` iteration and
    `async with` context manager are both supported.
    """

    arraysize: int = 1

    def __init__(self, connection):
        self._connection = connection
        self._description: list[tuple] | None = None
        self._annotations: list[dict | None] | None = None
        self._rows: list[list] = []
        self._row_index: int = 0
        self._rowcount: int = -1
        self._closed: bool = False
        self._lastrowid = None
        self._rowfactory = None

    def _check_open(self) -> None:
        if self._closed:
            raise InterfaceError("cursor is closed")
        if self._connection is None or self._connection._writer is None:
            raise InterfaceError("connection is closed")

    @property
    def description(self) -> list[tuple] | None:
        return self._description

    @property
    def annotations(self) -> list[dict | None] | None:
        """Per-column SQL annotations (23ai) for the last SELECT, aligned with
        `description`. See `oracle.cursor.Cursor.annotations`."""
        return self._annotations

    @property
    def rowcount(self) -> int:
        return self._rowcount

    @property
    def connection(self):
        return self._connection

    @property
    def rowfactory(self):
        """Optional callable applied to each fetched row. See
        `oracle.cursor.Cursor.rowfactory`."""
        return self._rowfactory

    @rowfactory.setter
    def rowfactory(self, value) -> None:
        self._rowfactory = value

    @property
    def lastrowid(self):
        """ROWID of the last row an INSERT / UPDATE / DELETE touched. See
        `oracle.cursor.Cursor.lastrowid`."""
        return self._lastrowid

    async def close(self) -> None:
        self._closed = True
        self._description = None
        self._annotations = None
        self._rows = []
        self._row_index = 0

    async def execute(self, operation: str, parameters=None) -> 'AsyncCursor':
        self._check_open()
        Bind = _resolve_parameters(operation, parameters)
        Bind = await self._promote_large_lob_binds(operation, Bind)
        return await self._run(operation, Bind)

    async def _promote_large_lob_binds(self, operation: str,
                                       Bind: list) -> list:
        """Async port of `Cursor._promote_large_lob_binds` (#91): stream a
        > 32767-byte CLOB / BLOB bind for a PL/SQL block into a server temp LOB
        and bind the locator, sidestepping ORA-01460. 12c+ / PL/SQL only."""
        Conn = self._connection
        if (getattr(Conn, 'field_version', 0) < FIELD_VERSION_12_1
                or not _is_plsql(operation) or not Bind):
            return Bind
        Promoted = []
        for Value in Bind:
            if isinstance(Value, str) and len(Value.encode('utf-8')) > 32767:
                Locator = await Conn.create_temp_lob()
                await Conn.write_temp_lob(Locator, Value)
                Promoted.append(TempLob(Locator, False, len(Value) * 4))
            elif (isinstance(Value, (bytes, bytearray))
                    and len(Value) > 32767):
                Locator = await Conn.create_temp_lob(is_blob=True)
                await Conn.write_temp_lob(Locator, bytes(Value), is_blob=True)
                Promoted.append(TempLob(Locator, True, len(Value)))
            else:
                Promoted.append(Value)
        return Promoted

    async def _run(self, operation: str, Bind: list,
                   Batch: list | None = None, BatchErrors: bool = False,
                   ArrayDmlRowCounts: bool = False) -> 'AsyncCursor':
        _check_object_bind_support(self._connection, Bind, Batch)
        Result = await self._connection.execute(
            operation, Bind=Bind, Batch=Batch, BatchErrors=BatchErrors,
            ArrayDmlRowCounts=ArrayDmlRowCounts)
        try:
            OraCode = Result[1]
            RetFormat = Result[3]
            Rows = Result[4]
            Message = Result[5] if len(Result) > 5 else None
            LastRowid = Result[6] if len(Result) > 6 else None
        except (TypeError, IndexError, ValueError) as exc:
            raise DatabaseError(f"unexpected wire response: {Result!r}") from exc

        # Array-DML batch errors (#18): each entry is {offset, code, message}.
        self._batcherrors = list(Result[7]) if len(Result) > 7 else []
        # Array-DML per-iteration row counts (#18): list of ints, one per row.
        self._arraydmlrowcounts = (
            list(Result[8]) if len(Result) > 8 and Result[8] else [])

        # ORA-24381 ("error(s) in array DML") is the non-fatal summary the
        # server returns when batcherrors collected per-row failures — surface
        # them through getbatcherrors() instead of raising (mirrors sync _run).
        NonFatal = (0, 1403, 24381) if BatchErrors else (0, 1403)
        if OraCode not in NonFatal:
            Detail = Message or f"ORA-{OraCode:05d}"
            raise from_ora_code(OraCode)(Detail, code=OraCode)

        # PL/SQL OUT / IN OUT binds: scalars are assigned here; REF CURSOR OUT
        # binds are fetched (async) and wrapped in a nested AsyncCursor.
        for Variable, Marker in _assign_out_binds(Bind, Result):
            Rows = await self._connection.fetch_all_rows(
                Marker['cursor_id'], Marker['row_format'])
            Variable._value = await self._build_refcursor(Rows, Marker)

        ServerRowCount = None
        ColMeta = None
        if isinstance(RetFormat, tuple) and len(RetFormat) >= 2:
            ServerRowCount = RetFormat[0]
            if isinstance(RetFormat[1], list):
                ColMeta = RetFormat[1]

        if ColMeta:
            # SELECT result set: clear lastrowid (see sync Cursor._run).
            self._lastrowid = None
            self._description = [_column_description(C) for C in ColMeta]
            self._annotations = [_col_annotations(C) for C in ColMeta]
            # Async LOB auto-resolve: same shape as sync `_resolve_lobs`
            # but each `LOB.aread()` is awaited individually. CLOB → str,
            # BLOB / BFILE → bytes, NULL LOBs stay as None (already
            # filtered out at the row-decoder level).
            from oracle.lob import LOB
            from oracle.dbobject import (ObjectImage, DbObject,
                                         decode_object_image,
                                         decode_collection_image)
            ResolvedRows = []
            for Row in (Rows or []):
                NewRow = list(Row)
                for I, Val in enumerate(NewRow):
                    if isinstance(Val, LOB):
                        Val._connection = self._connection
                        NewRow[I] = await Val.aread()
                    elif isinstance(Val, ObjectImage):
                        # Object / collection auto-resolve (#115/#117): fetch the
                        # type (awaited; cached on the connection) and walk the
                        # packed image into a DbObject or a list-collection.
                        Typ = await self._connection._describe_object_type(
                            Val.type_schema, Val.type_name)
                        Charset = Val.charset or AL32UTF8_CHARSET
                        if Typ is not None and Typ.is_collection:
                            Elements = decode_collection_image(
                                Val.image, Typ.element or {}, Charset)
                            NewRow[I] = DbObject(Val.type_name,
                                                 elements=Elements, dbtype=Typ)
                        else:
                            Layout = Typ.attrs if Typ is not None else []
                            Attrs = decode_object_image(Val.image, Layout, Charset)
                            NewRow[I] = DbObject(Val.type_name, Attrs, dbtype=Typ)
                ResolvedRows.append(NewRow)
            self._rows = ResolvedRows
            self._rowcount = len(self._rows)
        else:
            self._lastrowid = LastRowid
            self._description = None
            self._annotations = None
            self._rows = []
            self._rowcount = ServerRowCount if isinstance(ServerRowCount, int) else -1

        self._row_index = 0
        return self

    async def _build_refcursor(self, Rows, Marker) -> 'AsyncCursor':
        # Wrap an already-fetched REF CURSOR result set in a nested AsyncCursor,
        # resolving any LOB cells with await (mirrors AsyncCursor.execute).
        from oracle.lob import LOB
        Nested = AsyncCursor(self._connection)
        Nested._description = [_column_description(C)
                               for C in Marker['row_format']]
        Nested._annotations = [_col_annotations(C)
                               for C in Marker['row_format']]
        Resolved = []
        for Row in Rows:
            NewRow = list(Row)
            for I, Val in enumerate(NewRow):
                if isinstance(Val, LOB):
                    Val._connection = self._connection
                    NewRow[I] = await Val.aread()
            Resolved.append(NewRow)
        Nested._rows = Resolved
        Nested._rowcount = len(Resolved)
        Nested._row_index = 0
        return Nested

    def var(self, typ, size=None) -> Var:
        """Create a bind variable for an OUT / IN OUT argument. See
        `oracle.cursor.Cursor.var`."""
        return Var(typ, size)

    async def callproc(self, name: str, parameters=None) -> list:
        """Call a stored procedure. `parameters` is a positional list of plain
        values (IN) and `Var` objects (OUT / IN OUT). Returns the list with
        each `Var` replaced by its returned value."""
        self._check_open()
        Params = list(parameters) if parameters else []
        Placeholders = ', '.join(f':{I + 1}' for I in range(len(Params)))
        await self.execute(f"BEGIN {name}({Placeholders}); END;", Params)
        return [P.getvalue() if isinstance(P, Var) else P for P in Params]

    async def callfunc(self, name: str, return_type, parameters=None):
        """Call a stored function and return its value. See
        `oracle.cursor.Cursor.callfunc`."""
        self._check_open()
        Ret = Var(return_type)
        Params = list(parameters) if parameters else []
        Args = ', '.join(f':{I + 2}' for I in range(len(Params)))
        await self.execute(f"BEGIN :1 := {name}({Args}); END;", [Ret] + Params)
        return Ret.getvalue()

    async def executemany(self, operation: str, seq_of_parameters,
                          batcherrors: bool = False,
                          arraydmlrowcounts: bool = False) -> 'AsyncCursor':
        # Array DML in a single round trip; see Cursor.executemany. The
        # batcherrors / arraydmlrowcounts refinements behave exactly as the sync
        # cursor's (#18): batch-error collection via getbatcherrors(), and
        # per-iteration row counts (12.1+ only) via getarraydmlrowcounts().
        self._check_open()
        if arraydmlrowcounts \
                and self._connection.field_version < FIELD_VERSION_12_1:
            raise NotSupportedError(
                "arraydmlrowcounts requires an Oracle 12.1+ server")
        self._batcherrors = []
        self._arraydmlrowcounts = []
        Rows = [_resolve_parameters(operation, P) for P in seq_of_parameters]
        if not Rows:
            self._description = None
            self._rows = []
            self._rowcount = 0
            self._row_index = 0
            return self
        return await self._run(operation, Rows[0], Batch=Rows[1:],
                               BatchErrors=batcherrors,
                               ArrayDmlRowCounts=arraydmlrowcounts)

    def getbatcherrors(self) -> list:
        """Errors collected by the most recent
        ``executemany(batcherrors=True)``. See
        `oracle.cursor.Cursor.getbatcherrors`."""
        Out = []
        for E in getattr(self, '_batcherrors', []):
            Code = E.get('code')
            Exc = from_ora_code(Code)(E.get('message') or f"ORA-{Code:05d}",
                                      code=Code)
            Exc.offset = E.get('offset')
            Out.append(Exc)
        return Out

    def getarraydmlrowcounts(self) -> list:
        """Per-iteration row counts from the most recent
        ``executemany(arraydmlrowcounts=True)``. See
        `oracle.cursor.Cursor.getarraydmlrowcounts`."""
        return list(getattr(self, '_arraydmlrowcounts', []))

    async def fetchone(self) -> tuple | None:
        self._check_open()
        if self._description is None:
            raise InterfaceError("no result set; call execute() with a SELECT first")
        if self._row_index >= len(self._rows):
            return None
        Row = self._rows[self._row_index]
        self._row_index += 1
        if self._rowfactory is not None:
            return self._rowfactory(*Row)
        return tuple(Row)

    async def fetchmany(self, size: int | None = None) -> list[tuple]:
        if size is None:
            size = self.arraysize
        Out = []
        for _ in range(max(size, 0)):
            Row = await self.fetchone()
            if Row is None:
                break
            Out.append(Row)
        return Out

    async def fetchall(self) -> list[tuple]:
        Out = []
        while True:
            Row = await self.fetchone()
            if Row is None:
                break
            Out.append(Row)
        return Out

    async def scroll(self, value: int = 0, mode: str = "relative") -> None:
        """Scroll the result-set cursor to a new position. See
        `oracle.cursor.Cursor.scroll`. The reposition is local (the whole
        result set is buffered on execute), so this awaits nothing on the wire
        but stays `async def` for API symmetry."""
        self._check_open()
        if self._description is None:
            raise InterfaceError("no result set; call execute() with a SELECT first")
        Count = len(self._rows)
        if mode == "relative":
            Target = self._row_index + value
        elif mode == "absolute":
            Target = value
        elif mode == "first":
            Target = 1
        elif mode == "last":
            Target = Count
        else:
            raise ProgrammingError(f"invalid scroll mode: {mode!r}")
        if Target < 1 or Target > Count:
            raise IndexError("scroll operation would leave the result set")
        self._row_index = Target - 1

    def setinputsizes(self, sizes) -> None:
        pass

    def setoutputsize(self, size, column=None) -> None:
        pass

    # ----- async iteration -----

    def __aiter__(self):
        return self

    async def __anext__(self):
        Row = await self.fetchone()
        if Row is None:
            raise StopAsyncIteration
        return Row

    # ----- async context manager -----

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()
