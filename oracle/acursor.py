# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Async PEP 249-style cursor. Mirrors `oracle.cursor.Cursor` but with
`async def` for every method that touches the wire."""

from oracle.cursor import (
    _assign_out_binds,
    _column_description,
    _resolve_parameters,
)
from oracle.datatypes import Var
from oracle.exceptions import (
    DatabaseError, InterfaceError, from_ora_code,
)


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
        self._rows = []
        self._row_index = 0

    async def execute(self, operation: str, parameters=None) -> 'AsyncCursor':
        self._check_open()
        Bind = _resolve_parameters(operation, parameters)
        return await self._run(operation, Bind)

    async def _run(self, operation: str, Bind: list,
                   Batch: list | None = None) -> 'AsyncCursor':
        Result = await self._connection.execute(operation, Bind=Bind, Batch=Batch)
        try:
            CallStatus = Result[0]
            OraCode = Result[1]
            RetFormat = Result[3]
            Rows = Result[4]
            Message = Result[5] if len(Result) > 5 else None
            LastRowid = Result[6] if len(Result) > 6 else None
        except (TypeError, IndexError, ValueError) as exc:
            raise DatabaseError(f"unexpected wire response: {Result!r}") from exc

        if OraCode not in (0, 1403):
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
            # Async LOB auto-resolve: same shape as sync `_resolve_lobs`
            # but each `LOB.aread()` is awaited individually. CLOB → str,
            # BLOB / BFILE → bytes, NULL LOBs stay as None (already
            # filtered out at the row-decoder level).
            from oracle.lob import LOB
            ResolvedRows = []
            for Row in (Rows or []):
                NewRow = list(Row)
                for I, Val in enumerate(NewRow):
                    if isinstance(Val, LOB):
                        Val._connection = self._connection
                        NewRow[I] = await Val.aread()
                ResolvedRows.append(NewRow)
            self._rows = ResolvedRows
            self._rowcount = len(self._rows)
        else:
            self._lastrowid = LastRowid
            self._description = None
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

    async def executemany(self, operation: str, seq_of_parameters) -> 'AsyncCursor':
        # Array DML in a single round trip; see Cursor.executemany.
        self._check_open()
        Rows = [_resolve_parameters(operation, P) for P in seq_of_parameters]
        if not Rows:
            self._description = None
            self._rows = []
            self._rowcount = 0
            self._row_index = 0
            return self
        return await self._run(operation, Rows[0], Batch=Rows[1:])

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
