# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Async PEP 249-style cursor. Mirrors `oracle.cursor.Cursor` but with
`async def` for every method that touches the wire."""

from oracle.cursor import (
    _column_description,
    _resolve_parameters,
)
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

    async def close(self) -> None:
        self._closed = True
        self._description = None
        self._rows = []
        self._row_index = 0

    async def execute(self, operation: str, parameters=None) -> 'AsyncCursor':
        self._check_open()
        Bind = _resolve_parameters(operation, parameters)
        Result = await self._connection.execute(operation, Bind=Bind)
        try:
            CallStatus = Result[0]
            OraCode = Result[1]
            RetFormat = Result[3]
            Rows = Result[4]
            Message = Result[5] if len(Result) > 5 else None
        except (TypeError, IndexError, ValueError) as exc:
            raise DatabaseError(f"unexpected wire response: {Result!r}") from exc

        if OraCode not in (0, 1403):
            Detail = Message or f"ORA-{OraCode:05d}"
            raise from_ora_code(OraCode)(Detail, code=OraCode)

        ServerRowCount = None
        ColMeta = None
        if isinstance(RetFormat, tuple) and len(RetFormat) >= 2:
            ServerRowCount = RetFormat[0]
            if isinstance(RetFormat[1], list):
                ColMeta = RetFormat[1]

        if ColMeta:
            self._description = [_column_description(C) for C in ColMeta]
            # LOB auto-resolve needs to be async-aware. For the first cut
            # we hand back the raw `oracle.lob.LOB` objects; the user can
            # `await lob.aread()` (see #76) once that lands. NULL LOBs
            # already arrive as Python None from the row decoder.
            self._rows = [list(row) for row in (Rows or [])]
            self._rowcount = len(self._rows)
        else:
            self._description = None
            self._rows = []
            self._rowcount = ServerRowCount if isinstance(ServerRowCount, int) else -1

        self._row_index = 0
        return self

    async def executemany(self, operation: str, seq_of_parameters) -> 'AsyncCursor':
        self._check_open()
        Total = 0
        for Params in seq_of_parameters:
            await self.execute(operation, Params)
            if self._rowcount > 0:
                Total += self._rowcount
        if Total > 0:
            self._rowcount = Total
        return self

    async def fetchone(self) -> tuple | None:
        self._check_open()
        if self._description is None:
            raise InterfaceError("no result set; call execute() with a SELECT first")
        if self._row_index >= len(self._rows):
            return None
        Row = self._rows[self._row_index]
        self._row_index += 1
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
