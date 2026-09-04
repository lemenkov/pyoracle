# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Async PEP 249-style cursor. Mirrors `seerdb.client.cursor.Cursor` but with
`async def` for every method that touches the wire."""

from typing import Any

from seerdb.client._cursor_logic import _CursorLogic
from seerdb.client.cursor import (
    _assign_out_binds,
    _assign_return_binds,
    _check_object_bind_support,
    _col_annotations,
    _column_description,
    _extract_implicit_results,
    _is_plsql,
    _resolve_parameters,
)
from seerdb.common.datatypes import TempLob, Var
from seerdb.common.exceptions import (
    DatabaseError,
    InterfaceError,
    NotSupportedError,
    ProgrammingError,
    from_ora_code,
)
from seerdb.common.sqltext import returning_bind_positions
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    FIELD_VERSION_10_2,
    FIELD_VERSION_12_1,
)


class AsyncCursor(_CursorLogic):
    """Async equivalent of `seerdb.client.cursor.Cursor`.

    Result-set handling is the same: the rows the server sends back in
    the EXEC / FETCH response are buffered locally, and fetchone /
    fetchmany / fetchall walk the buffer. `async for` iteration and
    `async with` context manager are both supported.
    """

    def _check_open(self) -> None:
        if self._closed:
            raise InterfaceError('cursor is closed')
        if self._connection is None or self._connection._writer is None:
            raise InterfaceError('connection is closed')

    async def close(self) -> None:
        self._release_scroll_cursor()
        self._closed = True
        self._description = None
        self._annotations = None
        self._rows = []
        self._row_index = 0

    def _release_scroll_cursor(self) -> None:
        # Queue the kept-open scrollable cursor for close (#181); reuses the #191
        # close-piggyback queue so it rides the next call (no extra round trip).
        if self._scroll_active and self._scroll_cursor_id:
            Conn = self._connection
            if Conn is not None and getattr(Conn, '_writer', None) is not None:
                try:
                    Conn._cursors_to_close.append(self._scroll_cursor_id)
                except Exception:
                    # Best-effort cleanup (see sync Cursor._release_scroll_cursor):
                    # the server frees the cursor on session end regardless.
                    pass
        self._scroll_active = False
        self._scroll_cursor_id = 0

    async def execute(self, operation: str, parameters=None) -> 'AsyncCursor':
        self._check_open()
        self._release_scroll_cursor()  # free any prior scrollable cursor (#181)
        Bind = _resolve_parameters(operation, parameters)
        Bind = await self._promote_large_lob_binds(operation, Bind)
        return await self._run(operation, Bind)

    async def _promote_large_lob_binds(self, operation: str, Bind: list) -> list:
        """Async port of `Cursor._promote_large_lob_binds` (#91): stream a
        > 32767-byte CLOB / BLOB bind for a PL/SQL block into a server temp LOB
        and bind the locator, sidestepping ORA-01460. 12c+ / PL/SQL only."""
        Conn = self._connection
        if (
            getattr(Conn, 'field_version', 0) < FIELD_VERSION_12_1
            or not _is_plsql(operation)
            or not Bind
        ):
            return Bind
        Promoted = []
        for Value in Bind:
            if isinstance(Value, str) and len(Value.encode('utf-8')) > 32767:
                Locator = await Conn.create_temp_lob()
                await Conn.write_temp_lob(Locator, Value)
                Promoted.append(TempLob(Locator, False, len(Value) * 4))
            elif isinstance(Value, (bytes, bytearray)) and len(Value) > 32767:
                Locator = await Conn.create_temp_lob(is_blob=True)
                await Conn.write_temp_lob(Locator, bytes(Value), is_blob=True)
                Promoted.append(TempLob(Locator, True, len(Value)))
            else:
                Promoted.append(Value)
        return Promoted

    async def _run(
        self,
        operation: str,
        Bind: list,
        Batch: list | None = None,
        BatchErrors: bool = False,
        ArrayDmlRowCounts: bool = False,
    ) -> 'AsyncCursor':
        _check_object_bind_support(self._connection, Bind, Batch)
        Kw: dict[str, Any] = {
            'Bind': Bind,
            'Batch': Batch,
            'BatchErrors': BatchErrors,
            'ArrayDmlRowCounts': ArrayDmlRowCounts,
        }
        ReturnBinds = returning_bind_positions(operation, len(Bind or []))
        if ReturnBinds:  # DML RETURNING ... INTO (#120)
            Kw['ReturnBinds'] = ReturnBinds
        # Server-side scrollable open (#181), 10g+ only; 9i (fv2) falls back to
        # the buffered scroll (#161).
        if self._scrollable and self._connection.field_version >= FIELD_VERSION_10_2:
            Kw['scrollable'] = True
            Kw['Prefetch'] = max(int(self.prefetchrows), 1)
        Result = await self._connection.execute(operation, **Kw)
        return await self._apply_result(Bind, Result, BatchErrors=BatchErrors)

    async def _apply_result(
        self, Bind: list, Result, BatchErrors: bool = False
    ) -> 'AsyncCursor':
        # Interpret a decoded execute Result into this cursor (rows / rowcount /
        # OUT binds). Split out of _run (#158) so the request-pipelining wire
        # path can reuse the post-processing on a response it read out-of-band.
        try:
            OraCode = Result[1]
            RetFormat = Result[3]
            Rows = Result[4]
            Message = Result[5] if len(Result) > 5 else None
            LastRowid = Result[6] if len(Result) > 6 else None
            ErrorOffset = Result[9] if len(Result) > 9 else None
        except (TypeError, IndexError, ValueError) as exc:
            raise DatabaseError(f'unexpected wire response: {Result!r}') from exc

        # Array-DML batch errors (#18): each entry is {offset, code, message}.
        self._batcherrors = list(Result[7]) if len(Result) > 7 else []
        # Array-DML per-iteration row counts (#18): list of ints, one per row.
        self._arraydmlrowcounts = (
            list(Result[8]) if len(Result) > 8 and Result[8] else []
        )

        # ORA-24381 ("error(s) in array DML") is the non-fatal summary the
        # server returns when batcherrors collected per-row failures — surface
        # them through getbatcherrors() instead of raising (mirrors sync _run).
        NonFatal = (0, 1403, 24381) if BatchErrors else (0, 1403)
        if OraCode not in NonFatal:
            Detail = Message or f'ORA-{OraCode:05d}'
            Exc = from_ora_code(OraCode)(Detail, code=OraCode)
            # oracledb parity: the 0-based character offset of the error in the
            # statement text, for a parse/bind error (0 when the server reports none).
            Exc.offset = ErrorOffset
            raise Exc

        # PL/SQL OUT / IN OUT binds: scalars are assigned here; REF CURSOR OUT
        # binds are fetched (async) and wrapped in a nested AsyncCursor.
        for Variable, Marker in _assign_out_binds(Bind, Result):
            Rows = await self._connection.fetch_all_rows(
                Marker['cursor_id'], Marker['row_format']
            )
            Variable._value = await self._build_refcursor(Rows, Marker)

        # DML RETURNING ... INTO: write the returned value list onto each Var.
        _assign_return_binds(Bind, Result)

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
            self._rows = await self._resolve_rows(Rows)
            self._rowcount = len(self._rows)
            if (
                self._scrollable
                and self._connection.field_version >= FIELD_VERSION_10_2
            ):
                # Server-side scroll window (#181), 10g+; 9i stays buffered (#161).
                CursorId = (
                    Result[2] if len(Result) > 2 and isinstance(Result[2], int) else 0
                )
                self._init_scroll_window(
                    CursorId, ColMeta, ServerRowCount, len(self._rows), OraCode == 1403
                )
        else:
            self._lastrowid = LastRowid
            self._description = None
            self._annotations = None
            self._rows = []
            self._rowcount = ServerRowCount if isinstance(ServerRowCount, int) else -1

        # Implicit result sets (#121): queue DBMS_SQL.RETURN_RESULT cursors.
        self._implicit_results = _extract_implicit_results(Result)

        self._row_index = 0
        return self

    async def _resolve_rows(self, Rows) -> list:
        # Async row resolution shared by execute and nextset: LOB cells via
        # await aread(), object/collection cells via the awaited type describe
        # (mirrors the sync _resolve_lobs + _resolve_objects).
        from seerdb.common.dbobject import (
            DbObject,
            ObjectImage,
            decode_collection_image,
            decode_object_image,
            decode_xmltype,
        )
        from seerdb.common.lob import LOB
        from seerdb.common.tns_consts import TNS_TYPE_CLOB

        ResolvedRows = []
        for Row in Rows or []:
            NewRow = list(Row)
            for I, Val in enumerate(NewRow):
                if isinstance(Val, LOB):
                    Val._connection = self._connection
                    NewRow[I] = await Val.aread()
                elif isinstance(Val, ObjectImage) and Val.type_name == 'XMLTYPE':
                    # XMLType (#124): decode to str, or read the CLOB locator.
                    (IsLob, XmlVal) = decode_xmltype(
                        Val.image, Val.charset or AL32UTF8_CHARSET
                    )
                    if IsLob:
                        Lob = LOB(TNS_TYPE_CLOB, XmlVal)
                        Lob._connection = self._connection
                        NewRow[I] = await Lob.aread()
                    else:
                        NewRow[I] = XmlVal
                elif isinstance(Val, ObjectImage):
                    Typ = await self._connection._describe_object_type(
                        Val.type_schema, Val.type_name
                    )
                    Charset = Val.charset or AL32UTF8_CHARSET
                    if Typ is not None and Typ.is_collection:
                        Elements = decode_collection_image(
                            Val.image, Typ.element or {}, Charset
                        )
                        NewRow[I] = DbObject(
                            Val.type_name, elements=Elements, dbtype=Typ
                        )
                    else:
                        Layout = Typ.attrs if Typ is not None else []
                        Attrs = decode_object_image(Val.image, Layout, Charset)
                        NewRow[I] = DbObject(Val.type_name, Attrs, dbtype=Typ)
            ResolvedRows.append(NewRow)
        return ResolvedRows

    async def nextset(self) -> bool | None:
        """Advance to the next implicit result set (#121); async port of
        Cursor.nextset(). Returns True if a set became current, else None."""
        self._check_open()
        if not self._implicit_results:
            return None
        RowFormat, CursorId = self._implicit_results.pop(0)
        Rows = await self._connection.fetch_all_rows(CursorId, RowFormat)
        self._description = [_column_description(C) for C in RowFormat]
        self._annotations = [_col_annotations(C) for C in RowFormat]
        self._rows = await self._resolve_rows(Rows)
        self._rowcount = len(self._rows)
        self._row_index = 0
        return True

    async def _build_refcursor(self, Rows, Marker) -> 'AsyncCursor':
        # Wrap an already-fetched REF CURSOR result set in a nested AsyncCursor,
        # resolving any LOB cells with await (mirrors AsyncCursor.execute).
        from seerdb.common.lob import LOB

        Nested = AsyncCursor(self._connection)
        Nested._description = [_column_description(C) for C in Marker['row_format']]
        Nested._annotations = [_col_annotations(C) for C in Marker['row_format']]
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

    def arrayvar(self, typ, value_or_numelements, size=None) -> Var:
        """Bulk-array bind for a PL/SQL associative array (#122). See
        `seerdb.client.cursor.Cursor.arrayvar`."""
        if isinstance(value_or_numelements, int):
            num, values = value_or_numelements, []
        else:
            values = list(value_or_numelements)
            num = len(values)
        var = Var(typ, size, is_array=True, num_elements=max(num, 1))
        var._value = values
        var.has_value = bool(values)
        return var

    async def callproc(self, name: str, parameters=None) -> list:
        """Call a stored procedure. `parameters` is a positional list of plain
        values (IN) and `Var` objects (OUT / IN OUT). Returns the list with
        each `Var` replaced by its returned value."""
        self._check_open()
        Params = list(parameters) if parameters else []
        Placeholders = ', '.join(f':{I + 1}' for I in range(len(Params)))
        await self.execute(f'BEGIN {name}({Placeholders}); END;', Params)
        return [P.getvalue() if isinstance(P, Var) else P for P in Params]

    async def callfunc(self, name: str, return_type, parameters=None):
        """Call a stored function and return its value. See
        `seerdb.client.cursor.Cursor.callfunc`."""
        self._check_open()
        Ret = Var(return_type)
        Params = list(parameters) if parameters else []
        Args = ', '.join(f':{I + 2}' for I in range(len(Params)))
        await self.execute(f'BEGIN :1 := {name}({Args}); END;', [Ret] + Params)
        return Ret.getvalue()

    async def executemany(
        self,
        operation: str,
        seq_of_parameters,
        batcherrors: bool = False,
        arraydmlrowcounts: bool = False,
    ) -> 'AsyncCursor':
        # Array DML in a single round trip; see Cursor.executemany. The
        # batcherrors / arraydmlrowcounts refinements behave exactly as the sync
        # cursor's (#18): batch-error collection via getbatcherrors(), and
        # per-iteration row counts (12.1+ only) via getarraydmlrowcounts().
        self._check_open()
        if arraydmlrowcounts and self._connection.field_version < FIELD_VERSION_12_1:
            raise NotSupportedError('arraydmlrowcounts requires an Oracle 12.1+ server')
        self._batcherrors = []
        self._arraydmlrowcounts = []
        Rows = [_resolve_parameters(operation, P) for P in seq_of_parameters]
        if not Rows:
            self._description = None
            self._rows = []
            self._rowcount = 0
            self._row_index = 0
            return self
        return await self._run(
            operation,
            Rows[0],
            Batch=Rows[1:],
            BatchErrors=batcherrors,
            ArrayDmlRowCounts=arraydmlrowcounts,
        )

    # --- Server-side scroll window helpers (#181), see seerdb.client.cursor.Cursor ---

    async def _scroll_refill(self) -> None:
        # Continue with orient CURRENT at the next absolute row (oracledb fetches
        # every batch as a positioned scroll re-execute, not a TTI_FETCH — #181).
        from seerdb.common.tns_consts import TNS_FETCH_ORIENTATION_CURRENT

        Conn = self._connection
        Size = max(int(self.arraysize), 1)
        Prev = self._rows[-1] if self._rows else None
        Rows, Eof, ServerRowCount = await Conn.scroll_fetch(
            self._scroll_cursor_id,
            TNS_FETCH_ORIENTATION_CURRENT,
            self._scroll_consumed + 1,
            self._scroll_rowformat,
            Fetch=Size,
            PrevRow=Prev,
        )
        Batch = await self._resolve_rows(Rows)
        self._rows = Batch
        # _scroll_set_window resets to empty for an off-the-end batch so a later
        # scroll() can't buffer-hit a stale window (mirrors sync).
        self._scroll_set_window(ServerRowCount, len(Batch))
        self._scroll_eof = Eof or not Batch

    async def fetchone(self) -> tuple | None:
        self._check_open()
        if self._description is None:
            raise InterfaceError('no result set; call execute() with a SELECT first')
        if self._row_index >= len(self._rows):
            if self._scroll_active and not self._scroll_eof:
                await self._scroll_refill()
            if self._row_index >= len(self._rows):
                return None
        Row = self._rows[self._row_index]
        self._row_index += 1
        if self._scroll_active:
            self._scroll_consumed = self._scroll_buf_min + self._row_index - 1
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

    async def fetch_df_all(self):
        """Fetch all remaining rows as a single ``pyarrow.Table`` (#162). Async
        mirror of `Cursor.fetch_df_all`; the rows are already buffered so this
        awaits nothing on the wire but stays async for API symmetry."""
        self._check_open()
        if self._description is None:
            raise InterfaceError('no result set; call execute() with a SELECT first')
        from seerdb.client.dataframe import build_table

        Rows = self._rows[self._row_index :]
        self._row_index = len(self._rows)
        return build_table(Rows, self._description)

    async def fetch_df_batches(self, size: int | None = None):
        """Yield the result set as ``pyarrow.Table`` batches of ``size`` rows
        (#162). Async generator mirror of `Cursor.fetch_df_batches`."""
        self._check_open()
        if self._description is None:
            raise InterfaceError('no result set; call execute() with a SELECT first')
        from seerdb.client.dataframe import build_table

        if size is None:
            size = self.arraysize
        size = max(int(size), 1)
        while self._row_index < len(self._rows):
            Rows = self._rows[self._row_index : self._row_index + size]
            self._row_index += len(Rows)
            yield build_table(Rows, self._description)

    async def scroll(self, value: int = 0, mode: str = 'relative') -> None:
        """Scroll the result-set cursor to a new position. See
        `seerdb.client.cursor.Cursor.scroll`. With scrollable=True the reposition is
        server-side and rows are fetched lazily (#181); otherwise it is a local
        move over the buffered result set (#161)."""
        self._check_open()
        if self._description is None:
            raise InterfaceError('no result set; call execute() with a SELECT first')
        if self._scroll_active:
            return await self._scroll_server(value, mode)
        return self._scroll_buffered(value, mode)

    async def _scroll_server(self, value: int, mode: str) -> None:
        from seerdb.common.tns_consts import (
            TNS_FETCH_ORIENTATION_ABSOLUTE,
            TNS_FETCH_ORIENTATION_FIRST,
            TNS_FETCH_ORIENTATION_LAST,
            TNS_FETCH_ORIENTATION_RELATIVE,
        )

        if mode == 'relative':
            Orientation = TNS_FETCH_ORIENTATION_RELATIVE
            Desired = self._scroll_consumed + value
        elif mode == 'absolute':
            Orientation = TNS_FETCH_ORIENTATION_ABSOLUTE
            Desired = value
        elif mode == 'first':
            Orientation = TNS_FETCH_ORIENTATION_FIRST
            Desired = 1
        elif mode == 'last':
            Orientation = TNS_FETCH_ORIENTATION_LAST
            Desired = 0
        else:
            raise ProgrammingError(f'invalid scroll mode: {mode!r}')
        if mode in ('relative', 'absolute') and Desired < 1:
            raise IndexError('scroll operation would leave the result set')
        if mode != 'last' and self._scroll_buf_min <= Desired < self._scroll_buf_max:
            self._row_index = Desired - self._scroll_buf_min
            self._scroll_consumed = Desired - 1
            return
        Conn = self._connection
        Size = max(int(self.arraysize), 1)
        Prev = self._rows[-1] if self._rows else None
        Rows, Eof, ServerRowCount = await Conn.scroll_fetch(
            self._scroll_cursor_id,
            Orientation,
            Desired,
            self._scroll_rowformat,
            Fetch=Size,
            PrevRow=Prev,
        )
        Batch = await self._resolve_rows(Rows)
        if not Batch:
            self._rows = []
            self._scroll_buf_min = self._scroll_buf_max = 0
            self._scroll_consumed = 0
            self._row_index = 0
            self._scroll_eof = True
            return
        self._rows = Batch
        self._scroll_set_window(ServerRowCount, len(Batch))
        self._scroll_eof = Eof

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
