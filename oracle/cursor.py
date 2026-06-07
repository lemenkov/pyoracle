# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import re

from oracle.datatypes import Var
from oracle.exceptions import (
    DatabaseError, InterfaceError, NotSupportedError, ProgrammingError,
    from_ora_code,
)
from oracle.tns_consts import UTF8_CHARSET


# `:name` placeholder. Names are case-insensitive and follow normal SQL
# identifier rules; pure-digit forms (`:1`, `:2`) are handled separately as
# positional indices.
_NAMED_BIND_RE = re.compile(r':([A-Za-z_]\w*)')


class cursor:
    # Sentinel passed as a bind value to indicate a REFCURSOR slot. Consumed by
    # the encoder in oracle.tns (encode_token_oac / encode_token_rxd). Kept
    # lowercase for backwards-compatibility with existing call sites.
    id: int = 0


class Cursor:
    # PEP 249 DB-API 2.0 cursor. Wraps OracleConnect.execute and presents the
    # standard fetchone/fetchmany/fetchall surface. Backwards-compatibility
    # note: the raw 5-tuple result format produced by OracleConnect.execute
    # is still available for callers that prefer it.

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
        if self._connection is None or self._connection.sock is None:
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
        """Optional callable applied to each fetched row. It is called with the
        row's column values as positional arguments (oracledb semantics), e.g.
        `cur.rowfactory = lambda *a: dict(zip([c[0] for c in cur.description], a))`.
        None (the default) yields plain tuples."""
        return self._rowfactory

    @rowfactory.setter
    def rowfactory(self, value) -> None:
        self._rowfactory = value

    def close(self) -> None:
        self._closed = True
        self._description = None
        self._rows = []
        self._row_index = 0

    def execute(self, operation: str, parameters=None) -> 'Cursor':
        self._check_open()
        Bind = _resolve_parameters(operation, parameters)
        return self._run(operation, Bind)

    def _run(self, operation: str, Bind: list, Batch: list | None = None) -> 'Cursor':
        Result = self._connection.execute(operation, Bind=Bind, Batch=Batch)
        # Wire result tuple from decode_token_oer:
        #   (call_status, oracle_error_code, cursor_id, (rowcount, col_meta),
        #    rows, message_or_none)
        # The trailing message slot is present for the new OER decoder. Earlier
        # decoders returned a 5-tuple; tolerate either shape so a stale build
        # doesn't crash here.
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

        # PL/SQL OUT / IN OUT binds: write returned values back into any Var
        # objects the caller passed. REF CURSOR OUT binds are fetched here.
        for Variable, Marker in _assign_out_binds(Bind, Result):
            Rows = self._connection.fetch_all_rows(
                Marker['cursor_id'], Marker['row_format'])
            Variable._value = _build_refcursor_cursor(
                self._connection, Rows, Marker)

        ServerRowCount = None
        ColMeta = None
        if isinstance(RetFormat, tuple) and len(RetFormat) >= 2:
            ServerRowCount = RetFormat[0]
            if isinstance(RetFormat[1], list):
                ColMeta = RetFormat[1]

        if ColMeta:
            self._description = [_column_description(C) for C in ColMeta]
            self._rows = [_resolve_lobs(self._connection, row)
                          for row in (Rows or [])]
            # For SELECT, the OER's success-iters value is the per-call fetch
            # count, not the total result set size; len(rows) is the answer
            # callers expect from cursor.rowcount.
            self._rowcount = len(self._rows)
        else:
            # DDL / DML / non-result-set statement. OER carries the affected
            # row count in its success-iters field; surface it.
            self._description = None
            self._rows = []
            self._rowcount = ServerRowCount if isinstance(ServerRowCount, int) else -1

        self._row_index = 0
        return self

    def var(self, typ, size=None) -> Var:
        """Create a bind variable that can receive an OUT / IN OUT value.

        `typ` is a Python type (`int`, `str`, `bytes`, `datetime`, ...) or an
        `oracle` type constant (`oracle.NUMBER`, `oracle.STRING`,
        `oracle.DB_TYPE_*`). Pass the returned `Var` in a `callproc` /
        `execute` parameter list and read the result with `getvalue()`.
        """
        return Var(typ, size)

    def callproc(self, name: str, parameters=None) -> list:
        """Call a stored procedure. `parameters` is a positional list of plain
        values (IN) and `Var` objects (OUT / IN OUT). Returns the parameter
        list with each `Var` replaced by its returned value (PEP 249 / oracledb
        compatible).
        """
        self._check_open()
        Params = list(parameters) if parameters else []
        Placeholders = ', '.join(f':{I + 1}' for I in range(len(Params)))
        self.execute(f"BEGIN {name}({Placeholders}); END;", Params)
        return [P.getvalue() if isinstance(P, Var) else P for P in Params]

    def callfunc(self, name: str, return_type, parameters=None):
        """Call a stored function and return its value. `return_type` is a
        Python type or `oracle` type constant (as for `var`); `parameters`
        are the function's arguments (plain values for IN, `Var` for OUT /
        IN OUT). PEP 249 / oracledb compatible.
        """
        self._check_open()
        Ret = Var(return_type)
        Params = list(parameters) if parameters else []
        # :1 is the return value; arguments are :2, :3, ...
        Args = ', '.join(f':{I + 2}' for I in range(len(Params)))
        self.execute(f"BEGIN :1 := {name}({Args}); END;", [Ret] + Params)
        return Ret.getvalue()

    def executemany(self, operation: str, seq_of_parameters) -> 'Cursor':
        # Array DML: bind every row's values and execute them in a single
        # server round trip (one parse, `len(rows)` iterations) rather than
        # one execute() per row. Column types are taken from the first row.
        self._check_open()
        Rows = [_resolve_parameters(operation, P) for P in seq_of_parameters]
        if not Rows:
            self._description = None
            self._rows = []
            self._rowcount = 0
            self._row_index = 0
            return self
        return self._run(operation, Rows[0], Batch=Rows[1:])

    def fetchone(self) -> tuple | None:
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

    def fetchmany(self, size: int | None = None) -> list[tuple]:
        if size is None:
            size = self.arraysize
        Out = []
        for _ in range(max(size, 0)):
            Row = self.fetchone()
            if Row is None:
                break
            Out.append(Row)
        return Out

    def fetchall(self) -> list[tuple]:
        Out = []
        while True:
            Row = self.fetchone()
            if Row is None:
                break
            Out.append(Row)
        return Out

    def setinputsizes(self, sizes) -> None:
        # PEP 249 allows this to be a no-op when sizing isn't required.
        pass

    def setoutputsize(self, size, column=None) -> None:
        pass

    def __iter__(self):
        return self

    def __next__(self):
        Row = self.fetchone()
        if Row is None:
            raise StopIteration
        return Row

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def _assign_out_binds(Bind, Result) -> list:
    # After a PL/SQL execute, the IOV decoder leaves an {'out_positions',
    # 'out_values', ...} record as the single "row". Decode each scalar OUT
    # value by its Var's declared type and store it on the Var. REF CURSOR OUT
    # values arrive as a marker dict ({'_refcursor', 'cursor_id',
    # 'row_format'}); they need a server fetch to materialise, which differs
    # between the sync and async cursors, so collect and return them as
    # (Var, marker) pairs for the caller to finish.
    if not isinstance(Bind, list) or not isinstance(Result, tuple) \
            or len(Result) < 5:
        return []
    Rows = Result[4]
    if not Rows or not isinstance(Rows[0], dict) \
            or 'out_positions' not in Rows[0]:
        return []
    from oracle.types import decode_value
    Record = Rows[0]
    RefCursors = []
    for Pos, Value in zip(Record['out_positions'], Record['out_values']):
        if Pos >= len(Bind) or not isinstance(Bind[Pos], Var):
            continue
        Variable = Bind[Pos]
        if isinstance(Value, dict) and Value.get('_refcursor'):
            RefCursors.append((Variable, Value))
        else:
            Column = {'data_type': Variable.dbtype.tns_type,
                      'charset': UTF8_CHARSET}
            Variable._value = decode_value(Column, Value if Value else None)
    return RefCursors


def _build_refcursor_cursor(Connection, Rows, Marker) -> 'Cursor':
    # Wrap an already-fetched REF CURSOR result set in a Cursor.
    Nested = Cursor(Connection)
    Nested._description = [_column_description(C) for C in Marker['row_format']]
    Nested._rows = [_resolve_lobs(Connection, Row) for Row in Rows]
    Nested._rowcount = len(Nested._rows)
    Nested._row_index = 0
    return Nested


def _resolve_lobs(Connection, Row: list) -> list:
    # Replace any LOB cells in the row with their resolved Python value.
    # CLOB → str, BLOB → bytes, empty → "" / b"", NULL stays as None (the
    # row decoder already handed back None for NULL LOBs before they ever
    # became LOB objects).
    from oracle.lob import LOB
    Out = list(Row)
    for I, Val in enumerate(Out):
        if isinstance(Val, LOB):
            Val._connection = Connection
            Out[I] = Val.read()
    return Out


def _resolve_parameters(SQL: str, Params) -> list:
    # Translate the caller-supplied parameters into a positional list. The
    # wire protocol sends bind values positionally; named placeholders
    # (`:foo`) just give the caller a way to refer to them by name.
    #
    # For plain SQL each `:name` occurrence is a distinct bind position
    # — Oracle expects N values when `:name` appears N times. For PL/SQL
    # blocks Oracle dedupes by unique placeholder name (per the OCI
    # binding contract), so we emit each unique name once. The
    # difference is detected on the SQL itself by `_is_plsql`.
    if Params is None:
        return []
    if isinstance(Params, (list, tuple)):
        return list(Params)
    if isinstance(Params, dict):
        Names = _extract_bind_names(SQL, dedupe=_is_plsql(SQL))
        Lower = {str(k).lower(): v for k, v in Params.items()}
        Out = []
        for N in Names:
            if N not in Lower:
                raise ProgrammingError(
                    f"missing bind value for :{N}"
                )
            Out.append(Lower[N])
        return Out
    raise NotSupportedError(
        f"parameters must be a list, tuple, or dict; got {type(Params).__name__}"
    )


def _extract_bind_names(SQL: str, dedupe: bool = False) -> list[str]:
    # `:name` placeholders in left-to-right SQL order, case-folded to
    # lower, with quoted strings and SQL comments stripped so we don't
    # match inside them.
    #
    # If `dedupe` is True (PL/SQL path), keep only the first occurrence
    # of each name. Otherwise (plain SQL path) return every occurrence
    # — Oracle expects one bind value per textual occurrence in DML.
    Cleaned = re.sub(r"'(?:''|[^'])*'", "''", SQL)
    Cleaned = re.sub(r'"(?:""|[^"])*"', '""', Cleaned)
    Cleaned = re.sub(r'--[^\n]*', '', Cleaned)
    Cleaned = re.sub(r'/\*.*?\*/', '', Cleaned, flags=re.S)
    Seen: list[str] = []
    Found: set[str] = set()
    for M in _NAMED_BIND_RE.finditer(Cleaned):
        N = M.group(1).lower()
        if dedupe:
            if N not in Found:
                Found.add(N)
                Seen.append(N)
        else:
            Seen.append(N)
    return Seen


def _is_plsql(SQL: str) -> bool:
    # PL/SQL blocks start with BEGIN or DECLARE after stripping leading
    # whitespace and SQL comments. Anonymous blocks, packaged calls
    # wrapped in BEGIN...END;, and DECLARE...BEGIN forms all match.
    Stripped = re.sub(r'^\s*(?:--[^\n]*\n|/\*.*?\*/|\s)+', '',
                      SQL, flags=re.S)
    Head = Stripped[:8].upper()
    return Head.startswith("BEGIN") or Head.startswith("DECLARE")


def _column_description(Col: dict) -> tuple:
    # PEP 249 description tuple:
    #   (name, type_code, display_size, internal_size, precision, scale, null_ok)
    Name = Col.get('column_name')
    if isinstance(Name, bytes):
        Name = Name.decode('utf-8', errors='replace')
    InternalSize = Col.get('data_length')
    DisplaySize = Col.get('max_size') or InternalSize
    return (
        Name,
        Col.get('data_type'),
        DisplaySize or None,
        InternalSize or None,
        Col.get('precision'),
        Col.get('data_scale'),
        bool(Col.get('null_ok', 0)),
    )
