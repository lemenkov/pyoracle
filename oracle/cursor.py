# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import re

from oracle.exceptions import (
    DatabaseError, InterfaceError, NotSupportedError, ProgrammingError,
)


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

    def close(self) -> None:
        self._closed = True
        self._description = None
        self._rows = []
        self._row_index = 0

    def execute(self, operation: str, parameters=None) -> 'Cursor':
        self._check_open()
        Bind = _resolve_parameters(operation, parameters)
        Result = self._connection.execute(operation, Bind=Bind)
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
            raise DatabaseError(Detail, code=OraCode)

        ServerRowCount = None
        ColMeta = None
        if isinstance(RetFormat, tuple) and len(RetFormat) >= 2:
            ServerRowCount = RetFormat[0]
            if isinstance(RetFormat[1], list):
                ColMeta = RetFormat[1]

        if ColMeta:
            self._description = [_column_description(C) for C in ColMeta]
            self._rows = list(Rows or [])
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

    def executemany(self, operation: str, seq_of_parameters) -> 'Cursor':
        self._check_open()
        Total = 0
        for Params in seq_of_parameters:
            self.execute(operation, Params)
            if self._rowcount > 0:
                Total += self._rowcount
        if Total > 0:
            self._rowcount = Total
        return self

    def fetchone(self) -> tuple | None:
        self._check_open()
        if self._description is None:
            raise InterfaceError("no result set; call execute() with a SELECT first")
        if self._row_index >= len(self._rows):
            return None
        Row = self._rows[self._row_index]
        self._row_index += 1
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


def _resolve_parameters(SQL: str, Params) -> list:
    # Translate the caller-supplied parameters into a positional list in the
    # order the placeholders first appear in the SQL. The wire protocol always
    # sends bind values positionally; named placeholders (`:foo`) just give
    # the caller a way to refer to them by name.
    if Params is None:
        return []
    if isinstance(Params, (list, tuple)):
        return list(Params)
    if isinstance(Params, dict):
        Names = _extract_bind_names(SQL)
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


def _extract_bind_names(SQL: str) -> list[str]:
    # First-occurrence order of `:name` placeholders, case-folded to lower,
    # with quoted strings and SQL comments stripped so we don't match inside
    # them.
    Cleaned = re.sub(r"'(?:''|[^'])*'", "''", SQL)
    Cleaned = re.sub(r'"(?:""|[^"])*"', '""', Cleaned)
    Cleaned = re.sub(r'--[^\n]*', '', Cleaned)
    Cleaned = re.sub(r'/\*.*?\*/', '', Cleaned, flags=re.S)
    Seen: list[str] = []
    Found = set()
    for M in _NAMED_BIND_RE.finditer(Cleaned):
        N = M.group(1).lower()
        if N not in Found:
            Found.add(N)
            Seen.append(N)
    return Seen


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
