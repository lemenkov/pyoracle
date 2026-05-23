# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

from oracle.exceptions import (
    DatabaseError, InterfaceError, NotSupportedError,
)


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
        if parameters:
            raise NotSupportedError(
                "bind variables are not yet supported; inline literals for now"
            )

        Result = self._connection.execute(operation)
        # Wire result tuple: (RetCode, OraCode, CursorHandle, RetFormat, Rows).
        # RetCode is the OPI status; OraCode carries the Oracle error number
        # (0 on plain success, 1403 at end-of-fetch).
        try:
            (_, OraCode, _, RetFormat, Rows) = Result
        except (TypeError, ValueError) as exc:
            raise DatabaseError(f"unexpected wire response: {Result!r}") from exc

        if OraCode not in (0, 1403):
            raise DatabaseError(f"ORA-{OraCode:05d}", code=OraCode)

        ColMeta = None
        if isinstance(RetFormat, tuple) and len(RetFormat) >= 2 \
                and isinstance(RetFormat[1], list):
            ColMeta = RetFormat[1]

        if ColMeta:
            self._description = [_column_description(C) for C in ColMeta]
            self._rows = list(Rows or [])
            self._rowcount = len(self._rows)
        else:
            # DDL/DML or other non-result-set statements. The OER block carries
            # an affected-row count which the decoder doesn't surface yet, so
            # leave rowcount unknown rather than lie.
            self._description = None
            self._rows = []
            self._rowcount = -1

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
