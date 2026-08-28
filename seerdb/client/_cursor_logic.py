# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Non-I/O cursor logic shared by the sync and async cursors (#553).

`Cursor` (sync) and `AsyncCursor` (async) duplicate a body of methods whose
logic contains no ``await`` and touches no socket — the DB-API accessor
properties, bind-variable / batch-error helpers, and the buffered (client-side)
scroll bookkeeping. `_CursorLogic` holds that shared logic; both concrete cursor
classes inherit it, so a single definition serves both and the sync/async parity
holds by construction. The genuinely I/O-bound methods (execute, fetch*, the
server-side scroll path, close, iteration) stay per-class.

The shared ``__init__`` establishes the cursor state the concrete I/O methods
read and write.
"""

from __future__ import annotations

from seerdb.common.datatypes import Var
from seerdb.common.exceptions import ProgrammingError, from_ora_code


class _CursorLogic:
    """Shared non-I/O logic for `Cursor` / `AsyncCursor` (#553)."""

    arraysize: int = 1
    # Rows the server prefetches on a scrollable open (oracledb's prefetchrows
    # default). Kept small so the open does not drain the cursor to EOF, which
    # would break the subsequent scroll re-execute (#181).
    prefetchrows: int = 2

    def __init__(self, connection, scrollable: bool = False):
        self._connection = connection
        self._description: list[tuple] | None = None
        self._annotations: list[dict | None] | None = None
        self._rows: list[list] = []
        self._row_index: int = 0
        self._rowcount: int = -1
        self._closed: bool = False
        self._lastrowid = None
        self._rowfactory = None
        # Scrollable cursor. With scrollable=True a SELECT is fetched lazily from
        # a kept-open server cursor: scroll() repositions server-side and
        # fetchone/many pull batches on demand (#181). With scrollable=False the
        # whole result set is buffered on execute and scroll() is a local
        # reposition (#161) — kept for backwards compatibility.
        self._scrollable = bool(scrollable)
        # Server-side scroll state (only used when scrollable and a SELECT is
        # open). _scroll_active gates the lazy path; the buffer window spans
        # absolute rows [_scroll_buf_min, _scroll_buf_max), and _scroll_consumed
        # is the absolute row number of the last row returned (oracledb's
        # rowcount), used to compute relative-scroll targets.
        self._scroll_active: bool = False
        self._scroll_cursor_id: int = 0
        self._scroll_rowformat: list | None = None
        self._scroll_buf_min: int = 0
        self._scroll_buf_max: int = 0
        self._scroll_consumed: int = 0
        self._scroll_eof: bool = False
        # Pending implicit result sets (#121): (row_format, cursor_id) queue
        # left by a DBMS_SQL.RETURN_RESULT block, consumed via nextset().
        self._implicit_results: list = []

    @property
    def scrollable(self) -> bool:
        """Whether this cursor was opened scrollable (#161). seerdb's
        result-set buffer makes scroll() available on any cursor, so this is
        primarily for oracledb API compatibility."""
        return self._scrollable

    @scrollable.setter
    def scrollable(self, value: bool) -> None:
        self._scrollable = bool(value)

    @property
    def description(self) -> list[tuple] | None:
        return self._description

    @property
    def annotations(self) -> list[dict | None] | None:
        """Per-column SQL annotations (23ai) for the last SELECT, aligned with
        `description`: a list with one entry per column — a `{name: value}` dict
        for an annotated column (value is '' for a name-only annotation) or
        `None` for a column with no annotations. `None` overall when the last
        statement produced no result set or the server is pre-23ai."""
        return self._annotations

    @property
    def rowcount(self) -> int:
        # For a lazy server-side scrollable cursor, rowcount tracks the number of
        # rows consumed so far (the absolute position of the last row returned),
        # matching oracledb; otherwise it is the buffered result-set size / DML
        # affected-row count.
        if self._scroll_active:
            return self._scroll_consumed
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

    @property
    def lastrowid(self):
        """ROWID (string) of the last row an INSERT / UPDATE / DELETE touched,
        or None when the last statement produced no rowid (SELECT, DDL, or a
        multi-row/zero-row change). PEP 249 optional attribute."""
        return self._lastrowid

    def var(self, typ, size=None) -> Var:
        """Create a bind variable that can receive an OUT / IN OUT value.

        `typ` is a Python type (`int`, `str`, `bytes`, `datetime`, ...) or an
        `seerdb` type constant (`seerdb.NUMBER`, `seerdb.STRING`,
        `seerdb.DB_TYPE_*`). Pass the returned `Var` in a `callproc` /
        `execute` parameter list and read the result with `getvalue()`.
        """
        return Var(typ, size)

    def getbatcherrors(self) -> list:
        """Errors collected by the most recent ``executemany(batcherrors=True)``.

        Returns a list of ``DatabaseError`` objects, one per failed row, each
        carrying ``.offset`` (the 0-based row index in the batch), ``.code``
        (the ORA number) and the message. Empty if the last statement had no
        batch errors. oracledb-compatible.
        """
        Out = []
        for E in getattr(self, '_batcherrors', []):
            Code = E.get('code')
            Exc = from_ora_code(Code)(E.get('message') or f'ORA-{Code:05d}', code=Code)
            Exc.offset = E.get('offset')
            Out.append(Exc)
        return Out

    def getarraydmlrowcounts(self) -> list:
        """Per-iteration row counts from the most recent
        ``executemany(arraydmlrowcounts=True)``.

        Returns a list of ints, one per row in the batch, giving how many rows
        that iteration affected (e.g. an UPDATE matching 3 rows yields 3).
        Empty if the last statement didn't request row counts. Requires a 12.1+
        server. oracledb-compatible.
        """
        return list(getattr(self, '_arraydmlrowcounts', []))

    def _init_scroll_window(
        self, cursor_id: int, colmeta: list, server_rowcount, batch_len: int, eof: bool
    ) -> None:
        # Arm the lazy server-side scroll path after a scrollable open.
        self._scroll_active = True
        self._scroll_cursor_id = cursor_id
        self._scroll_rowformat = colmeta
        self._scroll_set_window(server_rowcount, batch_len)
        self._scroll_eof = eof

    def _scroll_set_window(self, server_rowcount, batch_len: int) -> None:
        # Place the buffer window from the server's cumulative rowcount (the
        # absolute 1-based row number of the last row in the batch) and the batch
        # size, mirroring oracledb's _post_process_scroll. _scroll_consumed is
        # the absolute position of the last row already returned to the caller.
        if batch_len <= 0:
            self._scroll_buf_min = self._scroll_buf_max = 0
            self._scroll_consumed = 0
            self._row_index = 0
            return
        Srv = server_rowcount if isinstance(server_rowcount, int) else batch_len
        self._scroll_buf_min = Srv - batch_len + 1
        self._scroll_buf_max = self._scroll_buf_min + batch_len
        self._scroll_consumed = self._scroll_buf_min - 1
        self._row_index = 0

    def _scroll_buffered(self, value: int, mode: str) -> None:
        # #161 fallback: the whole result set is in self._rows, so scroll() is a
        # local index move. Used for non-scrollable cursors.
        Count = len(self._rows)
        if mode == 'relative':
            Target = self._row_index + value
        elif mode == 'absolute':
            Target = value
        elif mode == 'first':
            Target = 1
        elif mode == 'last':
            Target = Count
        else:
            raise ProgrammingError(f'invalid scroll mode: {mode!r}')
        if Target < 1 or Target > Count:
            raise IndexError('scroll operation would leave the result set')
        self._row_index = Target - 1

    def setinputsizes(self, sizes) -> None:
        # PEP 249 allows this to be a no-op when sizing isn't required.
        pass

    def setoutputsize(self, size, column=None) -> None:
        pass
