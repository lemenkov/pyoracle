# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Request pipelining (#132): a Pipeline collects several operations that are
# sent to the server back-to-back in one round trip (on a 23ai server that
# negotiated end-of-response framing, #155) instead of one call at a time. The
# API mirrors python-oracledb: build a Pipeline with create_pipeline(), add
# operations, then run it with connection.run_pipeline(pipeline). The wire flow
# and the serial fallback live on the connection; this module is just the
# operation/result value objects.

from __future__ import annotations

from enum import Enum


class PipelineOpType(Enum):
    EXECUTE = 1
    EXECUTE_MANY = 2
    FETCH_ONE = 3
    FETCH_MANY = 4
    FETCH_ALL = 5
    COMMIT = 6
    CALL_FUNC = 7
    CALL_PROC = 8


class PipelineOp:
    """A single operation queued in a Pipeline (#132)."""

    __slots__ = (
        'op_type',
        'statement',
        'parameters',
        'keyword_parameters',
        'name',
        'return_type',
        'num_rows',
        'arraysize',
        'rowfactory',
    )

    def __init__(
        self,
        op_type,
        statement=None,
        parameters=None,
        keyword_parameters=None,
        name=None,
        return_type=None,
        num_rows=None,
        arraysize=None,
        rowfactory=None,
    ):
        self.op_type = op_type
        self.statement = statement
        self.parameters = parameters
        self.keyword_parameters = keyword_parameters
        self.name = name
        self.return_type = return_type
        self.num_rows = num_rows
        self.arraysize = arraysize
        self.rowfactory = rowfactory

    def __repr__(self):
        what = self.statement or self.name or ''
        return f'<seerdb.PipelineOp {self.op_type.name} {what!r}>'


class PipelineOpResult:
    """The result of one PipelineOp after run_pipeline (#132)."""

    __slots__ = ('operation', 'rows', 'return_value', 'columns', 'error', 'warning')

    def __init__(self, operation):
        self.operation = operation
        self.rows = None
        self.return_value = None
        self.columns = None
        self.error = None
        self.warning = None

    def __repr__(self):
        state = 'error' if self.error else 'ok'
        return f'<seerdb.PipelineOpResult {self.operation.op_type.name} {state}>'


class Pipeline:
    """An ordered list of operations to run in one pipelined round trip (#132).
    Build it with create_pipeline(), add operations, then pass it to
    connection.run_pipeline()."""

    def __init__(self):
        self.operations = []

    def _add(self, op: PipelineOp) -> PipelineOp:
        self.operations.append(op)
        return op

    def add_execute(self, statement, parameters=None) -> PipelineOp:
        """Queue a statement execute (DML/DDL/PL-SQL); no rows are fetched."""
        return self._add(PipelineOp(PipelineOpType.EXECUTE, statement, parameters))

    def add_executemany(self, statement, parameters) -> PipelineOp:
        """Queue an executemany over a sequence of parameter rows."""
        return self._add(PipelineOp(PipelineOpType.EXECUTE_MANY, statement, parameters))

    def add_fetchone(self, statement, parameters=None, rowfactory=None) -> PipelineOp:
        """Queue a query and fetch its first row (result.rows[0] or None)."""
        return self._add(
            PipelineOp(
                PipelineOpType.FETCH_ONE, statement, parameters, rowfactory=rowfactory
            )
        )

    def add_fetchmany(
        self, statement, parameters=None, num_rows=None, rowfactory=None
    ) -> PipelineOp:
        """Queue a query and fetch up to num_rows rows."""
        return self._add(
            PipelineOp(
                PipelineOpType.FETCH_MANY,
                statement,
                parameters,
                num_rows=num_rows,
                rowfactory=rowfactory,
            )
        )

    def add_fetchall(
        self, statement, parameters=None, arraysize=None, rowfactory=None
    ) -> PipelineOp:
        """Queue a query and fetch all its rows."""
        return self._add(
            PipelineOp(
                PipelineOpType.FETCH_ALL,
                statement,
                parameters,
                arraysize=arraysize,
                rowfactory=rowfactory,
            )
        )

    def add_commit(self) -> PipelineOp:
        """Queue a commit."""
        return self._add(PipelineOp(PipelineOpType.COMMIT))

    def add_callproc(
        self, name, parameters=None, keyword_parameters=None
    ) -> PipelineOp:
        """Queue a stored-procedure call."""
        return self._add(
            PipelineOp(
                PipelineOpType.CALL_PROC,
                name=name,
                parameters=parameters,
                keyword_parameters=keyword_parameters,
            )
        )

    def add_callfunc(
        self, name, return_type, parameters=None, keyword_parameters=None
    ) -> PipelineOp:
        """Queue a stored-function call returning return_type."""
        return self._add(
            PipelineOp(
                PipelineOpType.CALL_FUNC,
                name=name,
                return_type=return_type,
                parameters=parameters,
                keyword_parameters=keyword_parameters,
            )
        )


def create_pipeline() -> Pipeline:
    """Create an empty Pipeline (#132)."""
    return Pipeline()
