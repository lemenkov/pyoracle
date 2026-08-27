# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A PostgreSQL backend for the Mirror (psycopg 3).

Point a Mirror at a PostgreSQL database and thin-dialect Oracle clients run real
SQL against it. Result columns map from PostgreSQL type OIDs to Oracle types; a
column whose type the Mirror cannot yet represent is refused with a clean
``ORA-03001`` (unimplemented feature) rather than mis-encoded — the same
capabilities-and-errors contract SQLite uses, just with a different set of
supported types.

Requires the ``psycopg`` package. This is a demo/adapter outside ``seerdb``
core; the driver dependency lives here, not in the library.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import psycopg

from seerdb.common.tns_consts import (
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_DATE,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
)
from seerdb.server import (
    BackendError,
    Capability,
    ColumnMeta,
    Credentials,
    Result,
    UnsupportedFeature,
    credential_lookup,
)

# Oracle numbered/named binds (:1, :name) → psycopg positional '%s'. The
# negative lookbehind leaves any '::' cast untouched.
_ORACLE_BIND = re.compile(r'(?<!:):\w+')

# Oracle → PostgreSQL column-type rewrites for CREATE TABLE (#500). Applied in
# order, so a multi-word / longer keyword comes before a shorter one it contains
# (LONG RAW before RAW / LONG, TIMESTAMP WITH TIME ZONE before TIMESTAMP,
# NVARCHAR2 before VARCHAR2, NCLOB before CLOB). A size suffix the target type
# keeps (VARCHAR2(10) → varchar(10), NUMBER(p,s) → numeric(p,s)) rides along
# because only the keyword is replaced; one PostgreSQL rejects (RAW(16)) is
# matched with its parens and dropped. Word boundaries keep column names and
# other tokens untouched; only CREATE TABLE is rewritten, so a type keyword used
# as an identifier elsewhere is left alone.
_DDL_TYPE_REWRITES = [
    (re.compile(r'\bLONG\s+RAW\b', re.IGNORECASE), 'bytea'),
    (re.compile(r'\bRAW\s*\(\s*\d+\s*\)', re.IGNORECASE), 'bytea'),
    (re.compile(r'\bRAW\b', re.IGNORECASE), 'bytea'),
    (
        re.compile(r'\bTIMESTAMP\s+WITH\s+(?:LOCAL\s+)?TIME\s+ZONE\b', re.IGNORECASE),
        'timestamptz',
    ),
    (re.compile(r'\bTIMESTAMP\b', re.IGNORECASE), 'timestamp'),
    (re.compile(r'\bDATE\b', re.IGNORECASE), 'timestamp(0)'),
    (
        re.compile(
            r'\bINTERVAL\s+DAY(?:\s*\(\d+\))?\s+TO\s+SECOND(?:\s*\(\d+\))?\b',
            re.IGNORECASE,
        ),
        'interval',
    ),
    (
        re.compile(r'\bINTERVAL\s+YEAR(?:\s*\(\d+\))?\s+TO\s+MONTH\b', re.IGNORECASE),
        'interval',
    ),
    (re.compile(r'\bNVARCHAR2\b', re.IGNORECASE), 'varchar'),
    (re.compile(r'\bVARCHAR2\b', re.IGNORECASE), 'varchar'),
    (re.compile(r'\bNCHAR\b', re.IGNORECASE), 'char'),
    (re.compile(r'\bNUMBER\b', re.IGNORECASE), 'numeric'),
    (re.compile(r'\bNCLOB\b', re.IGNORECASE), 'text'),
    (re.compile(r'\bCLOB\b', re.IGNORECASE), 'text'),
    (re.compile(r'\bBLOB\b', re.IGNORECASE), 'bytea'),
    (re.compile(r'\bLONG\b', re.IGNORECASE), 'text'),
    (re.compile(r'\bBINARY_FLOAT\b', re.IGNORECASE), 'real'),
    (re.compile(r'\bBINARY_DOUBLE\b', re.IGNORECASE), 'double precision'),
]
# Oracle table clauses PostgreSQL has no equal for — dropped (the resulting plain
# table is close enough for the suite): an index-organized table is just a table
# (a PRIMARY KEY already gives the index), and GLOBAL TEMPORARY maps to a plain
# TEMPORARY table (ON COMMIT ... ROWS is already valid PostgreSQL).
_DDL_ORG_INDEX = re.compile(r'\s+ORGANIZATION\s+INDEX\b', re.IGNORECASE)
_DDL_GLOBAL_TEMPORARY = re.compile(r'\bGLOBAL\s+TEMPORARY\b', re.IGNORECASE)
_IS_CREATE_TABLE = re.compile(
    r'\s*CREATE\s+(?:GLOBAL\s+TEMPORARY\s+)?TABLE\b', re.IGNORECASE
)


def _translate_ddl(sql: str) -> str:
    """Rewrite an Oracle ``CREATE TABLE`` to PostgreSQL: map the column types and
    drop the clauses PostgreSQL has no equal for (#500). Non-CREATE-TABLE SQL is
    returned unchanged."""
    if not _IS_CREATE_TABLE.match(sql):
        return sql
    out = _DDL_GLOBAL_TEMPORARY.sub('TEMPORARY', sql)
    out = _DDL_ORG_INDEX.sub('', out)
    for pattern, replacement in _DDL_TYPE_REWRITES:
        out = pattern.sub(replacement, out)
    return out


# PostgreSQL type OIDs (pg_type.oid) → Oracle wire type.
_NUMBER_OIDS = frozenset(
    {
        16,
        20,
        21,
        23,
        26,
        1700,
    }  # bool int8 int2 int4 oid numeric
)
# IEEE-754 floats map to Oracle's native binary types, not base-100 NUMBER —
# preserving the exact bits and the "this is a float, not a decimal" nature.
_BINARY_FLOAT_OIDS = {
    700: (TNS_TYPE_BFLOAT, 4),  # float4 (real)
    701: (TNS_TYPE_BDOUBLE, 8),  # float8 (double precision)
}
_TEXT_OIDS = frozenset({18, 19, 25, 1042, 1043})  # char name text bpchar varchar
_RAW_OIDS = frozenset({17})  # bytea
# Each PostgreSQL temporal OID maps to the Oracle type of matching precision:
# a bare date → DATE (7 bytes), timestamp → TIMESTAMP (11), timestamptz → 13.
_TEMPORAL_OIDS = {
    1082: (TNS_TYPE_DATE, 7),  # date
    1114: (TNS_TYPE_TIMESTAMP, 11),  # timestamp (without time zone)
    1184: (TNS_TYPE_TIMESTAMPTZ, 13),  # timestamptz
}
# PostgreSQL `interval` (oid 1186) → Oracle INTERVAL DAY TO SECOND. psycopg
# returns it as a datetime.timedelta, which the Mirror already encodes for an
# INTERVALDS column. INTERVAL YEAR TO MONTH can't round-trip: PostgreSQL/psycopg
# collapse a year-month interval to an approximate day count (a timedelta with no
# months), losing the calendar distinction Oracle keeps — that's an Oracle-only
# ceiling (#504), not a mapping this backend can honour.
_INTERVAL_OIDS = frozenset({1186})

_ORA_INVALID_SQL = 900

# Map a PostgreSQL error (by SQLSTATE) to the Oracle error number a client
# expects, so error-conditional flows behave (#500). The load-bearing one is
# `undefined_table` → ORA-00942: the suite's setUp/tearDown drops tables
# best-effort and only swallows ORA-00942 — reporting ORA-00900 instead re-raised
# and failed every test in setUp. Anything unmapped falls back to ORA-00900.
_SQLSTATE_TO_ORA = {
    '42P01': 942,  # undefined_table         -> table or view does not exist
    '42704': 942,  # undefined_object (type) -> (DROP TYPE cleanup)
    '42P07': 955,  # duplicate_table         -> name is already used
    '42703': 904,  # undefined_column        -> invalid identifier
    '42883': 904,  # undefined_function
    '23505': 1,  # unique_violation        -> unique constraint violated
    '23502': 1400,  # not_null_violation      -> cannot insert NULL
    '23514': 2290,  # check_violation         -> check constraint violated
}


def _ora_code_for(exc) -> int:
    return _SQLSTATE_TO_ORA.get(getattr(exc, 'sqlstate', None), _ORA_INVALID_SQL)


def _column_meta(desc, values: list) -> ColumnMeta:
    # `desc` is a psycopg Column (name / type_code / precision / scale / ...).
    name, oid = desc.name, desc.type_code
    ident = name.upper().encode('utf-8')
    if oid in _NUMBER_OIDS:
        # A numeric(p, s) column reports its precision/scale; int / float / bare
        # numeric report None, which becomes Oracle's unconstrained NUMBER (0/0).
        return ColumnMeta(
            name=ident,
            data_type=TNS_TYPE_NUMBER,
            data_length=22,
            max_size=22,
            precision=desc.precision or 0,
            scale=desc.scale or 0,
        )
    if oid in _BINARY_FLOAT_OIDS:
        data_type, width = _BINARY_FLOAT_OIDS[oid]
        return ColumnMeta(
            name=ident, data_type=data_type, data_length=width, max_size=width
        )
    if oid in _TEMPORAL_OIDS:
        data_type, width = _TEMPORAL_OIDS[oid]
        return ColumnMeta(
            name=ident, data_type=data_type, data_length=width, max_size=width
        )
    if oid in _INTERVAL_OIDS:
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_INTERVALDS, data_length=11, max_size=11
        )
    if oid in _RAW_OIDS:
        width = max(
            (len(v) for v in values if isinstance(v, (bytes, bytearray, memoryview))),
            default=1,
        )
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_RAW, data_length=width, max_size=width
        )
    if oid in _TEXT_OIDS:
        width = max((len(str(v)) for v in values if v is not None), default=1)
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_VARCHAR, data_length=width, max_size=width
        )
    raise UnsupportedFeature(
        f'column {name!r}: PostgreSQL type oid {oid} is not supported yet'
    )


class PostgresBackend:
    """A :class:`~seerdb.server.Backend` over a psycopg connection.

    One instance per Mirror session. ``conninfo`` is a libpq connection string,
    e.g. ``host=127.0.0.1 port=5432 user=pyo password=... dbname=mirror``.

    The connection is transactional (``autocommit`` off), so the Mirror's
    commit / rollback are real: work persists only on commit and is discarded on
    rollback. Each statement runs inside an implicit ``SAVEPOINT`` so a failed
    statement rolls back only itself — the transaction (and any earlier
    uncommitted work) survives, matching Oracle's statement-level error model
    rather than PostgreSQL's abort-the-whole-transaction default.
    """

    capabilities = frozenset({Capability.TRANSACTIONS})

    def __init__(
        self, conninfo: str = '', *, credentials: Credentials | None = None
    ) -> None:
        self._conn = psycopg.connect(conninfo)
        self._credentials = credentials or {}

    def authenticate(self, username: str) -> str | None:
        # The login store the Mirror authenticates clients against — separate
        # from the libpq `conninfo` the backend itself connects to PostgreSQL
        # with. A production backend might instead consult a PG table here.
        return credential_lookup(self._credentials, username)

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        # Translate Oracle DDL column types to PostgreSQL's dialect (#500) — this
        # is where dialect knowledge belongs, not in the generic compat shim.
        sql = _translate_ddl(sql)
        if binds:
            sql = _ORACLE_BIND.sub('%s', sql)
        cursor = self._conn.cursor()
        # SAVEPOINT isolates this statement: on any error we roll back to here
        # (which also clears PostgreSQL's aborted-transaction state) and leave the
        # rest of the transaction intact; on success we release it. Either way
        # the savepoint is resolved, so they never accumulate across statements.
        cursor.execute('SAVEPOINT _mirror_stmt')
        try:
            cursor.execute(sql, tuple(binds) or None)
            if cursor.description is None:
                result = Result(rowcount=max(cursor.rowcount, 0))
            else:
                rows = cursor.fetchall()
                columns = [
                    _column_meta(desc, [r[i] for r in rows])
                    for i, desc in enumerate(cursor.description)
                ]
                result = Result(columns=columns, rows=rows)
        except psycopg.Error as exc:
            self._conn.execute('ROLLBACK TO SAVEPOINT _mirror_stmt')
            self._conn.execute('RELEASE SAVEPOINT _mirror_stmt')
            # A PostgreSQL failure surfaces as a clean ORA error — never a desync.
            # Map the SQLSTATE to the matching Oracle code so error-conditional
            # client flows (e.g. a best-effort DROP that swallows ORA-00942) work.
            raise BackendError(str(exc).strip(), ora_code=_ora_code_for(exc)) from exc
        except Exception:
            # An our-side rejection (e.g. UnsupportedFeature on an unmapped column
            # type) after the statement ran — undo it and re-raise for the session
            # to map to an ORA error.
            self._conn.execute('ROLLBACK TO SAVEPOINT _mirror_stmt')
            self._conn.execute('RELEASE SAVEPOINT _mirror_stmt')
            raise
        self._conn.execute('RELEASE SAVEPOINT _mirror_stmt')
        return result

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()
