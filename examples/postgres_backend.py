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

**Requires the** `orafce <https://github.com/orafce/orafce>`_ **PostgreSQL
extension** for Oracle-compatible SQL functions (``nvl``, ``decode``,
``to_char`` / ``to_date``, ``add_months``, ``instr``, …). The backend puts its
``oracle`` schema on the search_path and creates the extension if it can, so
those idioms need no hand-rolled translation — only the ones orafce does not
cover are rewritten (``hextoraw``, ``empty_clob`` / ``empty_blob``, ``from_tz``,
the ``BINARY_DOUBLE`` special values / literal suffix). Install it on the server
(e.g. Alpine ``apk add postgresql-orafce`` for a matching PG major, or build from
source with PGXS) — see ``examples/mirror-pg.Dockerfile``.
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
    BindVar,
    Capability,
    ColumnMeta,
    Credentials,
    Result,
    UnsupportedFeature,
    credential_lookup,
)

# One Oracle bind reference: `:` + an identifier or number (`:x`, `:my_var`,
# `:1`). A `::` cast is left alone (handled by the scan below, which only starts
# a bind where the previous char isn't `:`).
_BIND_REF = re.compile(r':(\w+)')


def _bind_key(name: str) -> str:
    # A psycopg dict key for a bind name — a numbered bind (:1) isn't a valid
    # placeholder key, so prefix it (b1). Named binds keep their name.
    return name if name.isidentifier() else f'b{name}'


def _translate_binds(sql: str, binds: Sequence) -> tuple[str, dict]:
    """Rewrite Oracle bind references to psycopg named placeholders and build the
    parameter dict (#516). Oracle binds by name, so a bind repeated in the text
    (``:x … :x``) is one value, and a ``:`` inside a string literal is not a bind
    — both of which a blind ``:name`` → ``%s`` substitution gets wrong. Distinct
    binds map to ``binds`` in first-appearance order (positional ``:1 :2`` and a
    single dict/list of values both land correctly)."""
    names: list[str] = []  # distinct bind names, in first-appearance order
    out: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        char = sql[i]
        if char == "'":  # copy a whole string literal verbatim ('' escapes a quote)
            out.append(char)
            i += 1
            while i < n:
                out.append(sql[i])
                if sql[i] == "'" and not (i + 1 < n and sql[i + 1] == "'"):
                    i += 1
                    break
                i += 2 if sql[i] == "'" else 1
            continue
        match = _BIND_REF.match(sql, i)
        if match is not None and (i == 0 or sql[i - 1] != ':'):
            name = match.group(1)
            if name not in names:
                names.append(name)
            out.append(f'%({_bind_key(name)})s')
            i = match.end()
            continue
        out.append(char)
        i += 1
    values = list(binds)
    params = {
        _bind_key(name): values[idx]
        for idx, name in enumerate(names)
        if idx < len(values)
    }
    return ''.join(out), params


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


# Oracle SQL functions / literal idioms → PostgreSQL (#502). Each is a function
# call or a literal keyword the suite uses; the rewrites are anchored on the
# call's `(` or a word boundary, so ordinary identifiers are left alone. Applied
# to every statement (a DEFAULT SYSDATE in DDL is rewritten too).
_IDIOM_REWRITES = [
    # HEXTORAW('DEADBEEF') → a RAW/bytea value from the hex string.
    (
        re.compile(r"\bhextoraw\s*\(\s*('(?:[^']|'')*')\s*\)", re.IGNORECASE),
        r"decode(\1, 'hex')",
    ),
    # RAWTOHEX(x) → the hex text of a bytea.
    (
        re.compile(r'\brawtohex\s*\(([^()]*)\)', re.IGNORECASE),
        r"encode(\1, 'hex')",
    ),
    # EMPTY_CLOB() / EMPTY_BLOB() → an empty string / empty bytea.
    (re.compile(r'\bempty_clob\s*\(\s*\)', re.IGNORECASE), "''"),
    (re.compile(r'\bempty_blob\s*\(\s*\)', re.IGNORECASE), "''::bytea"),
    # FROM_TZ(ts, 'zone') → interpret the naive timestamp as being in that zone.
    (
        re.compile(
            r"\bfrom_tz\s*\(\s*(.+?)\s*,\s*('(?:[^']|'')*')\s*\)", re.IGNORECASE
        ),
        r'(\1 AT TIME ZONE \2)',
    ),
    # (NVL, DECODE, TO_CHAR, TO_DATE, ADD_MONTHS, INSTR, … come from the orafce
    # extension — see __init__ — so they need no rewrite here.)
    # BINARY_DOUBLE/FLOAT special values → IEEE-754 float literals.
    (
        re.compile(r'\bbinary_(?:double|float)_infinity\b', re.IGNORECASE),
        "'Infinity'::float8",
    ),
    (
        re.compile(r'\bbinary_(?:double|float)_nan\b', re.IGNORECASE),
        "'NaN'::float8",
    ),
    # SYSDATE / SYSTIMESTAMP → the session clock (SYSDATE is to-the-second).
    (re.compile(r'\bsystimestamp\b', re.IGNORECASE), 'now()'),
    (re.compile(r'\bsysdate\b', re.IGNORECASE), 'localtimestamp(0)'),
    # A BINARY_DOUBLE / BINARY_FLOAT numeric literal suffix (1234.5678d, 1.5f) —
    # PostgreSQL has no such suffix, so drop it. A decimal point is required so
    # this never touches an identifier or a plain integer.
    (re.compile(r'\b(\d+\.\d+)[dfDF]\b'), r'\1'),
]


def _translate_idioms(sql: str) -> str:
    """Rewrite the Oracle SQL functions / literal idioms the suite uses to their
    PostgreSQL equivalents (#502). Applied to every statement."""
    for pattern, replacement in _IDIOM_REWRITES:
        sql = pattern.sub(replacement, sql)
    return sql


# Column types that are Oracle-only *for the version the Mirror advertises*
# (11.2) — native JSON is 21c+, VECTOR and BOOLEAN are 23ai+. The Mirror pins
# field version 11.2, so a real Oracle at that version rejects such a column with
# ORA-00902 (invalid datatype). PostgreSQL would instead accept JSON / BOOLEAN
# and reject VECTOR as an unknown type, so the suite's version guards (which skip
# on ORA-00902) never fired. Reject them here so those tests skip exactly as they
# do against a real pre-21c/23ai Oracle, rather than failing on a value the
# backend can't faithfully represent (#504). This is the honest ceiling: a
# PostgreSQL backend behind an 11.2 Mirror does not offer these types.
_ORA_INVALID_DATATYPE = 902
_ORACLE_ONLY_DDL_TYPES = re.compile(r'\b(JSON|VECTOR|BOOLEAN)\b', re.IGNORECASE)


def _reject_unsupported_ddl_types(sql: str) -> None:
    if not _IS_CREATE_TABLE.match(sql):
        return
    match = _ORACLE_ONLY_DDL_TYPES.search(sql)
    if match is not None:
        raise BackendError(
            f'invalid datatype: {match.group(1).upper()} is not available on '
            f'this server version',
            ora_code=_ORA_INVALID_DATATYPE,
        )


# --- PL/SQL: CREATE PROCEDURE / FUNCTION and callproc / callfunc (#503) ---------

# Oracle `CREATE [OR REPLACE] PROCEDURE|FUNCTION name (params) [RETURN t] AS|IS
# <body>`. The signature is close to PostgreSQL's; the body (BEGIN … END) is
# valid PL/pgSQL for the simple assignment / RETURN cases the suite uses.
_ROUTINE_DDL = re.compile(
    r'(?is)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(PROCEDURE|FUNCTION)\s+([\w.]+)\s*'
    r'\((.*)\)\s*(?:RETURN\s+([\w ]+?)\s+)?(?:AS|IS)\s+(.*?)\s*;?\s*$'
)
# Oracle parameter direction `IN OUT` → PostgreSQL `INOUT` (do this before the
# type rewrites, which share the DDL type list).
_PARAM_IN_OUT = re.compile(r'\bIN\s+OUT\b', re.IGNORECASE)


def _translate_routine_types(text: str) -> str:
    for pattern, replacement in _DDL_TYPE_REWRITES:
        text = pattern.sub(replacement, text)
    return text


def _translate_routine_ddl(sql: str) -> str:
    """Rewrite an Oracle ``CREATE PROCEDURE`` / ``CREATE FUNCTION`` to a PL/pgSQL
    routine (#503): translate the parameter types + ``IN OUT`` → ``INOUT``, map
    ``RETURN t`` → ``RETURNS t``, and wrap the ``BEGIN … END`` body as a
    ``LANGUAGE plpgsql`` dollar-quoted body. Non-routine SQL is unchanged."""
    match = _ROUTINE_DDL.match(sql)
    if match is None:
        return sql
    kind, name, params, return_type, body = match.groups()
    params = _translate_routine_types(_PARAM_IN_OUT.sub('INOUT', params))
    header = f'CREATE OR REPLACE {kind.upper()} {name}({params})'
    if kind.upper() == 'FUNCTION' and return_type:
        header += f' RETURNS {_translate_routine_types(return_type.strip())}'
    return f'{header} LANGUAGE plpgsql AS $$ {body} $$'


# The anonymous block a thin callproc / callfunc sends: BEGIN name(:a, :b); END;
# or BEGIN :r := name(:a, :b); END;
_CALL_BLOCK = re.compile(r'(?is)^\s*BEGIN\s+(.*?)\s*;?\s*END\s*;?\s*$')
_FUNC_CALL = re.compile(r'(?is)^\s*:(\d+)\s*:=\s*([\w.]+)\s*\((.*)\)\s*$')
_PROC_CALL = re.compile(r'(?is)^\s*([\w.]+)\s*\((.*)\)\s*$')
# A scalar OUT-bind assignment inside a block: `:ref := <expr>` (#517).
_OUT_ASSIGN = re.compile(r'(?is)^\s*:(\w+)\s*:=\s*(.+?)\s*$')


def _distinct_bind_refs(text: str) -> list[str]:
    # The distinct bind references in first-appearance order (their positions in
    # the Mirror's bind list), ignoring `:` inside string literals — the same
    # scan _translate_binds uses, so a ref's position stays consistent.
    seen: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "'":
            i += 1
            while i < n and text[i] != "'":
                i += 1
            i += 1
            continue
        match = _BIND_REF.match(text, i)
        if match is not None and (i == 0 or text[i - 1] != ':'):
            if match.group(1) not in seen:
                seen.append(match.group(1))
            i = match.end()
            continue
        i += 1
    return seen


def _parse_out_assignments(body: str) -> list[tuple[str, str]] | None:
    # An OUT-bind-assignment block is one or more `:ref := <expr>` statements
    # (BEGIN :y := 7*6; :2 := NULL; END). Returns (ref, expr) per assignment, or
    # None if any statement isn't such an assignment (so it isn't this shape).
    assignments = []
    for statement in filter(None, (s.strip() for s in body.split(';'))):
        match = _OUT_ASSIGN.match(statement)
        if match is None:
            return None
        assignments.append((match.group(1), match.group(2)))
    return assignments or None


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
    '22P02': 1722,  # invalid_text_representation -> invalid number (TO_NUMBER)
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
        # Lean on the `orafce` extension for Oracle-compatible SQL functions —
        # nvl, decode, to_char / to_date, add_months, instr, and much more —
        # rather than hand-rolling each rewrite. It installs those into the
        # `oracle` schema, so put it on the search_path; then only the idioms
        # orafce does NOT cover are translated in _translate_idioms. orafce is a
        # requirement of this backend (see the module docstring). Best-effort so a
        # PostgreSQL without it still starts — the uncovered idioms just fail as
        # before.
        try:
            self._conn.execute('CREATE EXTENSION IF NOT EXISTS orafce')
        except psycopg.Error:
            self._conn.rollback()
        self._conn.execute('SET search_path TO public, oracle')
        self._conn.commit()

    def authenticate(self, username: str) -> str | None:
        # The login store the Mirror authenticates clients against — separate
        # from the libpq `conninfo` the backend itself connects to PostgreSQL
        # with. A production backend might instead consult a PG table here.
        return credential_lookup(self._credentials, username)

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        # A PL/SQL block from callproc / callfunc arrives with BindVar binds (the
        # Mirror's OUT-bind flow); run it via CALL / SELECT and return the OUT
        # values (#503).
        if any(isinstance(b, BindVar) for b in binds):
            return self._execute_plsql(sql, binds)
        # Reject the column types that are Oracle-only for the version the Mirror
        # advertises (JSON/VECTOR/BOOLEAN), so the suite's version guards skip
        # rather than the backend mis-representing them (#504).
        _reject_unsupported_ddl_types(sql)
        # Translate Oracle SQL to PostgreSQL's dialect (#500/#502/#503) — DDL
        # column types, CREATE PROCEDURE/FUNCTION → PL/pgSQL, then the function /
        # literal idioms. This is where dialect knowledge belongs, not in the
        # generic compat shim.
        sql = _translate_idioms(_translate_routine_ddl(_translate_ddl(sql)))
        params: dict | None = None
        if binds:
            sql, params = _translate_binds(sql, binds)
        cursor = self._conn.cursor()
        # SAVEPOINT isolates this statement: on any error we roll back to here
        # (which also clears PostgreSQL's aborted-transaction state) and leave the
        # rest of the transaction intact; on success we release it. Either way
        # the savepoint is resolved, so they never accumulate across statements.
        cursor.execute('SAVEPOINT _mirror_stmt')
        try:
            cursor.execute(sql, params)
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

    def _execute_plsql(self, sql: str, binds: Sequence) -> Result:
        # A callproc / callfunc block. `binds` is one BindVar per positional bind
        # (:1 → index 0), value None for a pure OUT. Run the underlying routine and
        # return every bind's value in order (input for IN, the routine's result
        # for OUT / IN OUT / the function return) — the Mirror marks them all OUT
        # and the client keeps only the positions it bound as a Var (#483/#503).
        values = [b.value for b in binds]
        inner = _CALL_BLOCK.match(sql)
        statement = inner.group(1) if inner else ''
        try:
            func = _FUNC_CALL.match(statement)
            if func is not None:
                return self._call_function(func, values)
            proc = _PROC_CALL.match(statement)
            if proc is not None:
                return self._call_procedure(proc, values)
            assignments = _parse_out_assignments(statement)
            if assignments is not None:
                return self._eval_out_assignments(statement, assignments, binds, values)
            if inner is not None:
                # A block wrapping DML (BEGIN INSERT/UPDATE/DELETE …(:x); END) —
                # unwrap and run the inner statement with the binds.
                return self._run_block_statement(statement, values)
            # Not a shape we model — run it as-is (best effort) so a
            # side-effecting block still executes.
            self._conn.cursor().execute(_translate_idioms(sql))
            return Result(out_binds=values)
        except psycopg.Error as exc:
            self._conn.rollback()
            raise BackendError(str(exc).strip(), ora_code=_ora_code_for(exc)) from exc

    def _call_function(self, match: 're.Match', values: list) -> Result:
        # BEGIN :r := name(:a, :b); END;  →  SELECT name(a, b); the result is the
        # function's return value, written back into the :r bind position.
        ret_ref, name, args = match.groups()
        arg_refs = [int(r) for r in re.findall(r':(\d+)', args)]
        arg_values = [values[r - 1] for r in arg_refs]
        placeholders = ', '.join(['%s'] * len(arg_values))
        cursor = self._conn.cursor()
        cursor.execute(f'SELECT {name}({placeholders})', tuple(arg_values) or None)
        row = cursor.fetchone()
        out = list(values)
        out[int(ret_ref) - 1] = row[0] if row else None
        return Result(out_binds=out)

    def _call_procedure(self, match: 're.Match', values: list) -> Result:
        # BEGIN name(:a, :b); END;  →  CALL name(a, b); the OUT / IN OUT arguments
        # come back as a result row, in parameter order, which we place onto their
        # bind positions.
        name, args = match.groups()
        arg_refs = [int(r) for r in re.findall(r':(\d+)', args)]
        arg_values = [values[r - 1] for r in arg_refs]
        placeholders = ', '.join(['%s'] * len(arg_values))
        cursor = self._conn.cursor()
        cursor.execute(f'CALL {name}({placeholders})', tuple(arg_values) or None)
        returned = list(cursor.fetchone() or ()) if cursor.description else []
        modes = self._arg_modes(name, len(arg_refs))
        out = list(values)
        result_i = 0
        for position, ref in enumerate(arg_refs):
            is_out = modes[position] in ('o', 'b') if modes else False
            if is_out and result_i < len(returned):
                out[ref - 1] = returned[result_i]
                result_i += 1
        return Result(out_binds=out)

    def _eval_out_assignments(
        self, body: str, assignments: list, binds: Sequence, values: list
    ) -> Result:
        # BEGIN :a := <expr>; :b := <expr>; END — evaluate the right-hand sides
        # with one SELECT and place each result onto its bind position (#517).
        refs = _distinct_bind_refs(body)
        exprs = ', '.join(expr for _ref, expr in assignments)
        sql, params = _translate_binds(_translate_idioms(f'SELECT {exprs}'), values)
        cursor = self._conn.cursor()
        cursor.execute(sql, params)
        row = list(cursor.fetchone() or [])
        out = list(values)
        for (ref, _expr), result in zip(assignments, row):
            if ref in refs:
                out[refs.index(ref)] = result
        return Result(out_binds=out)

    def _run_block_statement(self, statement: str, values: list) -> Result:
        # A single DML statement unwrapped from a BEGIN … END block — run it with
        # the binds (#517). The block carried IN binds, so there are no OUT values
        # to return; the input values keep the bind positions aligned.
        sql, params = _translate_binds(
            _translate_idioms(_translate_ddl(statement)), values
        )
        self._conn.cursor().execute(sql, params)
        return Result(out_binds=values)

    def _arg_modes(self, name: str, nargs: int) -> list | None:
        # The parameter modes of a routine ('i' IN, 'o' OUT, 'b' IN OUT), so a
        # CALL's result row (which carries only the OUT / IN OUT values) can be
        # placed back onto the right bind positions. None means all-IN (PostgreSQL
        # leaves proargmodes NULL then).
        row = self._conn.execute(
            'SELECT proargmodes FROM pg_proc WHERE proname = %s '
            'ORDER BY oid DESC LIMIT 1',
            (name.split('.')[-1].lower(),),
        ).fetchone()
        if not row or not row[0]:
            return None
        return list(row[0])

    def change_password(
        self, username: str, old_password: str, new_password: str
    ) -> None:
        # The Mirror's client auth (the credential map) is separate from the
        # backend's PostgreSQL connection (a fixed conninfo), so a password change
        # updates only the map — a fresh Mirror session then authenticates with
        # the new password and the old one is rejected — without touching a
        # PostgreSQL role (which would break the backend's own conninfo). Oracle
        # validates the old password (ALTER USER … REPLACE); do the same against
        # the stored secret (#515). The map is shared across sessions.
        current = credential_lookup(self._credentials, username)
        if current is not None and old_password != current:
            raise BackendError('invalid username/password; logon denied', ora_code=1017)
        for name in list(self._credentials):
            if name.upper() == username.upper():
                self._credentials[name] = new_password
                return
        self._credentials[username.upper()] = new_password

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()
