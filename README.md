# seerdb

A pure-Python driver for a proprietary database, implementing the
[DB-API 2.0](https://peps.python.org/pep-0249/) interface by speaking the
database's native wire protocol (TNS/TTC) directly over TCP.

No proprietary client libraries or SDKs are required.

## Status

seerdb is a functional pure-Python driver: the core DB-API 2.0 and SQL
surface is stable, and it already covers async connection pooling, server-side
scrollable cursors, 23ai types (JSON / `BOOLEAN` / `VECTOR`), and the SODA
document store. It is usable for the features listed below; the feature matrix
spells out what is and isn't supported.

The wire protocol is reverse-engineered and implemented incrementally as a
clean-room effort — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the rules
contributors are expected to follow (no Oracle proprietary sources, no
decompiled binaries, no copied error-message catalogs; public references and
packet captures are fine).

What works:

- TNS transport layer (packet framing, fragmentation, SDU negotiation)
- TTC presentation layer (token encoding/decoding)
- Authentication handshake (O3LOGON, O5LOGON with 128/192/256-bit keys)
- Session setup and teardown
- SQL statement execution, full result-set decoding (DCB / RXH / RXD / BVC)
- DB-API 2.0 surface: `seerdb.connect()`, `Connection.cursor()`,
  `Cursor.execute / fetchone / fetchmany / fetchall / description /
  rowcount`, iteration protocol, context managers, PEP 249 exception
  hierarchy
- DB-API conveniences: `Connection.stmtcachesize` (read/write statement-
  cache size), `Connection.version` (server release string, e.g.
  `"11.2.0.2.0"`), `Cursor.rowfactory` (callable applied to each fetched
  row, invoked with the column values as positional arguments), and
  `Cursor.lastrowid` (ROWID of the last row an INSERT / UPDATE / DELETE
  touched). Sync and async
- Scrollable cursors: open with `conn.cursor(scrollable=True)`, then
  `Cursor.scroll(value, mode)` with `mode` in `relative` / `absolute` /
  `first` / `last` repositions the cursor and the next `fetchone()` returns
  the row at the new position (out-of-range raises `IndexError`). On 10g+
  the cursor is opened server-side and rows are fetched on demand as you
  scroll; 9i uses a client-buffered fallback. Sync and async
- Bind variables: `cur.execute(sql, [v1, v2])` (positional) or
  `cur.execute(sql, {"name": v})` (named, `:name` placeholders, case-
  insensitive); accepted bind types are `int`, `float`, `Decimal`,
  `str`, `bytes`, `bool`, `datetime.date` / `datetime` (with optional
  timezone and microseconds), `datetime.timedelta` (→ INTERVAL DAY TO
  SECOND), `seerdb.IntervalYM(years, months)` (→ INTERVAL YEAR TO
  MONTH), and `None`. A plain `float` binds as NUMBER; wrap it in
  `seerdb.BinaryFloat(x)` / `seerdb.BinaryDouble(x)` to send a native
  32/64-bit IEEE-754 binary float (the only way to bind `inf` / `nan`,
  which a non-finite plain `float` also auto-routes to BINARY_DOUBLE).
  `str` and `bytes` binds round-trip into CLOB / BLOB columns at any
  size: a value larger than the regular ~32 KiB ceiling is streamed to
  the server across multiple TNS packets (tested byte-for-byte to
  hundreds of KiB on both 11g and 12c+)
- Anonymous PL/SQL blocks with bind variables: `cur.execute("BEGIN
  ... :x ...; END;", [val])` runs the block server-side
- Stored procedures and OUT / IN OUT binds: `cur.callproc(name,
  [in_val, out_var, ...])` where an OUT / IN OUT argument is a
  `cur.var(type)` (type is a Python type or an `seerdb` constant like
  `seerdb.NUMBER` / `seerdb.STRING` / `seerdb.DB_TYPE_TIMESTAMP` /
  `seerdb.DB_TYPE_TIMESTAMP_TZ` / `seerdb.DB_TYPE_BINARY_FLOAT` /
  `seerdb.DB_TYPE_BINARY_DOUBLE` / `seerdb.DB_TYPE_INTERVAL_DS` /
  `seerdb.DB_TYPE_INTERVAL_YM`). Seed an IN OUT value with
  `var.setvalue(0, v)`; read results with `var.getvalue()`. `callproc`
  returns the argument list with OUT slots replaced by their values.
  OUT binds also work through `cur.execute` directly (pass a `Var`).
  Stored functions: `cur.callfunc(name, return_type, [args...])` returns
  the function's value (`return_type` is a Python type or `seerdb`
  constant). A REF CURSOR OUT parameter is a `cur.var(seerdb.CURSOR)`;
  after the call `var.getvalue()` is a ready-to-fetch nested cursor.
  Available on both the sync and async cursors
- Array DML: `cur.executemany(sql, [row1, row2, ...])` binds every row
  and executes the whole batch in a single server round trip (one parse,
  N iterations) instead of one `execute` per row; `cursor.rowcount`
  reflects the total rows affected. Column types are taken from the
  first row. Sync and async
- Python type coercion for fetched values: NUMBER → `int` / `Decimal`,
  VARCHAR2 / CHAR → `str` (charset-aware), DATE / TIMESTAMP / TIMESTAMP
  WITH TIME ZONE → `datetime.datetime` (a named-region zone, e.g.
  `US/Eastern`, resolves to the correct DST-aware offset via the stdlib
  `zoneinfo`, not a frozen Oracle offset table), BINARY_FLOAT / BINARY_DOUBLE →
  `float`, INTERVAL DAY TO SECOND → `datetime.timedelta`, INTERVAL YEAR
  TO MONTH → `seerdb.IntervalYM`, ROWID → `str` (the 18-char extended
  rowid, usable directly in a `WHERE ROWID = :r` bind), UROWID → `str`
  (the `*`-prefixed universal rowid, e.g. for index-organized tables),
  LONG → `str`, LONG RAW → `bytes`, NULL → `None`
- TLS connections (pass `ssl=True` to `seerdb.connect` for the system
  trust store; or `ssl={"ca_certs": ..., "certfile": ..., ...}` for a
  custom configuration; or hand in an `ssl.SSLContext` directly)
- DML rowcount and full server error messages: `cursor.rowcount`
  reflects the rows affected by `INSERT` / `UPDATE` / `DELETE` (read
  from the OER block); `DatabaseError(code=NNN)` carries the full
  `"ORA-NNNNN: ..."` text the server sent, not just the numeric code
- Follow-up `TTI_FETCH` flow for result sets larger than a single
  server response — `OracleConnect.execute` automatically drains the
  cursor when the EXEC OER signals `call_status = 1`
- Arrow / DataFrame bulk fetch: `cur.fetch_df_all()` returns the result
  set as a `pyarrow.Table`, `cur.fetch_df_batches(size=N)` yields it as
  record batches (column types derived from the describe, so a NUMBER /
  Decimal column lands as the right Arrow type without inference). Sync
  and async
- LOB content: CLOB / BLOB columns in a SELECT round-trip as `str` /
  `bytes` of any size. `Cursor.execute` automatically issues a
  `TTI_LOBOPS` READ for each non-empty LOB cell, materialising the
  content from the server. NULL LOBs come back as `None`;
  `EMPTY_CLOB()` / `EMPTY_BLOB()` as `""` / `b""`
- BFILE read: SELECT of a `BFILENAME(...)` / BFILE column round-trips
  the external file contents as `bytes`, read natively over
  `TTI_LOBOPS` (`FILE_OPEN` → `READ` → `FILE_CLOSE`). The only
  privilege the user needs is READ on the relevant DIRECTORY object —
  no server-side PL/SQL helper or CREATE PROCEDURE is installed
- Transaction control (commit, rollback, ping); sessionless transactions
  (start / suspend / resume by transaction id)
- End-to-end application tracing: `connection.module` / `action` /
  `client_identifier` / `clientinfo` / `dbop` flow to the server for
  monitoring (V$SESSION etc.)
- Multiple character set support, including the national charset: bind
  full Unicode through `DB_TYPE_NVARCHAR` / `DB_TYPE_NCHAR` regardless of
  the database charset, and read NVARCHAR2 / NCHAR / NCLOB back as `str`
- Cursor caching for DML: repeat `execute()` of the same INSERT /
  UPDATE / DELETE reuses the server-side cursor handle and skips
  the parse step. Cache size capped at 32 entries per connection
  (LRU eviction)
- Connection pool: `seerdb.create_pool(host=..., user=...,
  password=..., service_name=..., min=2, max=10)` returns a
  thread-safe pool of warm authenticated connections. `pool.acquire()`
  returns a context manager that releases on `__exit__`. Idle
  connections health-check on next acquire (configurable via
  `idle_timeout`)
- Async (asyncio) API: `await seerdb.connect_async(...)` returns
  an `AsyncOracleConnect`; `conn.cursor()` returns an
  `AsyncCursor` with `await cur.execute(...)`, `await cur.fetchone()`,
  `async for row in cur` iteration, and `async with` context
  managers. LOB cells (CLOB / BLOB / BFILE) auto-resolve through
  `await lob.aread()` exactly like the sync path. Async pool
  via `await seerdb.create_pool_async(...)` with the same
  `acquire/release/idle health-check` semantics as the sync `Pool`.
  Shares the protocol code with the sync APIs; the duplication is
  just the I/O layer
- SODA (Simple Oracle Document Access), 18c+: `conn.getSodaDatabase()`
  returns a `SodaDatabase` for JSON document collections —
  `createCollection` / `openCollection` / `getCollectionNames`, document
  `insertOne` / `insertOneAndGet` / `insertMany`, upsert `save` /
  `saveAndGet`, query-by-example
  `find().filter(...).getDocuments()` / `getOne()` / `count()` /
  `skip` / `limit` and streaming `getCursor()`,
  `replaceOne` / `replaceOneAndGet` / `remove`, and
  `createIndex` / `dropIndex` / `getDataGuide`. Built on `DBMS_SODA`.
  Sync and async

## Design goals & non-goals

seerdb is **pure Python by design** — no C extensions, no build step, no
compiler, and no Oracle Instant Client. It installs anywhere CPython runs
(`pip install`, no per-platform wheels), the whole package is type-annotated and
mypy-checked in CI, and the source stays easy to read, audit, and contribute to.

Staying pure Python is a deliberate **non-goal to add Cython or native
extensions**: they would trade that portability and readability for speed the
project does not need today. If a hot path ever warrants it, the plan is to
profile with the benchmark harness (#166) and optimize the Python — or ship an
*optional* accelerator with a pure-Python fallback — never a hard C dependency.

## Compatibility

The driver negotiates the TTC field version per connection, so a single build
speaks to every supported server:

| Oracle Database | Status | Notes |
| --- | --- | --- |
| 23ai | ✅ supported | fast-auth login at field version 24; JSON / OSON, native `BOOLEAN`, `VECTOR` (dense + sparse), column annotations |
| 21c | ✅ supported | |
| 19c · 18c · 12c | ✅ supported | same 12c+ wire protocol as 21c |
| 11g (11.2) | ✅ supported | primary reference tier |
| 10g (10.2) | ✅ supported | |
| 9i (9.2) | ✅ common surface | the legacy field-version-2 (`TTI_ALL7`) dialect — see the matrix note |

CI runs the offline suite on Python 3.10–3.13 and the integration suite against
live 11g, 21c and 23ai; 10g and 9i are validated locally, and 12c–19c share the
12c+ protocol the 21c tier exercises.

## Feature matrix

| Area | Support |
| --- | --- |
| **DB-API 2.0** — `connect`, cursors, `execute` / `executemany`, `fetchone` / `fetchmany` / `fetchall`, `description`, `rowcount`, iteration, context managers, PEP 249 exception hierarchy | ✅ |
| **Bind variables** — positional & named (`:name`), all scalar types, `None` | ✅ |
| **Scalar types** — NUMBER, VARCHAR2 / CHAR / NVARCHAR2 / NCHAR, DATE, TIMESTAMP [WITH [LOCAL] TIME ZONE], INTERVAL DAY-SECOND / YEAR-MONTH, RAW, BINARY_FLOAT / BINARY_DOUBLE, ROWID / UROWID | ✅ |
| **LONG / LONG RAW** | ✅ |
| **LOBs** — CLOB, NCLOB, BLOB, BFILE read; large `str` / `bytes` → CLOB / BLOB binds (streamed past the ~32 KiB inline limit) | ✅ |
| **23ai types** — JSON / OSON, `BOOLEAN`, `VECTOR` (dense + sparse) | ✅ |
| **23ai column annotations** — `cursor.annotations` (per-column `{name: value}` maps), via fast-auth at field version 24 | ✅ |
| **PL/SQL** — anonymous blocks, `callproc`, `callfunc`, OUT / IN OUT binds, REF CURSOR OUT | ✅ |
| **Transactions** — commit, rollback, autocommit, ping | ✅ |
| **Array DML** — `executemany`, `getbatcherrors`, `getarraydmlrowcounts` (12.1+) | ✅ |
| **Result handling** — large-result `TTI_FETCH` drain, server-side scrollable cursors (`scroll()`, with a client-buffered fallback), `rowfactory`, `lastrowid` | ✅ |
| **Arrow / DataFrame fetch** — `cursor.fetch_df_all` / `fetch_df_batches` (pyarrow `Table` / record batches) | ✅ |
| **SODA** — document store over `DBMS_SODA`: collections, documents, query-by-example (with streaming), insert / read / upsert / update / delete / bulk, indexing + data guide (18c+) | ✅ |
| **Connection** — pool (warm sessions + idle health-check), statement cache, `changepassword`, TLS | ✅ |
| **Authentication** — O3LOGON (8i / 9i) and O5LOGON (10g+, 128 / 192 / 256-bit) | ✅ |
| **Async** — full `asyncio` API (connection, cursor, pool) at parity with the sync API | ✅ |
| **Character sets** — AL32UTF8 and others; national-charset (`DB_TYPE_NVARCHAR` / `NCHAR`) binds | ✅ |
| Advanced Queuing (AQ), Continuous Query Notification (CQN), implicit results, DRCP, sharding, XA / distributed transactions | ❌ not implemented |

Most of the above works across every supported server version; a few features
are inherently version-scoped: the **23ai types** need 23ai (`VECTOR` /
`BOOLEAN`) or 21c+ (JSON), **SODA** needs 18c+, and **array DML** needs 12.1+.

**Oracle 9i** (the legacy field-version-2 / `TTI_ALL7` dialect) runs the common
surface — DB-API, scalar and national-charset binds, DATE / TIMESTAMP / INTERVAL,
RAW, small LONG, LOB reads, single-row DML, PL/SQL blocks with IN / OUT / IN OUT
binds, transactions, and the full async API — but not the features later versions
layer on top: `BINARY_FLOAT` / `BINARY_DOUBLE`, large streamed LOB / LONG binds,
array DML, REF CURSOR, the cursor cache, and `changepassword`. Its DB charset
also can't store text it doesn't cover, so use `DB_TYPE_NVARCHAR` / `NCHAR` for
full Unicode there rather than a plain `str` bind.

## Requirements

- Python >= 3.10
- [pycryptodome](https://pypi.org/project/pycryptodome/) — login/auth crypto
- [tzdata](https://pypi.org/project/tzdata/) — IANA time-zone database for
  named-region `TIMESTAMP WITH TIME ZONE` values (a no-op where the OS ships
  system zoneinfo)
- [pyarrow](https://pypi.org/project/pyarrow/) — backs the Arrow / DataFrame
  bulk fetch (`cursor.fetch_df_all` / `fetch_df_batches`)

## Installation

```
pip install .
```

## Quick start

```python
import seerdb

with seerdb.connect(host="dbhost", port=1521, user="scott",
                    password="tiger", service_name="MYDB") as conn:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, name FROM employees WHERE dept = :dept ORDER BY id",
            {"dept": "ENG"},
        )
        for row in cur:
            print(row)
```

## Quick start (async)

```python
import asyncio
import seerdb


async def main():
    async with await seerdb.connect_async(
        host="dbhost", port=1521, user="scott",
        password="tiger", service_name="MYDB",
    ) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, name FROM employees WHERE dept = :dept ORDER BY id",
                {"dept": "ENG"},
            )
            async for row in cur:
                print(row)


asyncio.run(main())
```

A connection pool keeps authenticated sessions warm. Sync:

```python
pool = seerdb.create_pool(host="dbhost", user="scott",
                          password="tiger", service_name="MYDB",
                          min=2, max=10)
with pool.acquire() as conn:
    ...
pool.close()
```

Async:

```python
pool = await seerdb.create_pool_async(host="dbhost", user="scott",
                                       password="tiger", service_name="MYDB",
                                       min=2, max=10)
async with pool.acquire() as conn:
    ...
await pool.close()
```

## Running tests

The default test suite is offline (encoders, crypto, packet round-trips):

```
python3 -m unittest discover -v tests/
```

A second suite of **integration tests** exercises type coercion and the
Cursor API against a real database. They are skipped unless connection
parameters are exported in the environment:

```
export PYORACLE_TEST_USER=pyo
export PYORACLE_TEST_PASSWORD=pyo123
export PYORACLE_TEST_HOST=localhost          # optional, default localhost
export PYORACLE_TEST_PORT=1521               # optional, default 1521
export PYORACLE_TEST_SERVICE=XE              # optional, default XE
python3 -m unittest discover -v tests/
```

The user only needs `CREATE SESSION` and `CREATE TABLE` privileges plus
a writable tablespace. Each test creates and drops its own scratch
table.

> **Connect-rate note.** Oracle XE rate-limits very rapid new connections
> at the listener (issue #7). The suite opens a fresh connection per test,
> so it keeps a small pre-connect pause (default 50&nbsp;ms, override with
> `PYORACLE_TEST_CONNECT_DELAY`) to stay under that limit; the `Pool`
> (issue #6) avoids it entirely by keeping connections warm. At the default
> pace the suite runs clean.
>
> Earlier this surfaced as a `ORA-01013` ("user requested cancel") flake
> roughly one run in five: a mid-session cancel (from the throttle or an
> errored call) tripped the driver's break/reset handling, desynced the
> connection and cascaded into many failures. That driver bug was fixed in
> issue #45, so the default-pace suite is now reliably green. Only running
> with *no* pre-connect pause at all still trips the raw listener throttle,
> which now shows up as dropped connections rather than `ORA-01013`.

## Contributing

Pull requests are welcome. Please read
[`CONTRIBUTING.md`](CONTRIBUTING.md) first — seerdb's clean-room
posture means there are a few sources you must NOT consult when
preparing a contribution, and a few citation expectations to follow
when you open a PR.

## Trademarks

Oracle and Oracle Database are trademarks or registered trademarks of Oracle
Corporation and/or its affiliates. seerdb is an independent, unaffiliated,
clean-room project — not endorsed by, sponsored by, or affiliated with Oracle
Corporation. References to "Oracle" are nominative, describing the database this
driver interoperates with. See [`NOTICE`](NOTICE).

## License

Licensed under the [MIT License](LICENSES/MIT.txt).
This project is [REUSE](https://reuse.software/) compliant.
