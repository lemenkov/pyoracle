# pyoracle

A pure-Python driver for a proprietary database, implementing the
[DB-API 2.0](https://peps.python.org/pep-0249/) interface by speaking the
database's native wire protocol (TNS/TTC) directly over TCP.

No proprietary client libraries or SDKs are required.

## Status

This project is in early development. The wire protocol is being
reverse-engineered and implemented incrementally as a clean-room
effort — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the rules
contributors are expected to follow (no Oracle proprietary sources,
no decompiled binaries, no copied error-message catalogs; public
references and packet captures are fine).

What works so far:

- TNS transport layer (packet framing, fragmentation, SDU negotiation)
- TTC presentation layer (token encoding/decoding)
- Authentication handshake (O3LOGON, O5LOGON with 128/192/256-bit keys)
- Session setup and teardown
- SQL statement execution, full result-set decoding (DCB / RXH / RXD / BVC)
- DB-API 2.0 surface: `oracle.connect()`, `Connection.cursor()`,
  `Cursor.execute / fetchone / fetchmany / fetchall / description /
  rowcount`, iteration protocol, context managers, PEP 249 exception
  hierarchy
- Bind variables: `cur.execute(sql, [v1, v2])` (positional) or
  `cur.execute(sql, {"name": v})` (named, `:name` placeholders, case-
  insensitive); accepted bind types are `int`, `float`, `Decimal`,
  `str`, `bytes`, `bool`, `datetime.date` / `datetime` (with optional
  timezone and microseconds), and `None`
- Python type coercion for fetched values: NUMBER → `int` / `Decimal`,
  VARCHAR2 / CHAR → `str` (charset-aware), DATE / TIMESTAMP / TIMESTAMP
  WITH TIME ZONE → `datetime.datetime`, NULL → `None`
- TLS connections (pass `ssl=True` to `oracle.connect` for the system
  trust store; or `ssl={"ca_certs": ..., "certfile": ..., ...}` for a
  custom configuration; or hand in an `ssl.SSLContext` directly)
- DML rowcount and full server error messages: `cursor.rowcount`
  reflects the rows affected by `INSERT` / `UPDATE` / `DELETE` (read
  from the OER block); `DatabaseError(code=NNN)` carries the full
  `"ORA-NNNNN: ..."` text the server sent, not just the numeric code
- Follow-up `TTI_FETCH` flow for result sets larger than a single
  server response — `OracleConnect.execute` automatically drains the
  cursor when the EXEC OER signals `call_status = 1`
- Transaction control (commit, rollback, ping)
- Multiple character set support

What is still in progress:

- Cursor caching
- **LOB column row format.** With the FETCH flow in place,
  SELECTs that reference LOB columns now reach the row stage — but
  the row decoder doesn't yet understand the LOB column structure
  (`ub4 num_bytes | ub8 size | ub4 chunk_size | DALC locator`, plus
  inline content for small CLOBs). See `docs/PROTOCOL.md §11.9` for
  the wire layout. Once that's in, a follow-up `TTI_LOBOPS` round
  trip (`§14`) can resolve out-of-line LOB content.
- Connection pooling

## Requirements

- Python >= 3.10
- [pycryptodome](https://pypi.org/project/pycryptodome/)

## Installation

```
pip install .
```

## Quick start

```python
import oracle

with oracle.connect(host="dbhost", port=1521, user="scott",
                    password="tiger", service_name="MYDB") as conn:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, name FROM employees WHERE dept = :dept ORDER BY id",
            {"dept": "ENG"},
        )
        for row in cur:
            print(row)
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

> **Known flake.** A small number of integration tests occasionally fail
> with `ORA-01013` ("user requested cancel of current operation") under
> rapid connect/disconnect churn — a residual protocol-state issue in the
> driver that surfaces when the same socket is hammered with statements
> in quick succession. A single re-run typically clears it.

## Contributing

Pull requests are welcome. Please read
[`CONTRIBUTING.md`](CONTRIBUTING.md) first — pyoracle's clean-room
posture means there are a few sources you must NOT consult when
preparing a contribution, and a few citation expectations to follow
when you open a PR.

## License

Licensed under the [MIT License](LICENSES/MIT.txt).
This project is [REUSE](https://reuse.software/) compliant.
