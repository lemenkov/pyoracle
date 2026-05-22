# pyoracle

A pure-Python driver for a proprietary database, implementing the
[DB-API 2.0](https://peps.python.org/pep-0249/) interface by speaking the
database's native wire protocol (TNS/TTC) directly over TCP.

No proprietary client libraries or SDKs are required.

## Status

This project is in early development. The wire protocol is being
reverse-engineered and implemented incrementally.

What works so far:

- TNS transport layer (packet framing, fragmentation, SDU negotiation)
- TTC presentation layer (token encoding/decoding)
- Authentication handshake (O3LOGON, O5LOGON with 128/192/256-bit keys)
- Session setup and teardown
- SQL statement execution
- Result set decoding at the wire level (DCB column metadata, RXH/RXD/BVC
  row data) — values are returned as raw Oracle bytes
- Transaction control (commit, rollback, ping)
- Multiple character set support

What is still in progress:

- Cursor caching
- LOB support
- SSL/TLS connections
- Connection pooling
- Comprehensive error handling

## Roadmap

In rough order of leverage for making this usable beyond protocol experiments:

1. **Python type coercion for fetched values.** The wire bytes are already
   surfaced in the row tuples — NUMBER comes back as e.g. `b'\xc1\x02'`,
   DATE as a 7-byte Oracle date, VARCHAR as UTF-8 bytes. Convert these to
   `int` / `float` / `Decimal` / `datetime` / `str` based on the column
   metadata from the DCB block.
2. **DB-API 2.0 `Cursor` with `fetchone` / `fetchmany` / `fetchall` /
   `description`.** Today `OracleConnect.execute` returns the raw decoder
   tuple; PEP 249 callers expect a cursor object with the standard methods.
3. **Bind variables.** `execute(sql, [1, 'alpha'])` instead of inlining
   literals into the SQL string. The encoding side (`encode_token_rxd` /
   `encode_token_oac` in `oracle/tns.py`) already supports binds; the
   missing piece is plumbing them through the cursor API. Also closes a
   SQL-injection footgun.

## Requirements

- Python >= 3.10
- [pycryptodome](https://pypi.org/project/pycryptodome/)

## Installation

```
pip install .
```

## Quick start

```python
from oracle.connection import OracleConnect

conn = OracleConnect(
    host="dbhost",
    port=1521,
    user="scott",
    password="tiger",
    service_name="MYDB",
)
conn.connect()
```

## Running tests

```
python3 -m unittest discover -v tests/
```

## Contributing

Pull requests are welcome.

## License

Licensed under the [MIT License](LICENSES/MIT.txt).
This project is [REUSE](https://reuse.software/) compliant.
