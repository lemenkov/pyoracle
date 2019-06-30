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
- SQL statement execution and row fetching (encoding side)
- Transaction control (commit, rollback, ping)
- Multiple character set support

What is still in progress:

- Full result set decoding and data type conversion
- Cursor caching
- LOB support
- SSL/TLS connections
- Connection pooling
- Comprehensive error handling

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
