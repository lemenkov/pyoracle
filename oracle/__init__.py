# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# PEP 249 (DB-API 2.0) module-level attributes.
apilevel = "2.0"
threadsafety = 1            # threads may share the module, not connections
paramstyle = "named"        # bind variables not yet wired through Cursor

from oracle.connection import OracleConnect
from oracle.exceptions import (
    DataError, DatabaseError, Error, IntegrityError, InterfaceError,
    InternalError, NotSupportedError, OperationalError, ProgrammingError,
    Warning,
)


def connect(*args, **kwargs) -> OracleConnect:
    """PEP 249 connect() factory. Returns a connected OracleConnect."""
    Conn = OracleConnect(*args, **kwargs)
    Conn.connect()
    return Conn


__all__ = [
    "apilevel", "threadsafety", "paramstyle",
    "connect", "OracleConnect",
    "Warning", "Error", "InterfaceError", "DatabaseError", "DataError",
    "OperationalError", "IntegrityError", "InternalError",
    "ProgrammingError", "NotSupportedError",
]
