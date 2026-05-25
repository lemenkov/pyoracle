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
from oracle.pool import Pool


def connect(*args, **kwargs) -> OracleConnect:
    """PEP 249 connect() factory. Returns a connected OracleConnect."""
    Conn = OracleConnect(*args, **kwargs)
    Conn.connect()
    return Conn


def create_pool(*args, **kwargs) -> Pool:
    """Create a `Pool` of authenticated connections.

    All `oracle.connect()` keyword arguments are accepted and forwarded
    to each pooled connection. Pool-specific knobs:

      - ``min`` / ``max`` (default 1 / 4): bounds on the pool size.
      - ``increment`` (default 1): how aggressively the pool grows
        (reserved for future load-aware behaviour; currently grows by
        one connection at a time on demand).
      - ``timeout`` (default 30s): how long `acquire()` blocks when the
        pool is at `max` before raising `InterfaceError`. `None` waits
        forever.
      - ``idle_timeout`` (default 60s): a free connection idle this
        long gets a ``SELECT 1 FROM DUAL`` health-check on the next
        acquire. `None` disables the check.
      - ``health_check`` (default True): set False to skip pings
        entirely.
    """
    return Pool(*args, **kwargs)


__all__ = [
    "apilevel", "threadsafety", "paramstyle",
    "connect", "create_pool", "OracleConnect", "Pool",
    "Warning", "Error", "InterfaceError", "DatabaseError", "DataError",
    "OperationalError", "IntegrityError", "InternalError",
    "ProgrammingError", "NotSupportedError",
]
