# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# PEP 249 (DB-API 2.0) module-level attributes.
apilevel = "2.0"
threadsafety = 1            # threads may share the module, not connections
paramstyle = "named"        # bind variables not yet wired through Cursor

from oracle.aconnection import AsyncOracleConnect
from oracle.apool import AsyncPool
from oracle.connection import OracleConnect, Xid
from oracle.tns_consts import (
    TPC_BEGIN_NEW, TPC_BEGIN_JOIN, TPC_BEGIN_RESUME, TPC_BEGIN_PROMOTE,
    TPC_END_NORMAL, TPC_END_SUSPEND,
)
from oracle.dbobject import DbObject, DbObjectType, DbRef
from oracle.aq import Queue, MessageProperties, EnqOptions, DeqOptions
from oracle.datatypes import (
    CURSOR, DB_TYPE_BINARY_DOUBLE, DB_TYPE_BINARY_FLOAT, DB_TYPE_CURSOR,
    DB_TYPE_DATE, DB_TYPE_INTERVAL_DS, DB_TYPE_INTERVAL_YM, DB_TYPE_NUMBER,
    DB_TYPE_RAW, DB_TYPE_TIMESTAMP, DB_TYPE_TIMESTAMP_TZ, DB_TYPE_VARCHAR,
    NUMBER, STRING, BinaryDouble, BinaryFloat, IntervalYM, JSON, Var,
)
from oracle.exceptions import (
    DataError, DatabaseError, Error, IntegrityError, InterfaceError,
    InternalError, NotSupportedError, OperationalError, ProgrammingError,
    Warning,
)
from oracle.pool import Pool
from oracle.vector import SparseVector


def connect(*args, **kwargs) -> OracleConnect:
    """PEP 249 connect() factory. Returns a connected OracleConnect."""
    Conn = OracleConnect(*args, **kwargs)
    Conn.connect()
    return Conn


async def connect_async(*args, **kwargs) -> AsyncOracleConnect:
    """Async counterpart to `connect()`. Returns a connected
    `AsyncOracleConnect`. Same constructor arguments as `connect`."""
    Conn = AsyncOracleConnect(*args, **kwargs)
    await Conn.connect()
    return Conn


async def create_pool_async(*args, **kwargs) -> AsyncPool:
    """Create an `AsyncPool` and pre-warm `min` connections.

    Same keyword arguments as `create_pool` (plus the regular
    `oracle.connect()` kwargs forwarded to each pooled connection).
    """
    Pool_ = AsyncPool(*args, **kwargs)
    await Pool_.prewarm()
    return Pool_


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
    "connect", "connect_async", "create_pool", "create_pool_async",
    "OracleConnect", "AsyncOracleConnect", "Pool", "AsyncPool",
    "BinaryFloat", "BinaryDouble", "IntervalYM", "JSON", "SparseVector", "Var",
    "DbObject", "DbObjectType", "DbRef", "Xid",
    "Queue", "MessageProperties", "EnqOptions", "DeqOptions",
    "TPC_BEGIN_NEW", "TPC_BEGIN_JOIN", "TPC_BEGIN_RESUME", "TPC_BEGIN_PROMOTE",
    "TPC_END_NORMAL", "TPC_END_SUSPEND",
    "NUMBER", "STRING", "DB_TYPE_NUMBER", "DB_TYPE_VARCHAR",
    "DB_TYPE_RAW", "DB_TYPE_DATE", "CURSOR", "DB_TYPE_CURSOR",
    "DB_TYPE_TIMESTAMP", "DB_TYPE_TIMESTAMP_TZ", "DB_TYPE_BINARY_FLOAT",
    "DB_TYPE_BINARY_DOUBLE", "DB_TYPE_INTERVAL_DS", "DB_TYPE_INTERVAL_YM",
    "Warning", "Error", "InterfaceError", "DatabaseError", "DataError",
    "OperationalError", "IntegrityError", "InternalError",
    "ProgrammingError", "NotSupportedError",
]
