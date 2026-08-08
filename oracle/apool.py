# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Async connection pool.

Async-native counterpart to `oracle.pool.Pool`. Same shape — pre-warm
to `min`, grow lazily to `max`, optional health-check on idle reacquire
— but the synchronisation primitives are `asyncio.Lock` and
`asyncio.Condition` so concurrent coroutines wait on a free entry
without blocking the event loop.

Usage:

    pool = await oracle.create_pool_async(
        host=..., user=..., password=..., service_name=...,
        min=2, max=10,
    )
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1 FROM dual")
    await pool.close()
"""

import asyncio
import time
from collections import deque

from oracle.aconnection import AsyncOracleConnect
from oracle.exceptions import InterfaceError


class _AsyncPoolEntry:
    """One pooled async connection plus its last-used timestamp."""

    __slots__ = ('conn', 'released_at')

    def __init__(self, conn: AsyncOracleConnect):
        self.conn = conn
        self.released_at = time.monotonic()


class _AsyncPooledConnectionGuard:
    """Async context manager returned by `AsyncPool.acquire()`.
    Releases on `__aexit__` even if the user's block raised."""

    __slots__ = ('_pool', '_conn')

    def __init__(self, pool: 'AsyncPool', conn: AsyncOracleConnect):
        self._pool = pool
        self._conn = conn

    async def __aenter__(self) -> AsyncOracleConnect:
        return self._conn

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._pool.release(self._conn)


class AsyncPool:
    """Async-native pool of `AsyncOracleConnect` instances.

    Construction does NOT pre-warm — there's no event loop at
    `__init__` time and we want the pool to be usable from
    synchronous helper code that calls `AsyncPool(...)` and only
    later enters the loop. Instead, the first batch of `min`
    connections is opened lazily on the first `acquire()`.

    Use `create_pool_async()` (module-level helper) to pre-warm
    explicitly in an async context.
    """

    def __init__(
        self,
        min: int = 1,
        max: int = 4,
        increment: int = 1,
        timeout: float | None = 30.0,
        idle_timeout: float | None = 60.0,
        health_check: bool = True,
        **connect_kwargs,
    ):
        if min < 0 or max <= 0 or min > max:
            raise ValueError(
                f'invalid pool sizes: min={min}, max={max} '
                f'(need 0 <= min <= max and max > 0)'
            )
        if increment <= 0:
            raise ValueError(f'increment must be positive, got {increment}')
        self._min = min
        self._max = max
        self._increment = increment
        self._timeout = timeout
        self._idle_timeout = idle_timeout
        self._health_check = health_check
        self._connect_kwargs = connect_kwargs

        # asyncio.Condition wraps an asyncio.Lock; same usage as the
        # sync Pool but everything is await-based. Created lazily so
        # the pool can be constructed outside an event loop.
        self._lock: asyncio.Lock | None = None
        self._available: asyncio.Condition | None = None
        self._free: deque[_AsyncPoolEntry] = deque()
        self._in_use: set[int] = set()
        self._closed = False
        self._prewarmed = False

    # ----- public API -----

    async def prewarm(self) -> None:
        """Open `min` connections up front. Idempotent. Normally called
        for you by the first `acquire()`; `create_pool_async()` calls
        it eagerly so the construction call awaits the opens."""
        cond = self._ensure_sync_primitives()
        async with cond:
            if self._prewarmed or self._closed:
                return
            self._prewarmed = True
            for _ in range(self._min):
                Conn = await self._open_connection()
                self._free.append(_AsyncPoolEntry(Conn))

    def acquire(self) -> '_AcquireContext':
        """Return an async context manager that yields a free
        connection (or opens a fresh one, up to `max`). Use as:

            async with pool.acquire() as conn:
                ...
        """
        return _AcquireContext(self)

    async def release(self, conn: AsyncOracleConnect) -> None:
        """Return a connection to the pool. Idempotent; releasing a
        connection not produced by this pool raises InterfaceError."""
        cond = self._ensure_sync_primitives()
        async with cond:
            CheckoutId = id(conn)
            if CheckoutId not in self._in_use:
                raise InterfaceError('connection was not acquired from this pool')
            self._in_use.discard(CheckoutId)
            if self._closed:
                try:
                    await conn.close()
                except Exception:
                    # Best-effort: the pool is closing, so there is nothing
                    # to recover if this connection fails to close cleanly.
                    pass
                return
            self._free.append(_AsyncPoolEntry(conn))
            cond.notify()

    async def close(self) -> None:
        """Close every free connection and mark the pool closed.
        Connections still checked out get closed when their caller
        releases them."""
        cond = self._ensure_sync_primitives()
        async with cond:
            self._closed = True
            while self._free:
                Entry = self._free.popleft()
                try:
                    await Entry.conn.close()
                except Exception:
                    # Best-effort: keep draining the rest even if one
                    # connection refuses to close.
                    pass
            cond.notify_all()

    @property
    def opened(self) -> int:
        return len(self._free) + len(self._in_use)

    @property
    def busy(self) -> int:
        return len(self._in_use)

    # ----- internals -----

    def _ensure_sync_primitives(self) -> asyncio.Condition:
        if self._available is None:
            self._lock = asyncio.Lock()
            self._available = asyncio.Condition(self._lock)
        return self._available

    async def _acquire_one(self) -> AsyncOracleConnect:
        """The body of acquire(), refactored so the
        `_AcquireContext` can drive it explicitly."""
        cond = self._ensure_sync_primitives()
        if not self._prewarmed:
            await self.prewarm()
        Deadline = None if self._timeout is None else (time.monotonic() + self._timeout)
        async with cond:
            while True:
                if self._closed:
                    raise InterfaceError('pool is closed')
                while self._free:
                    Entry = self._free.popleft()
                    if self._needs_health_check(Entry):
                        if not await self._ping(Entry.conn):
                            await self._discard_dead(Entry.conn)
                            continue
                    self._in_use.add(id(Entry.conn))
                    return Entry.conn
                if len(self._in_use) < self._max:
                    Conn = await self._open_connection()
                    self._in_use.add(id(Conn))
                    return Conn
                if Deadline is None:
                    await cond.wait()
                else:
                    Remaining = Deadline - time.monotonic()
                    if Remaining <= 0:
                        raise InterfaceError(
                            f'pool acquire timed out after {self._timeout}s '
                            f'(in_use={len(self._in_use)}, max={self._max})'
                        )
                    try:
                        await asyncio.wait_for(
                            cond.wait(),
                            timeout=Remaining,
                        )
                    except asyncio.TimeoutError:
                        raise InterfaceError(
                            f'pool acquire timed out after {self._timeout}s '
                            f'(in_use={len(self._in_use)}, max={self._max})'
                        )

    async def _open_connection(self) -> AsyncOracleConnect:
        Conn = AsyncOracleConnect(**self._connect_kwargs)
        await Conn.connect()
        return Conn

    def _needs_health_check(self, entry: _AsyncPoolEntry) -> bool:
        if not self._health_check or self._idle_timeout is None:
            return False
        return (time.monotonic() - entry.released_at) >= self._idle_timeout

    async def _ping(self, conn: AsyncOracleConnect) -> bool:
        try:
            Cur = conn.cursor()
            try:
                await Cur.execute('SELECT 1 FROM DUAL')
                await Cur.fetchone()
            finally:
                try:
                    await Cur.close()
                except Exception:
                    # Best-effort: the ping already has its result; a failed
                    # cursor close must not mask it.
                    pass
            return True
        except Exception:
            return False

    async def _discard_dead(self, conn: AsyncOracleConnect) -> None:
        try:
            await conn.close()
        except Exception:
            # The connection is already known to be dead; closing it is
            # purely best-effort cleanup.
            pass


class _AcquireContext:
    """Glue between `pool.acquire()` and the async-with statement.

    Resolves the connection in `__aenter__` (so the user awaits the
    acquire there) and hands it back to the pool in `__aexit__`.
    Returning a plain coroutine from `acquire()` would also work but
    forces `async with await pool.acquire():` — the extra `await`
    is ugly and easy to forget.
    """

    __slots__ = ('_pool', '_conn')

    def __init__(self, pool: AsyncPool):
        self._pool = pool
        self._conn: AsyncOracleConnect | None = None

    async def __aenter__(self) -> AsyncOracleConnect:
        self._conn = await self._pool._acquire_one()
        return self._conn

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._conn is not None:
            await self._pool.release(self._conn)
            self._conn = None
