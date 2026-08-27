# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Connection pool.

`seerdb.connect()` does a full TNS / O5LOGON handshake every time, which
takes a few hundred ms even against a local XE. Long-running applications
that frequently acquire short-lived connections (one per request, etc.)
end up spending more time handshaking than running queries.

A pool keeps a small set of authenticated `OracleConnect` instances
warm. Acquire pulls a free one from the pool (or opens a fresh one,
up to `max`); release returns it. Each acquisition optionally verifies
the connection is still alive with a cheap round-trip first.

Usage:

    pool = seerdb.create_pool(host=..., user=..., password=...,
                              service_name=..., min=2, max=10)
    with pool.acquire() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM dual")
    pool.close()
"""

import threading
import time
from collections import deque

from seerdb.client.connection import OracleConnect
from seerdb.common.exceptions import InterfaceError


class _PoolEntry:
    """One pooled connection plus its last-used timestamp."""

    __slots__ = ('conn', 'released_at')

    def __init__(self, conn: OracleConnect):
        self.conn = conn
        self.released_at = time.monotonic()


class _PooledConnectionGuard:
    """Context manager returned by Pool.acquire(). Releases on exit."""

    __slots__ = ('_pool', '_conn')

    def __init__(self, pool: 'Pool', conn: OracleConnect):
        self._pool = pool
        self._conn = conn

    def __enter__(self) -> OracleConnect:
        return self._conn

    def __exit__(self, exc_type, exc, tb) -> None:
        # Release whether or not the user's block raised; if the underlying
        # connection got into a bad state the next acquire's health-check
        # will catch it and discard the entry.
        self._pool.release(self._conn)


class Pool:
    """Thread-safe pool of authenticated `OracleConnect` instances.

    Construction is lazy: only `min` connections are opened up front;
    the rest are created on demand and capped at `max`. When the
    caller would exceed `max`, `acquire()` blocks (up to `timeout`
    seconds) until another caller releases.
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
        # `idle_timeout` is how long a free connection can sit unused
        # before the next acquire health-checks it. `None` disables the
        # check; pool consumers happy with stale connections can opt out.
        self._idle_timeout = idle_timeout
        self._health_check = health_check
        self._connect_kwargs = connect_kwargs

        # `_free` holds available entries; `_in_use` tracks acquired ones
        # so close() can finalise them.
        self._lock = threading.Lock()
        self._available = threading.Condition(self._lock)
        self._free: deque[_PoolEntry] = deque()
        self._in_use: set[int] = set()  # id(conn) → connection is checked out
        self._closed = False

        # Pre-warm to `min`. Failures here surface immediately rather than
        # later when the caller acquires.
        for _ in range(self._min):
            self._free.append(_PoolEntry(self._open_connection()))

    # ----- public API -----

    def acquire(self) -> _PooledConnectionGuard:
        """Get a connection from the pool. Returns a context manager
        that releases on __exit__."""
        Deadline = None if self._timeout is None else (time.monotonic() + self._timeout)
        with self._available:
            while True:
                if self._closed:
                    raise InterfaceError('pool is closed')
                # Fast path: hand out a free entry, health-check if stale.
                while self._free:
                    Entry = self._free.popleft()
                    if self._needs_health_check(Entry):
                        if not self._ping(Entry.conn):
                            # Connection is dead — discard and try again.
                            self._discard_dead(Entry.conn)
                            continue
                    self._in_use.add(id(Entry.conn))
                    Entry.conn._begin_request()  # request boundary (#464)
                    return _PooledConnectionGuard(self, Entry.conn)
                # Room to grow? Open a fresh one.
                if len(self._in_use) < self._max:
                    Conn = self._open_connection()
                    self._in_use.add(id(Conn))
                    Conn._begin_request()  # request boundary (#464)
                    return _PooledConnectionGuard(self, Conn)
                # At capacity — wait for a release.
                if Deadline is None:
                    self._available.wait()
                else:
                    Remaining = Deadline - time.monotonic()
                    if Remaining <= 0:
                        raise InterfaceError(
                            f'pool acquire timed out after {self._timeout}s '
                            f'(in_use={len(self._in_use)}, max={self._max})'
                        )
                    self._available.wait(Remaining)

    def release(self, conn: OracleConnect) -> None:
        """Return a connection to the pool. Idempotent on already-released
        connections (a misbehaving caller releasing twice doesn't break
        accounting). Connections not produced by this pool are rejected."""
        with self._available:
            CheckoutId = id(conn)
            if CheckoutId not in self._in_use:
                raise InterfaceError('connection was not acquired from this pool')
            self._in_use.discard(CheckoutId)
            if self._closed:
                # Pool closed while held — just close this one ourselves.
                try:
                    conn.close()
                except Exception:
                    # Best-effort: the pool is closing, so there is nothing
                    # to recover if this connection fails to close cleanly.
                    pass
                return
            # End the pooled logical request (#464): flush REQUEST_END if one is
            # open. A failure here means the connection is dead — discard it
            # rather than return a broken connection to the pool.
            try:
                conn._end_request()
            except Exception:
                self._discard_dead(conn)
                self._available.notify()
                return
            self._free.append(_PoolEntry(conn))
            self._available.notify()

    def close(self) -> None:
        """Close all connections (free + in-use). Subsequent `acquire`
        calls raise InterfaceError."""
        with self._available:
            self._closed = True
            # Free entries close immediately; in-use entries will close
            # when their caller releases them.
            while self._free:
                Entry = self._free.popleft()
                try:
                    Entry.conn.close()
                except Exception:
                    # Best-effort: keep draining the rest even if one
                    # connection refuses to close.
                    pass
            self._available.notify_all()

    @property
    def opened(self) -> int:
        """Connections currently held by the pool (free + in-use)."""
        with self._lock:
            return len(self._free) + len(self._in_use)

    @property
    def busy(self) -> int:
        """Connections currently checked out."""
        with self._lock:
            return len(self._in_use)

    # ----- internals -----

    def _open_connection(self) -> OracleConnect:
        Conn = OracleConnect(**self._connect_kwargs)
        Conn.connect()
        return Conn

    def _needs_health_check(self, entry: _PoolEntry) -> bool:
        if not self._health_check or self._idle_timeout is None:
            return False
        return (time.monotonic() - entry.released_at) >= self._idle_timeout

    def _ping(self, conn: OracleConnect) -> bool:
        # `SELECT 1 FROM DUAL` is the cheapest round-trip that confirms
        # the session is still good — any kind of broken socket or
        # killed-session state shows up here.
        try:
            Cur = conn.cursor()
            try:
                Cur.execute('SELECT 1 FROM DUAL')
                Cur.fetchone()
            finally:
                try:
                    Cur.close()
                except Exception:
                    # Best-effort: the ping already has its result; a failed
                    # cursor close must not mask it.
                    pass
            return True
        except Exception:
            return False

    def _discard_dead(self, conn: OracleConnect) -> None:
        try:
            conn.close()
        except Exception:
            # The connection is already known to be dead; closing it is
            # purely best-effort cleanup.
            pass
