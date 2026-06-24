#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Repeatable pyoracle performance benchmark (#166).

Opt-in (needs a live Oracle, like the integration suite): connection parameters
come from the same PYORACLE_TEST_* environment variables.

    PYORACLE_TEST_USER=pyo PYORACLE_TEST_PASSWORD=pyo123 \
    PYORACLE_TEST_PORT=1521 PYORACLE_TEST_SERVICE=XE \
        python3 tools/benchmark.py [scale]

`scale` (default 50000) is the row/iteration count the throughput scenarios use.
It is deliberately large: the Arrow fetch path has a fixed per-call setup cost,
so at a small scale it looks slower than `fetchall` even though it is faster
once that cost is amortised (~0.95x of `fetchall` time by 50k rows). Use a
representative scale when comparing.
Each scenario prints one stable line — name, count, seconds, rate — so runs are
easy to diff across changes (guards perf regressions; quantifies future work
such as the Arrow fetch fast path). Numbers are wall-clock against whatever
server PYORACLE_TEST_* points at; compare like-for-like, not across tiers.
"""

import os
import sys
import time

sys.path.insert(0, ".")
import oracle                                              # noqa: E402

_KW = dict(
    host=os.environ.get("PYORACLE_TEST_HOST", "localhost"),
    port=int(os.environ.get("PYORACLE_TEST_PORT", "1521")),
    user=os.environ.get("PYORACLE_TEST_USER", "pyo"),
    password=os.environ.get("PYORACLE_TEST_PASSWORD", ""),
    service_name=os.environ.get("PYORACLE_TEST_SERVICE", "XE"),
)
_TABLE = "PYORACLE_BENCH"


def _report(name, count, seconds, unit="rows"):
    rate = count / seconds if seconds else float("inf")
    print(f"{name:<22} {count:>9} {unit}  {seconds:8.3f}s  "
          f"{rate:12,.0f} {unit}/s")


def bench_connect(scale):
    # Connect latency, not throughput — cap the count so it doesn't scale with
    # `scale` (a connect storm can exhaust the server's session/process limit
    # and isn't what this measures).
    n = min(max(scale // 200, 20), 50)
    start = time.perf_counter()
    for _ in range(n):
        oracle.connect(**_KW).close()
    elapsed = time.perf_counter() - start
    _report("connect+close", n, elapsed, "conns")
    print(f"{'':22} {'':>9}        {elapsed / n * 1000:8.2f}ms / connect")


def _setup(conn):
    cur = conn.cursor()
    try:
        cur.execute(f"DROP TABLE {_TABLE}")
    except oracle.DatabaseError:
        # table may not exist on the first run; ignore
        pass
    cur.execute(f"CREATE TABLE {_TABLE} (id NUMBER, name VARCHAR2(40))")


def bench_insert(scale):
    # Per-row bind latency (not bulk throughput — use executemany for that).
    # On 12c+ each re-parse opens a server cursor that is not reused, so a long
    # loop trips ORA-01000 (#191) and the leaked cursors persist for the life of
    # the connection. So run on a dedicated connection (closing it frees them,
    # keeping the throughput scenarios clean) and stop gracefully if it trips.
    done = 0
    start = time.perf_counter()
    with oracle.connect(**_KW) as conn:        # closing frees the leaked cursors
        conn.autocommit = False
        cur = conn.cursor()
        for i in range(min(scale, 2000)):
            try:
                cur.execute(f"INSERT INTO {_TABLE} VALUES (:1, :2)",
                            [i, f"row{i}"])
                done += 1
            except oracle.DatabaseError as exc:
                if getattr(exc, "code", None) != 1000:
                    raise
                print(f"  (per-row insert stopped at {done}: ORA-01000, #191)")
                break
        conn.commit()
    _report("insert (per-row bind)", done, time.perf_counter() - start)


def bench_executemany(conn, scale):
    cur = conn.cursor()
    cur.execute(f"DELETE FROM {_TABLE}")
    conn.commit()
    rows = [(i, f"row{i}") for i in range(scale)]
    start = time.perf_counter()
    cur.executemany(f"INSERT INTO {_TABLE} VALUES (:1, :2)", rows)
    conn.commit()
    _report("executemany", scale, time.perf_counter() - start)


def bench_fetch(conn, scale):
    cur = conn.cursor()
    start = time.perf_counter()
    cur.execute(
        f"SELECT id, name FROM {_TABLE} "
        f"WHERE ROWNUM <= {scale} ORDER BY id")
    rows = cur.fetchall()
    _report("fetchall (tuples)", len(rows), time.perf_counter() - start)


def bench_fetch_df(conn, scale):
    cur = conn.cursor()
    start = time.perf_counter()
    cur.execute(
        f"SELECT id, name FROM {_TABLE} "
        f"WHERE ROWNUM <= {scale} ORDER BY id")
    table = cur.fetch_df_all()
    _report("fetch_df_all (arrow)", table.num_rows,
            time.perf_counter() - start)


def main():
    scale = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000
    print(f"pyoracle benchmark  service={_KW['service_name']} scale={scale}")
    print("-" * 64)
    bench_connect(scale)
    with oracle.connect(**_KW) as conn:
        conn.autocommit = False
        _setup(conn)
        bench_insert(scale)
        bench_executemany(conn, scale)
        bench_fetch(conn, scale)
        bench_fetch_df(conn, scale)
        conn.cursor().execute(f"DROP TABLE {_TABLE}")
        conn.commit()


if __name__ == "__main__":
    main()
