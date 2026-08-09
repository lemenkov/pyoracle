#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Repeatable seerdb performance benchmark (#166).

Opt-in (needs a live Oracle, like the integration suite): connection parameters
come from the same SEERDB_TEST_* environment variables.

    SEERDB_TEST_USER=pyo SEERDB_TEST_PASSWORD=pyo123 \
    SEERDB_TEST_PORT=1521 SEERDB_TEST_SERVICE=XE \
        python3 tools/benchmark.py [scale]

`scale` (default 50000) is the row/iteration count the throughput scenarios use;
use a representative scale when comparing. Both fetch scenarios are dominated by
the per-row value decode they share, so `fetch_df_all` (which builds an Arrow
Table on top) runs close to `fetchall`; the table includes a NUMBER(p,s) column
because that is where the Arrow build benefits most from explicit typing (#190).
Each scenario prints one stable line — name, count, seconds, rate — so runs are
easy to diff across changes (guards perf regressions; quantifies future work
such as the Arrow fetch fast path). Numbers are wall-clock against whatever
server SEERDB_TEST_* points at; compare like-for-like, not across tiers.
"""

import os
import sys
import time

sys.path.insert(0, ".")
import seerdb  # noqa: E402

_KW = dict(
    host=os.environ.get("SEERDB_TEST_HOST", "localhost"),
    port=int(os.environ.get("SEERDB_TEST_PORT", "1521")),
    user=os.environ.get("SEERDB_TEST_USER", "pyo"),
    password=os.environ.get("SEERDB_TEST_PASSWORD", ""),
    service_name=os.environ.get("SEERDB_TEST_SERVICE", "XE"),
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
        seerdb.connect(**_KW).close()
    elapsed = time.perf_counter() - start
    _report("connect+close", n, elapsed, "conns")
    print(f"{'':22} {'':>9}        {elapsed / n * 1000:8.2f}ms / connect")


def _setup(conn):
    cur = conn.cursor()
    try:
        cur.execute(f"DROP TABLE {_TABLE}")
    except seerdb.DatabaseError:
        # table may not exist on the first run; ignore
        pass
    # Include a NUMBER(p,s) column: it decodes to Decimal, the case where
    # fetch_df's Arrow build benefits most from explicit typing (#190).
    cur.execute(
        f"CREATE TABLE {_TABLE} (id NUMBER, name VARCHAR2(40), price NUMBER(10,2))")


def bench_insert(scale):
    # Per-row bind latency (not bulk throughput — use executemany for that).
    # On 12c+ each re-parse opens a server cursor that is not reused, so a long
    # loop trips ORA-01000 (#191) and the leaked cursors persist for the life of
    # the connection. So run on a dedicated connection (closing it frees them,
    # keeping the throughput scenarios clean) and stop gracefully if it trips.
    done = 0
    start = time.perf_counter()
    with seerdb.connect(**_KW) as conn:        # closing frees the leaked cursors
        conn.autocommit = False
        cur = conn.cursor()
        for i in range(min(scale, 2000)):
            try:
                cur.execute(f"INSERT INTO {_TABLE} VALUES (:1, :2, :3)",
                            [i, f"row{i}", i])
                done += 1
            except seerdb.DatabaseError as exc:
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
    rows = [(i, f"row{i}", i) for i in range(scale)]
    start = time.perf_counter()
    cur.executemany(f"INSERT INTO {_TABLE} VALUES (:1, :2, :3)", rows)
    conn.commit()
    _report("executemany", scale, time.perf_counter() - start)


def bench_fetch(conn, scale):
    cur = conn.cursor()
    start = time.perf_counter()
    cur.execute(
        f"SELECT id, name, price FROM {_TABLE} "
        f"WHERE ROWNUM <= {scale} ORDER BY id")
    rows = cur.fetchall()
    _report("fetchall (tuples)", len(rows), time.perf_counter() - start)


def bench_fetch_df(conn, scale):
    cur = conn.cursor()
    start = time.perf_counter()
    cur.execute(
        f"SELECT id, name, price FROM {_TABLE} "
        f"WHERE ROWNUM <= {scale} ORDER BY id")
    table = cur.fetch_df_all()
    _report("fetch_df_all (arrow)", table.num_rows,
            time.perf_counter() - start)


def main():
    scale = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000
    print(f"seerdb benchmark  service={_KW['service_name']} scale={scale}")
    print("-" * 64)
    bench_connect(scale)
    with seerdb.connect(**_KW) as conn:
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
