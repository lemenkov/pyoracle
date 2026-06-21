#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Repeatable pyoracle performance benchmark (#166).

Opt-in (needs a live Oracle, like the integration suite): connection parameters
come from the same PYORACLE_TEST_* environment variables.

    PYORACLE_TEST_USER=pyo PYORACLE_TEST_PASSWORD=pyo123 \
    PYORACLE_TEST_PORT=1521 PYORACLE_TEST_SERVICE=XE \
        python3 tools/benchmark.py [scale]

`scale` (default 10000) is the row/iteration count the throughput scenarios use.
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
    n = max(scale // 200, 20)
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
        pass
    cur.execute(f"CREATE TABLE {_TABLE} (id NUMBER, name VARCHAR2(40))")


def bench_insert(conn, scale):
    cur = conn.cursor()
    start = time.perf_counter()
    for i in range(scale):
        cur.execute(f"INSERT INTO {_TABLE} VALUES (:1, :2)", [i, f"row{i}"])
    conn.commit()
    _report("insert (per-row bind)", scale, time.perf_counter() - start)


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
    scale = int(sys.argv[1]) if len(sys.argv) > 1 else 10_000
    print(f"pyoracle benchmark  service={_KW['service_name']} scale={scale}")
    print("-" * 64)
    bench_connect(scale)
    conn = oracle.connect(**_KW)
    conn.autocommit = False
    try:
        _setup(conn)
        bench_insert(conn, scale)
        bench_executemany(conn, scale)
        bench_fetch(conn, scale)
        bench_fetch_df(conn, scale)
        conn.cursor().execute(f"DROP TABLE {_TABLE}")
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    main()
