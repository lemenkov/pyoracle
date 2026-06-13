#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Drive python-oracledb (thin mode) through the logging proxy to capture the
wire protocol for a 0.5.0 feature against a modern server (12.1+).

python-oracledb thin is a pure-Python reference client that speaks the same
TNS/TTC protocol pyoracle implements, and (unlike against 11g) it connects
happily to 12c+/23ai. Run one scenario at a time *through* tools/capture_proxy.py
so the proxy log contains just that exchange, then reverse-engineer it.

Prerequisites:
    pip install oracledb           # thin mode needs no Oracle client libs

Typical flow (two terminals):
    # terminal 1 — proxy in front of the 23ai listener (e.g. on :1523)
    python3 tools/capture_proxy.py --listen 1599 --target localhost:1523 \\
            --out /tmp/cap_lobwrite.log

    # terminal 2 — reference client THROUGH the proxy (note port 1599)
    python3 tools/reference_capture.py lobwrite \\
            --dsn localhost:1599/FREEPDB1 --user pyo --password pyo123

Scenarios: lobwrite | changepassword | batcherrors | fragment
Each prints what oracledb returned (to confirm it worked) while the proxy
records the bytes. changepassword changes the password and changes it back.
"""

import argparse

import oracledb   # python-oracledb; thin mode is the default


def _table(cur, name, ddl):
    try:
        cur.execute(f"DROP TABLE {name}")
    except oracledb.DatabaseError:
        # The table may not exist yet on a fresh run; ignore and (re)create.
        pass
    cur.execute(f"CREATE TABLE {name} {ddl}")


def scenario_lobwrite(conn):
    # Force a TTI_LOBOPS WRITE: build a temp CLOB and stream a >32KB payload
    # into it, then bind the locator. This is the path pyoracle can't do on 11g
    # (issue #14).
    cur = conn.cursor()
    _table(cur, "PYO_REF_LOB", "(id NUMBER, c CLOB)")
    lob = conn.createlob(oracledb.DB_TYPE_CLOB)
    lob.write("X" * 100_000)
    cur.execute("INSERT INTO PYO_REF_LOB VALUES (1, :1)", [lob])
    conn.commit()
    cur.execute("SELECT id, DBMS_LOB.GETLENGTH(c) FROM PYO_REF_LOB")
    print("lobwrite ->", cur.fetchall())


def scenario_changepassword(conn, user, password):
    # OCIPasswordChange equivalent (issue #21) — capture the AUTH_NEWPASSWORD
    # encoding/key that the 11g capture couldn't pin down.
    new = password + "X9"
    conn.changepassword(password, new)
    print("changepassword -> new password set OK")
    conn.changepassword(new, password)
    print("changepassword -> restored original")


def scenario_batcherrors(conn):
    # batcherrors + array DML row counts (issue #18).
    cur = conn.cursor()
    _table(cur, "PYO_REF_BE", "(id NUMBER PRIMARY KEY)")
    cur.executemany("INSERT INTO PYO_REF_BE VALUES (:1)",
                    [(1,), (2,), (2,), (3,), (3,), (5,)],
                    batcherrors=True, arraydmlrowcounts=True)
    print("batch errors ->", [(e.offset, e.code) for e in cur.getbatcherrors()])
    print("array dml rowcounts ->", cur.getarraydmlrowcounts())
    conn.commit()


def scenario_fragment(conn):
    # Large multi-packet response to study TNS fragmentation (issue #8).
    cur = conn.cursor()
    cur.execute("SELECT LPAD('x', 200, 'x') FROM dual CONNECT BY level <= 2000")
    rows = cur.fetchall()
    print(f"fragment -> fetched {len(rows)} rows")


def scenario_handshake(conn):
    # Minimal exchange: the connect already drove the full TTC capability
    # negotiation (TTI_PRO / TTI_DTY) and O5LOGON auth, which is what we want
    # to capture for 12c+ support (issue #27). One tiny query confirms the
    # session is usable without adding noise to the proxy log.
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM dual")
    print("handshake ->", cur.fetchall())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("scenario",
                    choices=["lobwrite", "changepassword", "batcherrors",
                             "fragment", "handshake"])
    ap.add_argument("--dsn", required=True,
                    help="host:port/service through the proxy, "
                         "e.g. localhost:1599/FREEPDB1")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    conn = oracledb.connect(user=args.user, password=args.password, dsn=args.dsn)
    print(f"oracledb {oracledb.__version__}, thin_mode={conn.thin}")
    try:
        if args.scenario == "lobwrite":
            scenario_lobwrite(conn)
        elif args.scenario == "changepassword":
            scenario_changepassword(conn, args.user, args.password)
        elif args.scenario == "batcherrors":
            scenario_batcherrors(conn)
        elif args.scenario == "fragment":
            scenario_fragment(conn)
        elif args.scenario == "handshake":
            scenario_handshake(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
