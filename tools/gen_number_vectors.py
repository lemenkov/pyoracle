#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Regenerate the Oracle NUMBER known-answer vectors in tests/test_number_codec.py.

Each vector is produced by ``SELECT dump(<literal>) FROM dual`` against a live
Oracle server, so the bytes are exactly what Oracle emits — and because DUMP
returns them as a *string*, the vectors are independent of seerdb's own decoder.

Connection comes from the project's standard integration env vars:
    SEERDB_TEST_HOST (default 127.0.0.1), SEERDB_TEST_PORT (1521),
    SEERDB_TEST_SERVICE (FREEPDB1), SEERDB_TEST_USER, SEERDB_TEST_PASSWORD

Prints Python rows to stdout; paste the VECTORS block into the test.
"""

import os
import re
import sys
from decimal import Decimal

# (sql_literal, expected value decode_number should return). Coverage follows
# the go-ora number test table (MIT) — scenario reused as fact.
CASES = [
    ('0', 0),
    ('1', 1),
    ('-1', -1),
    ('10', 10),
    ('100', 100),
    ('1000', 1000),
    ('10000000', 10000000),
    ('123456789', 123456789),
    ('-123456789', -123456789),
    ('0.1', Decimal('0.1')),
    ('0.001', Decimal('0.001')),
    ('-0.001', Decimal('-0.001')),
    ('0.5', Decimal('0.5')),
    ('0.25', Decimal('0.25')),
    ('0.125', Decimal('0.125')),
    ('1.5', Decimal('1.5')),
    ('100.5', Decimal('100.5')),
    ('1.234', Decimal('1.234')),
    ('-1.234', Decimal('-1.234')),
    ('999999999999.9999', Decimal('999999999999.9999')),
    ('9999999999999.999', Decimal('9999999999999.999')),
    ('99999999999999.99', Decimal('99999999999999.99')),
    ('9999999999999999', 9999999999999999),
    ('9223372036854775807', 9223372036854775807),
    ('-9223372036854775808', -9223372036854775808),
    ('18446744073709551615', 18446744073709551615),
    ('1E30', 10**30),
    ('3.1415926535897932384626433832795', Decimal('3.1415926535897932384626433832795')),
]


def main() -> int:
    # Run from anywhere: put the repo root (this file's grandparent) on the path.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import seerdb

    User = os.environ.get('SEERDB_TEST_USER')
    Password = os.environ.get('SEERDB_TEST_PASSWORD')
    if not User or not Password:
        sys.exit('set SEERDB_TEST_USER / SEERDB_TEST_PASSWORD (+ HOST/PORT/SERVICE)')
    Conn = seerdb.connect(
        host=os.environ.get('SEERDB_TEST_HOST', '127.0.0.1'),
        port=int(os.environ.get('SEERDB_TEST_PORT', '1521')),
        service_name=os.environ.get('SEERDB_TEST_SERVICE', 'FREEPDB1'),
        user=User,
        password=Password,
        timeout=8000,
    )
    Cur = Conn.cursor()
    for Expr, Expected in CASES:
        Cur.execute(f'SELECT dump({Expr}) FROM dual')
        Dumped = Cur.fetchone()[0]  # 'Typ=2 Len=2: 193,11'
        Match = re.search(r':\s*([\d, ]+)$', Dumped)
        assert Match is not None, Dumped
        Hex = bytes(int(X) for X in Match.group(1).split(',')).hex()
        print(f"    ({Expected!r}, '{Hex}'),  # {Expr}")
    Conn.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
