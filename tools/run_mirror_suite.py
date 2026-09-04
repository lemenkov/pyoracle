#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Run the integration suite THROUGH the Mirror, in one command.

Starts one of the example Mirror launchers as a separate process, points the
suite's SEERDB_TEST_* environment at it, runs pytest, and tears the Mirror down::

    python3 tools/run_mirror_suite.py postgres     [pytest args...]
    python3 tools/run_mirror_suite.py passthrough  [pytest args...]

``postgres``    — examples/mirror_over_postgres.py: the Mirror serving every
                  statement from PostgreSQL (needs orafce; see
                  examples/mirror-pg.Dockerfile). Connection string from the
                  MIRROR_PG environment variable (the same one
                  tests/test_postgres_backend.py reads).
``passthrough`` — examples/mirror_over_oracle.py: the Mirror relaying to a real
                  Oracle, from SEERDB_TEST_HOST / _PORT / _SERVICE (the same
                  variables the direct suite uses), so a failure isolates a
                  Mirror gap rather than a backend-dialect limit.

The Mirror runs as a SEPARATE process on purpose: run in-process, the suite's
client-side monkeypatches (send counting) would also see the passthrough's
upstream traffic, and per-backend credential copies break changepassword.
The Mirror's port comes from MIRROR_PORT (default 15521); its log is written
next to the checkout as mirror-<backend>.log and printed when the suite fails.
Committed defaults stay generic (127.0.0.1); point the variables at your beds.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_LAUNCHERS = {
    'postgres': 'examples/mirror_over_postgres.py',
    'passthrough': 'examples/mirror_over_oracle.py',
}
_DEFAULT_PG = 'host=127.0.0.1 port=5433 user=pyo password=pyo123 dbname=mirror'


def _launcher_args(backend: str, port: int) -> list[str]:
    if backend == 'postgres':
        return [os.environ.get('MIRROR_PG', _DEFAULT_PG), str(port)]
    upstream = (
        f'{os.environ.get("SEERDB_TEST_HOST", "127.0.0.1")}:'
        f'{os.environ.get("SEERDB_TEST_PORT", "1521")}/'
        f'{os.environ.get("SEERDB_TEST_SERVICE", "XE")}'
    )
    return [str(port), upstream]


def _wait_for(port: int, process: subprocess.Popen, seconds: float = 15.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in _LAUNCHERS:
        print(__doc__, file=sys.stderr)
        return 2
    backend, pytest_args = argv[0], argv[1:] or ['tests/test_integration.py']
    port = int(os.environ.get('MIRROR_PORT', '15521'))
    log_path = os.path.join(_ROOT, f'mirror-{backend}.log')
    # The Mirror imports seerdb.server, which the published wheel omits (#301):
    # run the launcher against the checkout, whatever is pip-installed.
    env = dict(os.environ, PYTHONPATH=_ROOT)
    env.setdefault('SEERDB_TEST_USER', 'PYO')
    env.setdefault('SEERDB_TEST_PASSWORD', 'pyo123')
    with open(log_path, 'w') as log:
        mirror = subprocess.Popen(
            [sys.executable, _LAUNCHERS[backend], *_launcher_args(backend, port)],
            cwd=_ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            if not _wait_for(port, mirror):
                print(f'the Mirror did not come up on {port}; see {log_path}')
                return 2
            # The suite now talks to the Mirror, which advertises service XE.
            env.update(
                SEERDB_TEST_HOST='127.0.0.1',
                SEERDB_TEST_PORT=str(port),
                SEERDB_TEST_SERVICE='XE',
            )
            env.pop('SEERDB_TEST_FIELD_VERSION', None)
            status = subprocess.call(
                [
                    sys.executable,
                    '-m',
                    'pytest',
                    '-p',
                    'no:cacheprovider',
                    *pytest_args,
                ],
                cwd=_ROOT,
                env=env,
            )
        finally:
            mirror.terminate()
            try:
                mirror.wait(timeout=10)
            except subprocess.TimeoutExpired:
                mirror.kill()
    if status:
        print(f'--- {log_path} (tail) ---')
        with open(log_path) as log:
            print(''.join(log.readlines()[-60:]))
    return status


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
