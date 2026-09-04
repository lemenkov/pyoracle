# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Run a Mirror that relays to a real Oracle — a transparent Oracle relay.

    python examples/mirror_over_oracle.py [LISTEN_PORT] [UPSTREAM_HOST:PORT/SERVICE]

Defaults: listen on 1521, relay to 127.0.0.1:1522/XE. Credentials come from
SEERDB_TEST_USER / SEERDB_TEST_PASSWORD (default PYO / pyo123). Point any Oracle
client — including the integration suite — at the listen port; every statement
runs on the real upstream Oracle and the real results come back through the
Mirror, so a test failure isolates a Mirror protocol gap.
"""

from __future__ import annotations

import logging
import os
import sys

from oracle_passthrough_backend import OraclePassthroughBackend

import seerdb


def main() -> None:
    listen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 1521
    upstream = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1:1521/XE'
    hostport, service = upstream.rsplit('/', 1)
    host, port = hostport.rsplit(':', 1)

    # The field version the Mirror advertises (default 11.2); a 12c+/23ai value
    # makes a thin client negotiate to it and exercises those wire formats.
    field_version = int(os.environ.get('MIRROR_FIELD_VERSION', '6'))
    # The TNS protocol version the ACCEPT answers with (default 11.2's 314).
    # 316 (12.2) and up switch the DATA stream to the 4-byte packet length.
    tns_version = int(os.environ.get('MIRROR_TNS_VERSION', '314'))
    user = os.environ.get('SEERDB_TEST_USER', 'PYO')
    password = os.environ.get('SEERDB_TEST_PASSWORD', 'pyo123')

    # One shared credential map across every session's backend, so a
    # changepassword on one connection is visible to the next (#21/#486).
    credentials = {user.upper(): password}

    logging.basicConfig(
        level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s'
    )
    seerdb.serve(
        '127.0.0.1',
        listen_port,
        field_version=field_version,
        tns_version=tns_version,
        backend_factory=lambda: OraclePassthroughBackend(
            host=host,
            port=int(port),
            service=service,
            credentials=credentials,
        ),
    )


if __name__ == '__main__':
    main()
