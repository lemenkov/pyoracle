# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Run the observation listener: ``python -m seerdb.server [--port N]``.

Point a client at the chosen port and watch what it puts on the wire.
"""

from __future__ import annotations

import argparse
import logging

from seerdb.server.listener import serve


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='python -m seerdb.server',
        description='Observe the client side of the TNS wire (bring-up tool).',
    )
    parser.add_argument('--host', default='127.0.0.1', help='bind address')
    parser.add_argument('--port', type=int, default=1521, help='listen port')
    parser.add_argument(
        '-v', '--verbose', action='store_true', help='debug-level logging'
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    try:
        serve(args.host, args.port)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
