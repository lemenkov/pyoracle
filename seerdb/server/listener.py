# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A minimal TCP listener that observes the client side of the wire.

This is the P0 bring-up tool, not yet a working server: it accepts a
connection, frames every incoming packet with :class:`PacketStream`, and logs
it. Pointing a real client (sqlplus, SeerODBC, seerdb) at it shows exactly what
that client puts on the wire — the raw material for authoring the ACCEPT / PRO /
DTY / auth replies in later increments.

It does not answer the handshake, so a client will log its ``CONNECT`` and then
wait; that is expected at this stage.
"""

from __future__ import annotations

import logging
import socket
from collections.abc import Callable

from seerdb.server.framing import DEFAULT_SDU, PacketStream
from seerdb.tns_consts import (
    TNS_ABORT,
    TNS_ACCEPT,
    TNS_ACK,
    TNS_CONNECT,
    TNS_DATA,
    TNS_MARKER,
    TNS_NULL,
    TNS_REDIRECT,
    TNS_REFUSE,
    TNS_RESEND,
)

logger = logging.getLogger('seerdb.server')

_PACKET_NAMES = {
    TNS_CONNECT: 'CONNECT',
    TNS_ACCEPT: 'ACCEPT',
    TNS_ACK: 'ACK',
    TNS_REFUSE: 'REFUSE',
    TNS_REDIRECT: 'REDIRECT',
    TNS_DATA: 'DATA',
    TNS_NULL: 'NULL',
    TNS_ABORT: 'ABORT',
    TNS_RESEND: 'RESEND',
    TNS_MARKER: 'MARKER',
}

# How many leading body bytes to hex-dump per packet in the log.
_DUMP_LIMIT = 96

Handler = Callable[[PacketStream], None]


def packet_name(packet_type: int) -> str:
    """Human-readable name for a TNS packet type."""
    return _PACKET_NAMES.get(packet_type, f'type={packet_type}')


def observe_connection(stream: PacketStream) -> None:
    """Log every packet a client sends until it disconnects.

    The default P0 handler: pure observation, no protocol replies.
    """
    while True:
        received = stream.read_packet()
        if received is None:
            logger.info('client closed the connection')
            return
        packet_type, body = received
        logger.info(
            'recv %-8s %5d bytes  %s%s',
            packet_name(packet_type),
            len(body),
            body[:_DUMP_LIMIT].hex(' '),
            ' …' if len(body) > _DUMP_LIMIT else '',
        )


class Listener:
    """Serial TCP listener for the observation handler.

    One connection is handled at a time — enough for bring-up, where a single
    client is pointed at the port. ``handler`` receives a :class:`PacketStream`
    per accepted connection.
    """

    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 1521,
        *,
        handler: Handler = observe_connection,
        sdu: int = DEFAULT_SDU,
    ) -> None:
        self.host = host
        self.port = port
        self.handler = handler
        self.sdu = sdu
        self._sock: socket.socket | None = None

    def serve_forever(self) -> None:
        """Bind, listen, and handle connections until interrupted."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(1)
        self._sock = sock
        logger.info('listening on %s:%d', self.host, self.port)
        try:
            while True:
                client, addr = sock.accept()
                logger.info('accepted connection from %s:%d', *addr)
                try:
                    self.handler(PacketStream(client, sdu=self.sdu))
                except OSError as exc:
                    logger.info('connection error: %s', exc)
                finally:
                    client.close()
        finally:
            sock.close()
            self._sock = None


def serve(
    host: str = '127.0.0.1',
    port: int = 1521,
    *,
    handler: Handler = observe_connection,
) -> None:
    """Convenience: build a :class:`Listener` and serve until interrupted."""
    Listener(host, port, handler=handler).serve_forever()
