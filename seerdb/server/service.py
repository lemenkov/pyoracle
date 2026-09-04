# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The Mirror server — accept Oracle clients and serve them from a backend.

The public entry point (``seerdb.serve`` / ``seerdb.Server``) ties the
handshake, O5LOGON auth, and query loop (:func:`serve_session`) to a credential
map and a **per-session backend factory**: one fresh :class:`Backend` per client
connection (the model both SQLite — thread-affine — and PostgreSQL want). Each
connection is handled on its own thread.
"""

from __future__ import annotations

import logging
import socket
import threading
from collections.abc import Callable

from seerdb.common.tns_consts import FIELD_VERSION_11_2
from seerdb.server.backend import Backend
from seerdb.server.framing import PacketStream
from seerdb.server.session import serve_session

logger = logging.getLogger('seerdb.server')

# Called once per client connection to open its backend session. The backend it
# returns owns auth too (its ``authenticate``), so the Server holds no
# credentials of its own.
BackendFactory = Callable[[], Backend]

_BACKLOG = 16


class Server:
    """A Mirror listening socket. Binds on construction (so ``port=0`` yields an
    ephemeral port readable as :attr:`port` before serving); serve on a thread
    or call :meth:`serve_forever` directly, and :meth:`close` to stop."""

    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 1521,
        *,
        backend_factory: BackendFactory,
        field_version: int = FIELD_VERSION_11_2,
        tns_version: int | None = None,
    ) -> None:
        self._backend_factory = backend_factory
        # The field version the Mirror advertises to thin clients (default the
        # pinned 11.2). Higher values unlock the 12c+ / 23ai wire formats a client
        # gates on that version; the login path handles them, the query path is
        # being brought up format by format.
        self._field_version = field_version
        self._tns_version = tns_version
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(_BACKLOG)
        # A short accept timeout lets close() stop the loop promptly (a plain
        # close() does not reliably wake a thread blocked in accept()).
        self._sock.settimeout(0.5)
        self.host, self.port = self._sock.getsockname()

    def serve_forever(self) -> None:
        """Accept and serve connections until :meth:`close` (or an interrupt)."""
        logger.info('Mirror listening on %s:%d', self.host, self.port)
        while self._running:
            try:
                client, addr = self._sock.accept()
            except TimeoutError:
                continue  # poll the running flag
            except OSError:
                break  # the socket was closed
            threading.Thread(
                target=self._handle, args=(client, addr), daemon=True
            ).start()

    def _handle(self, client: socket.socket, addr: tuple) -> None:
        backend = None
        try:
            backend = self._backend_factory()
            user = serve_session(
                PacketStream(client),
                backend,
                field_version=self._field_version,
                tns_version=self._tns_version,
            )
            logger.info('%s:%d session ended (%s)', addr[0], addr[1], user)
        except Exception:
            logger.exception('session error from %s:%d', *addr)
        finally:
            if backend is not None:
                try:
                    backend.close()
                except Exception:
                    logger.debug('backend close failed', exc_info=True)
            client.close()

    def close(self) -> None:
        """Stop accepting and release the listening socket."""
        self._running = False
        self._sock.close()


def serve(
    host: str = '127.0.0.1',
    port: int = 1521,
    *,
    backend_factory: BackendFactory,
    field_version: int = FIELD_VERSION_11_2,
    tns_version: int | None = None,
) -> None:
    """Run a Mirror server until interrupted — the one-call convenience."""
    server = Server(
        host,
        port,
        backend_factory=backend_factory,
        field_version=field_version,
        tns_version=tns_version,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
