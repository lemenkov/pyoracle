# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Tiny listener that answers the first TNS_CONNECT with a TNS_REDIRECT
# pointing at a real Oracle backend, used by the integration tests to exercise
# the redirect-follow path (#23) without a shared-server / RAC listener.
#
# It is a test fixture, not a production component: it accepts a connection,
# reads (and discards) the client's CONNECT packet, sends one REDIRECT packet
# carrying a connect descriptor for the backend, and closes. pyoracle should
# then reconnect to the backend and complete the handshake there.

import socket
import struct
import threading

from oracle.tns_consts import TNS_REDIRECT


class RedirectListener:
    """Sends a single TNS_REDIRECT to `backend_host:backend_port`."""

    def __init__(self, backend_host: str, backend_port: int,
                 listen_host: str = "127.0.0.1"):
        self.backend = (backend_host, backend_port)
        self.listen_host = listen_host
        self.listen_port: int | None = None
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def _redirect_packet(self) -> bytes:
        descriptor = (
            f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={self.backend[0]})"
            f"(PORT={self.backend[1]})))"
        ).encode("ascii")
        # Header (8 bytes) + ub2 data length + descriptor, matching the real
        # redirect packet layout.
        body = struct.pack(">H", len(descriptor)) + descriptor
        total = 8 + len(body)
        header = struct.pack(">HhBBh", total, 0, TNS_REDIRECT, 0, 0)
        return header + body

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, 0))
        self._sock.listen(1)
        self.listen_port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        try:
            conn.recv(8192)                       # read + discard the CONNECT
            conn.sendall(self._redirect_packet())
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self) -> "RedirectListener":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
