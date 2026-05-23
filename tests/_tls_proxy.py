# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Tiny TLS-to-TCP forwarding proxy used by the integration tests to give
# pyoracle a TLS endpoint to talk to without reconfiguring the Oracle
# listener. Accepts TLS on a local port, decrypts, and pipes the cleartext
# both directions to a plaintext Oracle listener.
#
# It is a test fixture, not a production component. Each connection gets a
# pair of pump threads; the proxy stops cleanly when stop() is called.

import os
import socket
import ssl
import threading


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
CERT_PATH = os.path.join(FIXTURES_DIR, "proxy_cert.pem")
KEY_PATH = os.path.join(FIXTURES_DIR, "proxy_key.pem")


class TLSProxy:
    """TLS terminator that forwards plaintext to a backend host:port."""

    def __init__(self, backend_host: str, backend_port: int,
                 cert_path: str = CERT_PATH, key_path: str = KEY_PATH,
                 listen_host: str = "127.0.0.1"):
        self.backend = (backend_host, backend_port)
        self.cert_path = cert_path
        self.key_path = key_path
        self.listen_host = listen_host
        self.listen_port: int | None = None
        self._sock: socket.socket | None = None
        self._ctx: ssl.SSLContext | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []

    def start(self) -> None:
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(self.cert_path, self.key_path)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, 0))
        self._sock.listen(8)
        self._sock.settimeout(0.5)
        self.listen_port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                        name="TLSProxy-accept")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
        for w in self._workers:
            w.join(timeout=2)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            t = threading.Thread(target=self._handle, args=(client,),
                                 daemon=True, name="TLSProxy-conn")
            self._workers.append(t)
            t.start()

    def _handle(self, plain_client: socket.socket) -> None:
        try:
            tls_client = self._ctx.wrap_socket(plain_client, server_side=True)
        except (ssl.SSLError, OSError):
            try:
                plain_client.close()
            except OSError:
                pass
            return
        try:
            backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend.connect(self.backend)
        except OSError:
            try:
                tls_client.close()
            except OSError:
                pass
            return
        # Pump in both directions. Either side closing tears the pair down.
        t1 = threading.Thread(target=self._pump,
                              args=(tls_client, backend),
                              daemon=True, name="TLSProxy-c2b")
        t2 = threading.Thread(target=self._pump,
                              args=(backend, tls_client),
                              daemon=True, name="TLSProxy-b2c")
        t1.start(); t2.start()
        t1.join(); t2.join()

    @staticmethod
    def _pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                buf = src.recv(8192)
                if not buf:
                    break
                dst.sendall(buf)
        except (ssl.SSLError, OSError):
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    s.close()
                except OSError:
                    pass

    def __enter__(self) -> "TLSProxy":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
