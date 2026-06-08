#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Logging TCP proxy for capturing the Oracle TNS/TTC wire protocol.

Sits between a reference client (python-oracledb thin) and a real Oracle
listener, forwarding bytes transparently while appending every chunk to a log
file as ``<DIR> <len>\\n<hex>\\n`` lines (DIR = C2S / S2C). Pair it with a
reference client run (tools/reference_capture.py) and then analyse the log to
reverse-engineer a feature against a modern server (12.1+), the same
capture-first method used for the 11g work.

Usage:
    python3 tools/capture_proxy.py --listen 1599 --target localhost:1523 \\
            --out /tmp/capture.log

Then point the reference client at the proxy port (1599) instead of the real
listener (1523 here). One scenario per proxy run keeps the log easy to read;
truncate (default) or --append between runs.
"""

import argparse
import socket
import threading


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--listen", type=int, default=1599,
                    help="local port to listen on (default 1599)")
    ap.add_argument("--target", default="localhost:1521",
                    help="real listener host:port (default localhost:1521)")
    ap.add_argument("--out", default="/tmp/capture.log",
                    help="capture log path (default /tmp/capture.log)")
    ap.add_argument("--append", action="store_true",
                    help="append to the log instead of truncating")
    args = ap.parse_args()

    thost, tport = args.target.rsplit(":", 1)
    target = (thost, int(tport))
    out = open(args.out, "ab" if args.append else "wb")
    lock = threading.Lock()

    def dump(tag: bytes, data: bytes) -> None:
        with lock:
            out.write(tag + b" " + str(len(data)).encode() + b"\n")
            out.write(data.hex().encode() + b"\n")
            out.flush()

    def pipe(src: socket.socket, dst: socket.socket, tag: bytes) -> None:
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dump(tag, chunk)
                dst.sendall(chunk)
        except OSError:
            # Either side closing ends the pump; propagate the half-close
            # to the peer in the finally block below.
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                # Best-effort: the peer may already be gone.
                pass

    def handle(client: socket.socket) -> None:
        try:
            server = socket.create_connection(target)
        except OSError as exc:
            print(f"proxy: cannot reach {target}: {exc}", flush=True)
            client.close()
            return
        threading.Thread(target=pipe, args=(client, server, b"C2S"),
                         daemon=True).start()
        pipe(server, client, b"S2C")

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.listen))
    srv.listen(8)
    print(f"proxy: 127.0.0.1:{args.listen} -> {target[0]}:{target[1]}  "
          f"logging to {args.out}", flush=True)
    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        print("\nproxy: stopped", flush=True)


if __name__ == "__main__":
    main()
