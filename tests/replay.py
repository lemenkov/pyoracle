# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Capture-replay test harness (#439).

A captured server response — pasted straight from ``hexdump -C`` / Wireshark /
tcpdump output — becomes bytes an offline test can push through seerdb's packet
framing and decoders, with no socket and no server. The idea (a fake transport
seeded with a captured byte buffer) is adopted from the go-ora driver's debug
session (MIT, Copyright 2020 Samy Sultan); the parser and the replay socket here
are re-authored.

Capture files live in ``tests/captures/*.hexdump``. Each line is the canonical
``OFFSET  xx xx ..  |ascii|`` form; the offset column and the ``|ascii|`` gutter
are ignored, blank lines and ``#`` comments are skipped, so a capture pastes in
verbatim.
"""

from __future__ import annotations

import os

_CAPTURES = os.path.join(os.path.dirname(__file__), 'captures')


def parse_hexdump(text: str) -> bytes:
    """Extract the raw bytes from ``hexdump -C`` style text.

    Each data line is ``OFFSET  <hex bytes>  |ascii|``; the 8-column offset and
    the ``|ascii|`` gutter carry no packet bytes, so only the two-hex-digit
    tokens between them are taken. ``#`` comment lines and blank lines are
    skipped.
    """
    out = bytearray()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        bar = line.find('|')
        region = line[8:bar] if bar > 0 else line[8:]
        for token in region.split():
            if len(token) == 2:
                try:
                    out.append(int(token, 16))
                except ValueError:
                    # A stray non-hex token (unlikely between offset and gutter).
                    pass
    return bytes(out)


def load_capture(name: str) -> bytes:
    """Read ``tests/captures/<name>`` and return its bytes via :func:`parse_hexdump`."""
    with open(os.path.join(_CAPTURES, name), encoding='utf-8') as f:
        return parse_hexdump(f.read())


class ReplaySocket:
    """A minimal read-only stand-in for a stream socket, seeded with captured
    server bytes. ``recv`` hands them out in SDU-sized slices and then reports
    EOF (empty bytes), so a receive loop replaying a capture terminates cleanly.
    Writes are accepted and discarded (a replay never talks back)."""

    def __init__(self, data: bytes):
        self._buf = data

    def recv(self, size: int) -> bytes:
        chunk = self._buf[:size]
        self._buf = self._buf[size:]
        return chunk

    def send(self, data: bytes) -> int:  # pragma: no cover - writes are ignored
        return len(data)

    def sendall(self, data: bytes) -> None:  # pragma: no cover - writes are ignored
        pass
