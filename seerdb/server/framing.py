# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side TNS packet framing.

This is the read/write counterpart of the client's ``Connection.recv()`` /
``Connection.send()``. Writing reuses :func:`seerdb.common.tns.encode_packet` verbatim
— the on-wire packet is identical whichever end emits it.

Reading, however, is *not* a straight reuse of :func:`seerdb.common.tns.assemble_packet`.
That routine reassembles multi-fragment ``DATA`` the way the **real Oracle
server** fragments it — keyed on an SDU-boundary heuristic
(``PacketSize == Length - 37`` / ``- 81``). A *client* fragments the other way:
``encode_packet`` splits at the full SDU and marks every non-final fragment with
the ``0x0020`` "more data" flag. Those two conventions are not inverses, so a
server that reused ``assemble_packet`` to read client requests would mis-split
any request large enough to fragment. We therefore parse the header ourselves
and key ``DATA`` reassembly on the ``0x0020`` flag — making ``read_packet`` a
true inverse of the client's ``send()``.

The 8-byte header has two layouts (see ``assemble_packet``): legacy
``len(ub2) + cksum(ub2) + type + flags + hdr-cksum(ub2)`` and, from protocol
version 315 (large SDU, #155), ``len(ub4) + type + flags + hdr-cksum(ub2)``.
"""

from __future__ import annotations

import socket
import struct

from seerdb.common.tns import encode_packet
from seerdb.common.tns_consts import DEFAULT_SDU, TNS_DATA

# Re-exported for the server modules that frame at the default SDU.
__all__ = ['DEFAULT_SDU', 'PacketStream']

# Non-final DATA fragment marker in the 2-byte data-flags that follow the
# header (PROTOCOL.md §1.3). encode_packet stamps this on every fragment but
# the last one.
_DATA_FLAG_MORE = 0x0020

_HEADER_LEGACY = struct.Struct('>HhBBh')  # size, cksum, type, flags, hdr-cksum
_HEADER_LARGE = struct.Struct('>IBBh')  # size, type, flags, hdr-cksum
_DATA_FLAGS = struct.Struct('>H')


class PacketStream:
    """Frames a connected stream socket into TNS packets.

    One instance per client connection; not thread-safe. ``read_packet`` blocks
    until a full packet (reassembling ``DATA`` fragments) is available or the
    peer closes; ``write_packet`` splits oversized payloads exactly as the
    client does.
    """

    def __init__(
        self, sock: socket.socket, *, sdu: int = DEFAULT_SDU, large: bool = False
    ) -> None:
        self._sock = sock
        self.sdu = sdu
        self.large = large
        self._acc = b''

    def _fill(self, n: int) -> bool:
        # Pull from the socket until the accumulator holds at least n bytes.
        # False signals the peer closed before n bytes arrived.
        while len(self._acc) < n:
            chunk = self._sock.recv(self.sdu)
            if not chunk:
                return False
            self._acc += chunk
        return True

    def _header(self) -> tuple[int, int]:
        # Parse (packet_size, type) from the 8-byte header at the front of _acc.
        head = self._acc[:8]
        if self.large:
            size, packet_type, _flags, _zero = _HEADER_LARGE.unpack(head)
        else:
            size, _cksum, packet_type, _flags, _zero = _HEADER_LEGACY.unpack(head)
        return size, packet_type

    def read_packet(self) -> tuple[int, bytes] | None:
        """Return ``(type, body)`` for the next packet, or ``None`` at EOF.

        ``DATA`` fragments (non-final ones carry the ``0x0020`` flag) are
        reassembled into a single body. For non-``DATA`` packets the body is
        everything after the 8-byte header.
        """
        body = b''
        while True:
            if not self._fill(8):
                self._acc = b''
                return None
            size, packet_type = self._header()
            if not self._fill(size):
                self._acc = b''
                return None
            packet = self._acc[:size]
            self._acc = self._acc[size:]
            if packet_type == TNS_DATA:
                (data_flags,) = _DATA_FLAGS.unpack(packet[8:10])
                body += packet[10:size]
                if data_flags & _DATA_FLAG_MORE:
                    continue
                return (TNS_DATA, body)
            return (packet_type, packet[8:size])

    def write_packet(self, packet_type: int, body: bytes) -> None:
        """Send one logical packet, splitting oversized payloads across SDUs.

        Mirrors ``Connection.send()``: ``encode_packet`` hands back the
        unsent remainder until it is exhausted.
        """
        data: bytes | None = body
        while data is not None:
            packet, data = encode_packet(packet_type, data, self.sdu, self.large)
            self._sock.sendall(packet)

    def send_raw(self, packet: bytes) -> None:
        """Send an already-framed packet verbatim (it includes its TNS header).

        For the handshake replies (ACCEPT / PRO / DTY) that are built as whole
        packets; TTC payloads go through :meth:`write_packet` instead.
        """
        self._sock.sendall(packet)
