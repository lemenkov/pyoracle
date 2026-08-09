# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side connect handshake.

Parses the client's CONNECT (the mirror of §2.1). The ACCEPT and PRO/DTY
replies (encode side) land in later increments; this module grows to hold the
whole handshake.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from seerdb.exceptions import InterfaceError

# The connect-data OFFSET field is measured from the start of the whole packet
# (it includes the 8-byte TNS header), while parse_connect receives the CONNECT
# body (what PacketStream.read_packet yields — header already stripped). So the
# descriptor sits at body[offset - 8].
_TNS_HEADER_LEN = 8

# Fixed-header field offsets, relative to the CONNECT body. This prefix is
# stable across protocol versions; where the descriptor lands varies (11g/v314
# puts it at packet offset 58, v319 at 74), so the offset field below — not a
# fixed position — is authoritative.
_OFF_VERSION = 0
_OFF_LOWEST = 2
_OFF_SDU = 6
_OFF_TDU = 8
_OFF_CDATA_LEN = 16
_OFF_CDATA_OFFSET = 18
_MIN_HEADER = 20  # bytes we must have to read every field above

_SERVICE_RE = re.compile(rb'\(SERVICE_NAME\s*=\s*([^)\s]+)', re.IGNORECASE)
_SID_RE = re.compile(rb'\(SID\s*=\s*([^)\s]+)', re.IGNORECASE)
_PROGRAM_RE = re.compile(rb'\(PROGRAM\s*=\s*([^)]*)\)', re.IGNORECASE)
_USER_RE = re.compile(rb'\(USER\s*=\s*([^)]*)\)', re.IGNORECASE)


@dataclass(frozen=True)
class ConnectRequest:
    """The negotiable parameters and identity a client asks for in CONNECT."""

    protocol_version: int
    lowest_version: int
    sdu: int
    tdu: int
    service_name: str | None
    program: str | None
    user: str | None
    descriptor: bytes


def _u16(body: bytes, offset: int) -> int:
    return struct.unpack('>H', body[offset : offset + 2])[0]


def _match(pattern: re.Pattern[bytes], descriptor: bytes) -> str | None:
    found = pattern.search(descriptor)
    return found.group(1).decode('ascii', 'replace') if found else None


def parse_connect(body: bytes) -> ConnectRequest:
    """Parse a CONNECT packet body into a :class:`ConnectRequest`.

    ``body`` is what :meth:`PacketStream.read_packet` returns for a
    ``TNS_CONNECT`` — the packet with its 8-byte TNS header already removed.
    Raises :class:`InterfaceError` if the packet is too short or the connect
    descriptor is out of bounds.
    """
    if len(body) < _MIN_HEADER:
        raise InterfaceError(f'CONNECT too short: {len(body)} bytes')

    cdata_len = _u16(body, _OFF_CDATA_LEN)
    cdata_offset = _u16(body, _OFF_CDATA_OFFSET)
    start = cdata_offset - _TNS_HEADER_LEN
    if start < 0 or start > len(body):
        raise InterfaceError(f'CONNECT descriptor offset out of range: {cdata_offset}')
    descriptor = body[start : start + cdata_len] if cdata_len else body[start:]

    return ConnectRequest(
        protocol_version=_u16(body, _OFF_VERSION),
        lowest_version=_u16(body, _OFF_LOWEST),
        sdu=_u16(body, _OFF_SDU),
        tdu=_u16(body, _OFF_TDU),
        service_name=_match(_SERVICE_RE, descriptor) or _match(_SID_RE, descriptor),
        program=_match(_PROGRAM_RE, descriptor),
        user=_match(_USER_RE, descriptor),
        descriptor=descriptor,
    )
