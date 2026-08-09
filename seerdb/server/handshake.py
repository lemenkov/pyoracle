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
from seerdb.server._handshake_11g import DTY_REPLY, PRO_REPLY
from seerdb.server.framing import DEFAULT_SDU
from seerdb.tns import encode_packet
from seerdb.tns_consts import TNS_ACCEPT, TNS_DATA

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
_OFF_OPTIONS = 4  # global service options
_OFF_SDU = 6
_OFF_TDU = 8
_OFF_CDATA_LEN = 16
_OFF_CDATA_OFFSET = 18
_MIN_HEADER = 20  # bytes we must have to read every field above

# The highest TNS protocol version the Mirror speaks. Pinned to 11g (0x013a =
# 314): < 315 so the connection uses legacy 2-byte framing, no large SDU, no
# end-of-response. A newer client negotiates down to this, exactly as it would
# against a real 11g listener.
_SERVER_TNS_VERSION = 314

# ACCEPT body fields that are server constants at 11g, read straight off the
# captured XE 11.2 ACCEPT (tests/handshake_11g.py): protocol characteristics,
# an accept-data length of 0, a flags word, and a reserved word.
_ACCEPT_PROTO_CHARS = 0x0100
_ACCEPT_DATA_LEN = 0x0000
_ACCEPT_FLAGS = 0x0020
_ACCEPT_RESERVED = 0x4141
_DEFAULT_TDU = 0xFFFF

# A DATA packet's TTC payload starts after the 8-byte TNS header + 2-byte data
# flags. The captured PRO/DTY replies are stored as full packets; re-wrapping
# their payload reproduces the packet and proves our framing matches the wire.
_DATA_PREFIX = 10

_SERVICE_RE = re.compile(rb'\(SERVICE_NAME\s*=\s*([^)\s]+)', re.IGNORECASE)
_SID_RE = re.compile(rb'\(SID\s*=\s*([^)\s]+)', re.IGNORECASE)
_PROGRAM_RE = re.compile(rb'\(PROGRAM\s*=\s*([^)]*)\)', re.IGNORECASE)
_USER_RE = re.compile(rb'\(USER\s*=\s*([^)]*)\)', re.IGNORECASE)


@dataclass(frozen=True)
class ConnectRequest:
    """The negotiable parameters and identity a client asks for in CONNECT."""

    protocol_version: int
    lowest_version: int
    global_service_options: int
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
        global_service_options=_u16(body, _OFF_OPTIONS),
        sdu=_u16(body, _OFF_SDU),
        tdu=_u16(body, _OFF_TDU),
        service_name=_match(_SERVICE_RE, descriptor) or _match(_SID_RE, descriptor),
        program=_match(_PROGRAM_RE, descriptor),
        user=_match(_USER_RE, descriptor),
        descriptor=descriptor,
    )


def encode_accept(request: ConnectRequest, *, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the ACCEPT reply to a parsed CONNECT (the server side of §2.2).

    Negotiates the TNS version down to what the Mirror speaks, echoes the
    client's global service options, and settles the SDU/TDU to the smaller of
    each side's. Returns the full TNS_ACCEPT packet (header included), ready to
    hand to :meth:`PacketStream.write_packet`.
    """
    version = min(request.protocol_version, _SERVER_TNS_VERSION)
    negotiated_sdu = min(request.sdu, sdu)
    negotiated_tdu = min(request.tdu, _DEFAULT_TDU)
    body = struct.pack(
        '>HHHHHHHH',
        version,
        request.global_service_options,
        negotiated_sdu,
        negotiated_tdu,
        _ACCEPT_PROTO_CHARS,
        _ACCEPT_DATA_LEN,
        _ACCEPT_FLAGS,
        _ACCEPT_RESERVED,
    ) + bytes(8)
    packet, _ = encode_packet(TNS_ACCEPT, body, sdu)
    return packet


def encode_pro_reply(*, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the server's PRO (protocol negotiation) reply — §4.1.

    Serves the oracledb/seerdb (``TTI_PRO``) dialect: replays the real 11g
    server's PRO reply, whose capability array pins the negotiated field
    version to 6. Returns the full TNS_DATA packet. The old sqlplus
    ``deadbeef`` PRO dialect is a different reply shape, not served yet.
    """
    packet, _ = encode_packet(TNS_DATA, PRO_REPLY[_DATA_PREFIX:], sdu)
    return packet


def encode_dty_reply(*, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the server's DTY (data-type negotiation) reply — §4.2.

    Replays the real 11g server's DTY reply (oracledb/seerdb dialect) as a
    full TNS_DATA packet.
    """
    packet, _ = encode_packet(TNS_DATA, DTY_REPLY[_DATA_PREFIX:], sdu)
    return packet
