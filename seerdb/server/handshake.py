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

from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import encode_packet
from seerdb.common.tns_consts import TNS_ACCEPT, TNS_DATA
from seerdb.server._handshake_11g import (
    build_caps_block_reply,
    build_dty_type_reply,
    build_pro_sqlplus_reply,
    build_type_reply_sqlplus,
)
from seerdb.server.framing import DEFAULT_SDU

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

# The classic sqlplus / thick-OCI PRO request leads its TTC payload with this
# magic instead of TTI_PRO (0x01); the Mirror must answer that request in the
# matching `deadbeef` dialect (#265).
_SQLPLUS_PRO_MAGIC = bytes.fromhex('deadbeef')


def pro_is_sqlplus(pro_body: bytes) -> bool:
    """Whether a PRO request is the classic sqlplus/thick `deadbeef` dialect
    (vs the oracledb/seerdb ``TTI_PRO`` dialect, which leads with the TTI_PRO
    ``0x01`` token).

    ``pro_body`` is what :meth:`PacketStream.read_packet` yields for the PRO
    ``TNS_DATA``: the TTC payload with **both** the 8-byte TNS header and the
    2-byte data-flags already stripped (``read_packet`` returns ``packet[10:]``
    for a DATA packet), so the magic sits at the very start — verified against a
    live sqlplus 11.2, which is exactly where a wrong offset misfires (#265).
    """
    return pro_body[:4] == _SQLPLUS_PRO_MAGIC


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


# A modern thin client (seerdb, go-ora, python-oracledb) runs an ANO (native
# network security) negotiation before PRO once the ACCEPT advertised ANO-capable
# — its container leads with the DEADBEEF magic and carries the 0x0B200200 ANO
# version at body offset 6. The classic sqlplus/thick-OCI client also negotiates
# ANO but stamps version 0x00000000, and its whole login is handled by the
# `deadbeef`-dialect path (#265) — so the modern version is what tells the two
# apart here. (#437)
_ANO_MAGIC = b'\xde\xad\xbe\xef'
_ANO_MODERN_VERSION = bytes.fromhex('0b200200')


def is_ano_negotiation(pro_body: bytes) -> bool:
    """Whether a post-ACCEPT packet is a modern thin client's ANO negotiation
    (vs a TTI_PRO or the sqlplus/OCI ANO, both handled by other paths)."""
    return pro_body[:4] == _ANO_MAGIC and pro_body[6:10] == _ANO_MODERN_VERSION


def encode_ano_null_reply(*, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the null-algorithm ANO negotiation reply — §ANO (#437).

    Replays the real 11g server's response to a modern client's ANO request:
    every service selects the null algorithm, so no cipher/MAC is activated and
    the session stays plaintext. (These are the same bytes the sqlplus/OCI path
    replays as its first `deadbeef` reply — it *is* the ANO response.)
    """
    packet, _ = encode_packet(TNS_DATA, build_pro_sqlplus_reply(), sdu)
    return packet


def encode_pro_reply(*, sqlplus: bool = False, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the server's PRO (protocol negotiation) reply — §4.1.

    Reproduces the real 11g server's PRO reply, whose capability array pins the
    negotiated field version to 6. ``sqlplus`` selects the classic
    ``deadbeef`` dialect (127B) over the oracledb/seerdb ``TTI_PRO`` dialect
    (238B); pass whatever :func:`pro_is_sqlplus` reported for the request.
    Returns the full TNS_DATA packet.
    """
    payload = build_pro_sqlplus_reply() if sqlplus else build_caps_block_reply()
    packet, _ = encode_packet(TNS_DATA, payload, sdu)
    return packet


def encode_dty_reply(*, sqlplus: bool = False, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the server's DTY (data-type negotiation) reply — §4.2.

    Reproduces the real 11g server's DTY reply as a full TNS_DATA packet.
    ``sqlplus`` selects the ``deadbeef`` dialect (238B — the same capability
    block as the thin PRO reply) over the oracledb/seerdb dialect (924B
    type-conversion table); use the same value the PRO reply used so both halves
    of the handshake speak one dialect.
    """
    payload = build_caps_block_reply() if sqlplus else build_dty_type_reply()
    packet, _ = encode_packet(TNS_DATA, payload, sdu)
    return packet


def encode_type_reply_sqlplus(*, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the deadbeef dialect's third-round data-type reply — the 26-byte
    ``ttc=02`` confirmation sqlplus/thick OCI expects after PRO and DTY, before
    it sends OSESSKEY (#265). Thin clients skip this round. Full TNS_DATA packet.
    """
    packet, _ = encode_packet(TNS_DATA, build_type_reply_sqlplus(), sdu)
    return packet
