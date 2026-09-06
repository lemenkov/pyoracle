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

from seerdb.common import ano
from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import encode_packet
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_2,
    TNS_ACCEPT,
    TNS_DATA,
    TNS_VERSION_MIN_LARGE_SDU,
)
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

# The TNS protocol version the Mirror answers with. 314 (0x013a) is 11.2: below
# ``TNS_VERSION_MIN_LARGE_SDU`` (315), so the session keeps the legacy 2-byte
# packet framing. A client that speaks a newer version negotiates down to
# whatever is set here, exactly as it would against a real listener of that age.
#
# The version scale, anchored on what the testbeds actually answer: 11.2 -> 314,
# 21c -> 318, 23ai/26ai -> 320. 12.1 and 12.2 sit in the gap, so 12.2 is taken as
# 316 — inferred from those anchors rather than captured, since there is no 12.2
# testbed here. What is *behavioural* about the number (and is captured) is which
# side of two thresholds it falls on: >= 315 switches the post-ACCEPT DATA stream
# to the 4-byte packet length, and >= 318 (``TNS_VERSION_MIN_OOB_CHECK``) adds the
# extended ``flags2`` word a client reads for end-of-response support. 316 is
# large-SDU but not end-of-response, which is what a 12.2 server is.
TNS_VERSION_11_2 = 314
TNS_VERSION_12_2 = 316

_SERVER_TNS_VERSION = TNS_VERSION_11_2


def server_tns_version(field_version: int) -> int:
    """The protocol version that goes with an advertised field version.

    These two are one decision, not two. A session that advertises a 12.2 field
    version but answers 314 is not a server that exists: it claims 12.2
    capabilities and reports a 12.2 release, then frames the connection the 11.2
    way. Deriving one from the other means asking for a 12.2 Mirror gets a 12.2
    Mirror end to end.

    Tiered like :func:`seerdb.server.identity.server_identity`, and on the same
    threshold. A field version above 12.2 also lands here — 12.2 is the newest
    release the Mirror models, and answering 316 is nearer the truth than
    dropping back to 11.2's framing.
    """
    if field_version >= FIELD_VERSION_12_2:
        return TNS_VERSION_12_2
    return TNS_VERSION_11_2


# ACCEPT body fields that are server constants at 11g, read straight off the
# captured XE 11.2 ACCEPT (tests/handshake_11g.py): protocol characteristics,
# an accept-data length of 0, a flags word, and a reserved word.
_ACCEPT_PROTO_CHARS = 0x0100
_ACCEPT_DATA_LEN = 0x0000
_ACCEPT_FLAGS = 0x0020
_ACCEPT_RESERVED = 0x4141
_DEFAULT_TDU = 0xFFFF

# A >= 315 ACCEPT carries the real SDU/TDU as 32-bit fields and zeroes the 16-bit
# pair the legacy form used, so the body grows past the legacy 24 bytes. Offsets
# and length are read off a live 21c ACCEPT (version 318, body 37 bytes) — the
# nearest capture below the end-of-response era: 16-byte fixed head, 8 zero bytes,
# ub4 SDU at 24, ub4 TDU at 28, then a byte and the flags2 word at 33. A client
# only reads flags2 at >= 318, so at 316 it stays zero and no end-of-response is
# advertised. The 21c flags/reserved words differ from the 11g pair above.
_ACCEPT_LARGE_BODY_LEN = 37
_OFF_ACCEPT_SDU32 = 24
_OFF_ACCEPT_TDU32 = 28
_ACCEPT_LARGE_FLAGS = 0x002D
_ACCEPT_LARGE_RESERVED = 0x4101
_LARGE_DEFAULT_TDU = 0x2000

# The classic sqlplus / thick-OCI PRO request leads its TTC payload with the ANO
# container magic (0xDEADBEEF) instead of TTI_PRO (0x01); the Mirror must answer
# that request in the matching `deadbeef` dialect (#265).


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
    return pro_body[:4] == ano.ANO_MAGIC_BYTES


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


def encode_accept(
    request: ConnectRequest,
    *,
    sdu: int = DEFAULT_SDU,
    tns_version: int = _SERVER_TNS_VERSION,
) -> bytes:
    """Build the ACCEPT reply to a parsed CONNECT (the server side of §2.2).

    Negotiates the TNS version down to what the Mirror speaks, echoes the
    client's global service options, and settles the SDU/TDU to the smaller of
    each side's. Returns the full TNS_ACCEPT packet (header included), ready to
    hand to :meth:`PacketStream.write_packet`.
    """
    version = negotiated_tns_version(request, tns_version)
    negotiated_sdu = min(request.sdu, sdu)
    if version >= TNS_VERSION_MIN_LARGE_SDU:
        # The 16-bit SDU/TDU pair is zeroed and the real values move to the ub4
        # fields the client reads at offsets 24 / 28.
        large_body = bytearray(_ACCEPT_LARGE_BODY_LEN)
        struct.pack_into(
            '>HHHHHHHH',
            large_body,
            0,
            version,
            request.global_service_options,
            0,
            0,
            _ACCEPT_PROTO_CHARS,
            _ACCEPT_DATA_LEN,
            _ACCEPT_LARGE_FLAGS,
            _ACCEPT_LARGE_RESERVED,
        )
        struct.pack_into('>I', large_body, _OFF_ACCEPT_SDU32, negotiated_sdu)
        struct.pack_into(
            '>I', large_body, _OFF_ACCEPT_TDU32, min(request.tdu, _LARGE_DEFAULT_TDU)
        )
        packet, _ = encode_packet(TNS_ACCEPT, bytes(large_body), sdu)
        return packet
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


def negotiated_tns_version(
    request: ConnectRequest, tns_version: int = _SERVER_TNS_VERSION
) -> int:
    """The protocol version this connection settles on.

    At or above :data:`TNS_VERSION_MIN_LARGE_SDU` the post-ACCEPT ``DATA`` stream
    switches to the 4-byte packet length, so the session has to know this to
    frame the rest of the connection (the CONNECT and ACCEPT packets themselves
    stay in the legacy 16-bit form either way — §1.1).
    """
    return min(request.protocol_version, tns_version)


# A modern thin client (seerdb, go-ora, python-oracledb) runs an ANO (native
# network security) negotiation before PRO once the ACCEPT advertised ANO-capable
# — its container leads with the DEADBEEF magic and carries the 0x0B200200 ANO
# version at body offset 6. The classic sqlplus/thick-OCI client also negotiates
# ANO but stamps version 0x00000000, and its whole login is handled by the
# `deadbeef`-dialect path (#265) — so the modern version is what tells the two
# apart here. (#437)


def is_ano_negotiation(pro_body: bytes) -> bool:
    """Whether a post-ACCEPT packet is a modern thin client's ANO negotiation
    (vs a TTI_PRO or the sqlplus/OCI ANO, both handled by other paths)."""
    return pro_body[:4] == ano.ANO_MAGIC_BYTES and pro_body[6:10] == ano.VERSION_BYTES


def encode_ano_null_reply(*, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the null-algorithm ANO negotiation reply — §ANO (#437).

    Replays the real 11g server's response to a modern client's ANO request:
    every service selects the null algorithm, so no cipher/MAC is activated and
    the session stays plaintext. (These are the same bytes the sqlplus/OCI path
    replays as its first `deadbeef` reply — it *is* the ANO response.)
    """
    packet, _ = encode_packet(TNS_DATA, build_pro_sqlplus_reply(), sdu)
    return packet


def encode_pro_reply(
    *,
    sqlplus: bool = False,
    sdu: int = DEFAULT_SDU,
    field_version: int = FIELD_VERSION_11_2,
) -> bytes:
    """Build the server's PRO (protocol negotiation) reply — §4.1.

    Reproduces the real 11g server's PRO reply, whose capability array pins the
    negotiated field version to 6. ``sqlplus`` selects the classic
    ``deadbeef`` dialect (127B) over the oracledb/seerdb ``TTI_PRO`` dialect
    (238B); pass whatever :func:`pro_is_sqlplus` reported for the request.
    Returns the full TNS_DATA packet.
    """
    payload = (
        build_pro_sqlplus_reply() if sqlplus else build_caps_block_reply(field_version)
    )
    packet, _ = encode_packet(TNS_DATA, payload, sdu)
    return packet


def encode_dty_reply(
    *,
    sqlplus: bool = False,
    sdu: int = DEFAULT_SDU,
    field_version: int = FIELD_VERSION_11_2,
) -> bytes:
    """Build the server's DTY (data-type negotiation) reply — §4.2.

    Reproduces the real 11g server's DTY reply as a full TNS_DATA packet.
    ``sqlplus`` selects the ``deadbeef`` dialect (238B — the same capability
    block as the thin PRO reply) over the oracledb/seerdb dialect (924B
    type-conversion table); use the same value the PRO reply used so both halves
    of the handshake speak one dialect.
    """
    payload = (
        build_caps_block_reply(field_version) if sqlplus else build_dty_type_reply()
    )
    packet, _ = encode_packet(TNS_DATA, payload, sdu)
    return packet


def encode_type_reply_sqlplus(*, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the deadbeef dialect's third-round data-type reply — the 26-byte
    ``ttc=02`` confirmation sqlplus/thick OCI expects after PRO and DTY, before
    it sends OSESSKEY (#265). Thin clients skip this round. Full TNS_DATA packet.
    """
    packet, _ = encode_packet(TNS_DATA, build_type_reply_sqlplus(), sdu)
    return packet
