# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side connect handshake parsing."""

from __future__ import annotations

import struct
from dataclasses import replace

import handshake_11g as fx
import pytest

# The captured PRO/DTY replies now live as golden fixtures alongside the
# generation test (the server module builds them from named pieces).
from test_handshake_generation import (
    DTY_REPLY,
    DTY_REPLY_SQLPLUS,
    PRO_REPLY,
    PRO_REPLY_SQLPLUS,
)

from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import CCAP_FIELD_VERSION, decode_token_pro
from seerdb.common.tns_consts import FIELD_VERSION_11_2, TNS_DATA, TTI_DTY, TTI_PRO
from seerdb.server.handshake import (
    encode_accept,
    encode_dty_reply,
    encode_pro_reply,
    parse_connect,
    pro_is_sqlplus,
)


def test_parse_real_11g_connect() -> None:
    # body = the CONNECT with its 8-byte TNS header stripped, as read_packet yields.
    req = parse_connect(fx.CONNECT[8:])
    assert req.protocol_version == 314
    assert req.lowest_version == 300
    assert req.sdu == 8192
    assert req.tdu == 65535
    assert req.global_service_options == 0x0C41
    assert req.service_name == 'XE'
    assert req.program == 'sqlplus@firefly'
    assert req.user == 'petro'
    assert req.descriptor.startswith(b'(DESCRIPTION')


def test_descriptor_offset_is_honoured_not_assumed() -> None:
    # The 11g client puts its descriptor at packet offset 58, not the v319 74 —
    # parsing must read the offset field, so the descriptor stays intact.
    req = parse_connect(fx.CONNECT[8:])
    assert req.descriptor.endswith(b'))')
    assert b'(PORT=1599)' in req.descriptor


def test_encode_accept_byte_matches_the_real_11g_accept() -> None:
    # The killer test: our ACCEPT reproduces the captured server packet exactly.
    req = parse_connect(fx.CONNECT[8:])
    assert encode_accept(req) == fx.ACCEPT


def test_accept_caps_version_for_a_newer_client() -> None:
    # A 12c+/v319 client negotiates down to the version the Mirror speaks (314),
    # just as it would against a real 11g listener.
    req = replace(parse_connect(fx.CONNECT[8:]), protocol_version=319)
    accept = encode_accept(req)
    assert struct.unpack('>H', accept[8:10])[0] == 314


def test_accept_settles_sdu_to_the_smaller_side() -> None:
    req = replace(parse_connect(fx.CONNECT[8:]), sdu=65535)
    accept = encode_accept(req, sdu=8192)
    assert struct.unpack('>H', accept[12:14])[0] == 8192  # body[4:6] = SDU


def test_pro_reply_reproduces_the_captured_packet() -> None:
    # Re-wrapping the stored payload must reproduce the real server packet —
    # proves both the payload and our DATA framing match the wire.
    assert encode_pro_reply() == PRO_REPLY


def test_dty_reply_reproduces_the_captured_packet() -> None:
    assert encode_dty_reply() == DTY_REPLY


def test_pro_reply_is_a_data_packet_leading_tti_pro() -> None:
    packet = encode_pro_reply()
    assert packet[4] == TNS_DATA
    assert packet[10] == TTI_PRO


def test_dty_reply_leads_tti_dty() -> None:
    assert encode_dty_reply()[10] == TTI_DTY


def test_pro_reply_pins_field_version_11g() -> None:
    # The conformance check: seerdb's own PRO decoder reads field version 6
    # out of the reply's capability array — so a client negotiates 11g.
    caps = decode_token_pro(encode_pro_reply()[10:])['compile_caps']
    assert caps[CCAP_FIELD_VERSION] == FIELD_VERSION_11_2


def test_pro_reply_field_version_is_negotiable() -> None:
    # The advertised field version is the one byte a client negotiates on; the
    # rest of the pinned 11.2 identity is unchanged around it.
    from seerdb.common.tns_consts import FIELD_VERSION_12_1, FIELD_VERSION_23_1

    for version in (FIELD_VERSION_12_1, FIELD_VERSION_23_1):
        reply = encode_pro_reply(field_version=version)
        caps = decode_token_pro(reply[10:])['compile_caps']
        assert caps[CCAP_FIELD_VERSION] == version
        default = encode_pro_reply()
        assert len(reply) == len(default)
        diffs = [i for i in range(len(reply)) if reply[i] != default[i]]
        assert len(diffs) == 1


# --- sqlplus 'deadbeef' PRO dialect (#265) ---


def _read_packet_body(raw: bytes) -> tuple[int, bytes]:
    # Drive raw wire bytes through the real PacketStream.read_packet, so the body
    # is exactly what the serve loop feeds pro_is_sqlplus (header + data-flags
    # stripped) — not a hand-sliced approximation.
    import socket

    from seerdb.server.framing import PacketStream

    a, b = socket.socketpair()
    try:
        a.sendall(raw)
        a.shutdown(socket.SHUT_WR)
        return PacketStream(b).read_packet()
    finally:
        a.close()
        b.close()


def test_pro_is_sqlplus_detects_the_deadbeef_dialect() -> None:
    # Run the captured sqlplus PRO through read_packet — the exact path a live
    # client exercises. read_packet strips the 8-byte header AND the 2-byte
    # data-flags, so the deadbeef magic must be at the very start of the body.
    # (Feeding a hand-sliced PRO_CLIENT[8:] hid an off-by-two here; a live
    # sqlplus 11.2 caught it — #265.)
    typ, body = _read_packet_body(fx.PRO_CLIENT)
    assert typ == TNS_DATA
    assert pro_is_sqlplus(body) is True

    # A thin (TTI_PRO) PRO through the same path is not the sqlplus dialect.
    thin_raw = struct.pack('>HHBBH', 8 + 2 + 8, 0, TNS_DATA, 0, 0)
    thin_raw += b'\x00\x00' + bytes([TTI_PRO, 6, 5, 4, 3, 2, 1, 0])
    _typ, thin_body = _read_packet_body(thin_raw)
    assert pro_is_sqlplus(thin_body) is False


def test_sqlplus_pro_reply_reproduces_the_captured_packet() -> None:
    # Re-wrapping the stored deadbeef payload reproduces the real sqlplus-dialect
    # server PRO packet (127B) exactly.
    assert encode_pro_reply(sqlplus=True) == fx.PRO_SERVER
    assert PRO_REPLY_SQLPLUS == fx.PRO_SERVER


def test_sqlplus_dty_reply_reproduces_the_captured_packet() -> None:
    assert encode_dty_reply(sqlplus=True) == fx.DTY_SERVER
    assert DTY_REPLY_SQLPLUS == fx.DTY_SERVER


def test_sqlplus_type_reply_reproduces_the_captured_packet() -> None:
    # The deadbeef dialect's third round: the built ttc=02 reply reproduces the
    # real server packet (#265).
    from test_handshake_generation import TYPE_REPLY_SQLPLUS

    from seerdb.server.handshake import encode_type_reply_sqlplus

    assert encode_type_reply_sqlplus() == TYPE_REPLY_SQLPLUS


def test_dialects_are_distinct() -> None:
    # The two dialects' replies are genuinely different shapes (238/924 vs
    # 127/238), so serving the wrong one would break the handshake.
    assert encode_pro_reply(sqlplus=True) != encode_pro_reply(sqlplus=False)
    assert encode_dty_reply(sqlplus=True) != encode_dty_reply(sqlplus=False)


def test_too_short_raises() -> None:
    with pytest.raises(InterfaceError):
        parse_connect(b'\x01\x3a\x01\x2c')


def test_bad_offset_raises() -> None:
    # A 20-byte header claiming a descriptor 9000 bytes in.
    body = bytearray(20)
    struct.pack_into('>H', body, 18, 9000)  # cdata_offset field
    with pytest.raises(InterfaceError):
        parse_connect(bytes(body))
