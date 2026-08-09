# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side connect handshake parsing."""

from __future__ import annotations

import struct
from dataclasses import replace

import handshake_11g as fx
import pytest

from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import CCAP_FIELD_VERSION, decode_token_pro
from seerdb.common.tns_consts import FIELD_VERSION_11_2, TNS_DATA, TTI_DTY, TTI_PRO
from seerdb.server._handshake_11g import DTY_REPLY, PRO_REPLY
from seerdb.server.handshake import (
    encode_accept,
    encode_dty_reply,
    encode_pro_reply,
    parse_connect,
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


def test_too_short_raises() -> None:
    with pytest.raises(InterfaceError):
        parse_connect(b'\x01\x3a\x01\x2c')


def test_bad_offset_raises() -> None:
    # A 20-byte header claiming a descriptor 9000 bytes in.
    body = bytearray(20)
    struct.pack_into('>H', body, 18, 9000)  # cdata_offset field
    with pytest.raises(InterfaceError):
        parse_connect(bytes(body))
