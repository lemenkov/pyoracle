# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side connect handshake parsing."""

from __future__ import annotations

import struct
from dataclasses import replace

import handshake_11g as fx
import pytest

from seerdb.exceptions import InterfaceError
from seerdb.server.handshake import encode_accept, parse_connect


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


def test_too_short_raises() -> None:
    with pytest.raises(InterfaceError):
        parse_connect(b'\x01\x3a\x01\x2c')


def test_bad_offset_raises() -> None:
    # A 20-byte header claiming a descriptor 9000 bytes in.
    body = bytearray(20)
    struct.pack_into('>H', body, 18, 9000)  # cdata_offset field
    with pytest.raises(InterfaceError):
        parse_connect(bytes(body))
