# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side connect handshake parsing."""

from __future__ import annotations

import struct

import handshake_11g as fx
import pytest

from seerdb.exceptions import InterfaceError
from seerdb.server.handshake import parse_connect


def test_parse_real_11g_connect() -> None:
    # body = the CONNECT with its 8-byte TNS header stripped, as read_packet yields.
    req = parse_connect(fx.CONNECT[8:])
    assert req.protocol_version == 314
    assert req.lowest_version == 300
    assert req.sdu == 8192
    assert req.tdu == 65535
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


def test_too_short_raises() -> None:
    with pytest.raises(InterfaceError):
        parse_connect(b'\x01\x3a\x01\x2c')


def test_bad_offset_raises() -> None:
    # A 20-byte header claiming a descriptor 9000 bytes in.
    body = bytearray(20)
    struct.pack_into('>H', body, 18, 9000)  # cdata_offset field
    with pytest.raises(InterfaceError):
        parse_connect(bytes(body))
