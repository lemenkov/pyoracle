# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side framing: read_packet is a true inverse of the client's send()."""

from __future__ import annotations

import socket

from seerdb.common.tns import encode_packet
from seerdb.common.tns_consts import TNS_CONNECT, TNS_DATA
from seerdb.server.framing import PacketStream


def _pair() -> tuple[socket.socket, socket.socket]:
    return socket.socketpair()


def test_reads_a_single_connect_packet() -> None:
    left, right = _pair()
    try:
        body = b'(CONNECT_DATA=(SERVICE_NAME=orcl))'
        packet, rest = encode_packet(TNS_CONNECT, body, 8192)
        assert rest is None
        left.sendall(packet)
        stream = PacketStream(right, sdu=8192)
        result = stream.read_packet()
        assert result == (TNS_CONNECT, body)
    finally:
        left.close()
        right.close()


def test_eof_returns_none() -> None:
    left, right = _pair()
    left.close()
    try:
        stream = PacketStream(right, sdu=8192)
        assert stream.read_packet() is None
    finally:
        right.close()


def test_data_roundtrips_through_write_then_read() -> None:
    left, right = _pair()
    try:
        writer = PacketStream(left, sdu=8192)
        reader = PacketStream(right, sdu=8192)
        payload = b'\x03\x05exec-body-goes-here'
        writer.write_packet(TNS_DATA, payload)
        assert reader.read_packet() == (TNS_DATA, payload)
    finally:
        left.close()
        right.close()


def test_large_data_fragments_reassemble() -> None:
    # A payload several times the SDU must split on write and reassemble on
    # read — the case assemble_packet's server-side heuristic would mishandle.
    left, right = _pair()
    try:
        sdu = 64
        writer = PacketStream(left, sdu=sdu)
        reader = PacketStream(right, sdu=sdu)
        payload = bytes(range(256)) * 3  # 768 bytes >> sdu, forces many splits
        writer.write_packet(TNS_DATA, payload)
        assert reader.read_packet() == (TNS_DATA, payload)
    finally:
        left.close()
        right.close()


def test_two_back_to_back_packets() -> None:
    # Consecutive packets in one buffer are framed independently.
    left, right = _pair()
    try:
        writer = PacketStream(left, sdu=8192)
        reader = PacketStream(right, sdu=8192)
        writer.write_packet(TNS_DATA, b'first')
        writer.write_packet(TNS_DATA, b'second')
        assert reader.read_packet() == (TNS_DATA, b'first')
        assert reader.read_packet() == (TNS_DATA, b'second')
    finally:
        left.close()
        right.close()
