# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Oracle Advanced Networking (ANO) negotiation codec (#437).

Oracle negotiates *native network encryption* and *data integrity* (the
"Advanced Security" / ANO options) right after the protocol accept and before
the PRO / DTY / auth exchange, using a self-contained packet format that is
distinct from the rest of TTC.

This module is the **sans-io codec** only: pure encode/decode of the negotiation
container, its four services, and their typed sub-packets, plus the algorithm-ID
tables. The Diffie-Hellman key exchange, the ciphers / MACs, and the wiring into
the connection handshake are separate, later phases.

Wire layout
-----------
A negotiation packet is a *container* followed by N *services*::

    container: magic(0xDEADBEEF, 4) | length(2) | version(4) | count(2) | err(1)
    service:   type(2) | subpacket_count(2) | err(4) | subpacket*

``length`` is the whole packet (``13`` container bytes + every service). Each
sub-packet is ``length(2) | type(2) | payload``; the type tags are:

    0 string   1 bytes   2 UB1   3 UB2   4 UB4   5 version   6 status

with a special UB2-array riding on the ``bytes`` tag (a ``0xDEADBEEF|3|count``
prefix). All integers are big-endian.

The layouts were re-expressed from the go-ora driver (MIT, Copyright 2020 Samy
Sultan); they are protocol facts the Oracle server enforces on the wire.
"""

import struct
from dataclasses import dataclass
from secrets import token_bytes

ANO_MAGIC = 0xDEADBEEF
# The "version" advertised in the container header and echoed per service.
ANO_VERSION = 0x17000000

# Service types.
SERVICE_AUTH = 1
SERVICE_ENCRYPTION = 2
SERVICE_DATA_INTEGRITY = 3
SERVICE_SUPERVISOR = 4

# Sub-packet type tags.
SP_STRING = 0
SP_BYTES = 1
SP_UB1 = 2
SP_UB2 = 3
SP_UB4 = 4
SP_VERSION = 5
SP_STATUS = 6

# Supervisor service payload.
SUPERVISOR_CID = bytes([0, 0, 16, 28, 102, 236, 40, 234])
SUPERVISOR_SERVICE_LIST = [
    SERVICE_SUPERVISOR,
    SERVICE_AUTH,
    SERVICE_ENCRYPTION,
    SERVICE_DATA_INTEGRITY,
]  # the {4, 1, 2, 3} the supervisor announces
SUPERVISOR_STATUS_OK = 31

# Encryption algorithm name -> wire ID.
ENCRYPTION_ALGO_IDS = {
    'RC4_40': 1,
    'RC4_56': 8,
    'RC4_128': 10,
    'RC4_256': 6,
    'DES40C': 3,
    'DES56C': 2,
    '3DES112': 11,
    '3DES168': 12,
    'AES128': 15,
    'AES192': 16,
    'AES256': 17,
}

# Data-integrity algorithm name -> wire ID.
INTEGRITY_ALGO_IDS = {
    'MD5': 1,
    'SHA1': 3,
    'SHA512': 4,
    'SHA256': 5,
    'SHA384': 6,
}

# The container header is a fixed 13 bytes: magic|length|version|count|err.
_HEADER = struct.Struct('>IHIHB')
_HEADER_LEN = _HEADER.size  # 13
# A service header is 8 bytes: type|subpacket_count|err.
_SERVICE_HEADER = struct.Struct('>HHI')


class AnoError(Exception):
    """A malformed ANO packet, or a server-signalled negotiation error."""


# --------------------------------------------------------------------------- #
# Sub-packet encoders — each is length(2) | type(2) | payload.
# --------------------------------------------------------------------------- #


def _subpacket(Type: int, Payload: bytes) -> bytes:
    return struct.pack('>HH', len(Payload), Type) + Payload


def sp_string(Value: bytes) -> bytes:
    return _subpacket(SP_STRING, Value)


def sp_bytes(Value: bytes) -> bytes:
    return _subpacket(SP_BYTES, Value)


def sp_ub1(Value: int) -> bytes:
    return _subpacket(SP_UB1, bytes([Value & 0xFF]))


def sp_ub2(Value: int) -> bytes:
    return _subpacket(SP_UB2, struct.pack('>H', Value))


def sp_ub4(Value: int) -> bytes:
    return _subpacket(SP_UB4, struct.pack('>I', Value))


def sp_version(Value: int = ANO_VERSION) -> bytes:
    return _subpacket(SP_VERSION, struct.pack('>I', Value))


def sp_status(Value: int) -> bytes:
    return _subpacket(SP_STATUS, struct.pack('>H', Value))


def sp_ub2_array(Values: list[int]) -> bytes:
    # A UB2 array rides on the `bytes` tag: a 0xDEADBEEF | 3 | count prefix, then
    # each element as a UB2. The header length is 10 + 2*count.
    Payload = struct.pack('>IHI', ANO_MAGIC, 3, len(Values))
    Payload += b''.join(struct.pack('>H', V) for V in Values)
    return _subpacket(SP_BYTES, Payload)


def parse_ub2_array(Payload: bytes) -> list[int]:
    """Decode the payload of a UB2-array sub-packet (see :func:`sp_ub2_array`)."""
    (Magic, Tag, Count) = struct.unpack_from('>IHI', Payload, 0)
    if Magic != ANO_MAGIC or Tag != 3:
        raise AnoError('malformed ANO UB2 array')
    Ints = struct.unpack_from(f'>{Count}H', Payload, 10)
    return list(Ints)


# --------------------------------------------------------------------------- #
# Service + container assembly.
# --------------------------------------------------------------------------- #


def encode_service(ServiceType: int, SubPackets: list[bytes]) -> bytes:
    """A service header (type | count | err=0) followed by its sub-packets."""
    Body = b''.join(SubPackets)
    return _SERVICE_HEADER.pack(ServiceType, len(SubPackets), 0) + Body


def encode_ano(Services: list[bytes]) -> bytes:
    """Wrap already-encoded services (in wire order) in a container header."""
    Body = b''.join(Services)
    Total = _HEADER_LEN + len(Body)
    return _HEADER.pack(ANO_MAGIC, Total, ANO_VERSION, len(Services), 0) + Body


# --------------------------------------------------------------------------- #
# Standard client services.
# --------------------------------------------------------------------------- #


def supervisor_service() -> bytes:
    """The supervisor service: version, control-ID, and the announced services."""
    return encode_service(
        SERVICE_SUPERVISOR,
        [
            sp_version(),
            sp_bytes(SUPERVISOR_CID),
            sp_ub2_array(SUPERVISOR_SERVICE_LIST),
        ],
    )


def encryption_service(AlgoNames: list[str]) -> bytes:
    """The encryption service: version, offered algorithm IDs, and a driver flag.

    The offered list is prefixed with the null algorithm (ID 0) — the "no
    service" fallback the server expects at the head of the list.
    """
    Ids = bytes([0]) + bytes(ENCRYPTION_ALGO_IDS[Name] for Name in AlgoNames)
    return encode_service(
        SERVICE_ENCRYPTION,
        [sp_version(), sp_bytes(Ids), sp_ub1(1)],
    )


def data_integrity_service(AlgoNames: list[str]) -> bytes:
    """The data-integrity service: version and the offered checksum algorithm IDs."""
    Ids = bytes([0]) + bytes(INTEGRITY_ALGO_IDS[Name] for Name in AlgoNames)
    return encode_service(
        SERVICE_DATA_INTEGRITY,
        [sp_version(), sp_bytes(Ids)],
    )


# Authentication service markers (no NTS/Kerberos selected by a thin client).
AUTH_MARKER = 0xE0E1
AUTH_STATUS_NONE = 0xFCFF


def auth_service() -> bytes:
    """The minimal authentication service — no NTS/Kerberos method offered."""
    return encode_service(
        SERVICE_AUTH,
        [sp_version(), sp_ub2(AUTH_MARKER), sp_status(AUTH_STATUS_NONE)],
    )


def dh_public_key_round(PublicKey: bytes) -> bytes:
    """The second negotiation round: the client's DH public key.

    A one-service container (data-integrity, a single ``bytes`` sub-packet) that
    the client sends after the server's response supplies the DH parameters.
    """
    return encode_ano([encode_service(SERVICE_DATA_INTEGRITY, [sp_bytes(PublicKey)])])


# --------------------------------------------------------------------------- #
# Parsing a negotiation response.
# --------------------------------------------------------------------------- #


def read_subpacket(Data: bytes, Offset: int) -> tuple[int, object, int]:
    """Read one sub-packet at ``Offset``; return ``(type, value, next_offset)``.

    Integer tags decode to ``int``; string/bytes (and the UB2-array) return the
    raw payload ``bytes`` — use :func:`parse_ub2_array` for the latter.
    """
    (Length, Type) = struct.unpack_from('>HH', Data, Offset)
    Offset += 4
    Payload = Data[Offset : Offset + Length]
    if len(Payload) != Length:
        raise AnoError('truncated ANO sub-packet')
    Offset += Length
    if Type == SP_UB1:
        return (Type, Payload[0], Offset)
    if Type in (SP_UB2, SP_STATUS):
        return (Type, struct.unpack('>H', Payload)[0], Offset)
    if Type in (SP_UB4, SP_VERSION):
        return (Type, struct.unpack('>I', Payload)[0], Offset)
    return (Type, Payload, Offset)


def decode_ano(Data: bytes) -> dict:
    """Parse a negotiation container into ``{version, services}``.

    ``services`` is a list of ``{type, error, subpackets}`` where ``subpackets``
    is a list of ``(type, value)`` from :func:`read_subpacket`. Raises
    :class:`AnoError` on a bad magic or a non-zero error flag.
    """
    if len(Data) < _HEADER_LEN:
        raise AnoError('ANO packet shorter than its header')
    (Magic, _Length, Version, Count, ErrFlag) = _HEADER.unpack_from(Data, 0)
    if Magic != ANO_MAGIC:
        raise AnoError(f'bad ANO magic 0x{Magic:08x}')
    if ErrFlag != 0:
        raise AnoError(f'ANO negotiation error flag {ErrFlag}')
    Offset = _HEADER_LEN
    Services = []
    for _ in range(Count):
        (SType, SubCount, SErr) = _SERVICE_HEADER.unpack_from(Data, Offset)
        Offset += _SERVICE_HEADER.size
        SubPackets = []
        for _ in range(SubCount):
            (Type, Value, Offset) = read_subpacket(Data, Offset)
            SubPackets.append((Type, Value))
        Services.append({'type': SType, 'error': SErr, 'subpackets': SubPackets})
    return {'version': Version, 'services': Services}


# --------------------------------------------------------------------------- #
# Diffie-Hellman key exchange (carried in the data-integrity service).
# --------------------------------------------------------------------------- #
#
# When the server's data-integrity service reply has 8 sub-packets, the tail
# carries a DH exchange: after (version, algo-id) come the generator bit-length
# and prime bit-length (UB2), then the generator, the prime, the server's public
# key, and the old IV (all `bytes`). The client picks a random private key of the
# same byte length, and computes:
#
#     public_key = generator ** private       (mod prime)   -> sent back
#     session_key = server_public ** private   (mod prime)   -> the shared secret
#     iv = session_key[32:64]
#
# The session key then folds into the crypto/MAC key (a later phase).


@dataclass
class DiffieHellman:
    """The result of the client-side DH computation."""

    # The client public key to send back, left-padded to the prime's byte length.
    public_key: bytes
    # The shared secret — the negotiation session key.
    session_key: bytes
    # The initial IV: bytes 32..64 of the session key.
    iv: bytes


def extract_dh_params(Service: dict) -> tuple[bytes, bytes, bytes, bytes]:
    """Pull ``(generator, prime, server_public, old_iv)`` from a decoded
    data-integrity service that carried a DH exchange (8 sub-packets)."""
    Sub = Service['subpackets']
    if len(Sub) < 8:
        raise AnoError('data-integrity service carries no DH exchange')
    # Sub = version, algo-id, gen-bitlen, prime-bitlen, gen, prime, server-pub, iv.
    return (Sub[4][1], Sub[5][1], Sub[6][1], Sub[7][1])


def compute_dh(
    Generator: bytes,
    Prime: bytes,
    ServerPublic: bytes,
    Private: bytes | None = None,
) -> DiffieHellman:
    """Run the client half of the DH exchange.

    ``Private`` (the client's random secret, one prime-length block) is generated
    when omitted; pass it only for deterministic tests. Keys are left-padded to
    the prime's byte length, matching what the server expects on the wire.
    """
    ByteLen = len(Prime)
    if ByteLen == 0:
        raise AnoError('empty DH prime')
    G = int.from_bytes(Generator, 'big')
    P = int.from_bytes(Prime, 'big')
    if Private is None:
        Private = token_bytes(ByteLen)
    Priv = int.from_bytes(Private, 'big')
    ServerPub = int.from_bytes(ServerPublic, 'big')
    Public = pow(G, Priv, P)
    Shared = pow(ServerPub, Priv, P)
    SessionKey = Shared.to_bytes(ByteLen, 'big')
    return DiffieHellman(
        public_key=Public.to_bytes(ByteLen, 'big'),
        session_key=SessionKey,
        iv=SessionKey[0x20:0x40],
    )
