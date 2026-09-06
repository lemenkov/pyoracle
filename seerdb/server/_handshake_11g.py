# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The 11g server's fixed identity for the PRO / DTY handshake replies.

The Mirror answers the protocol (PRO) and data-type (DTY) negotiation with a
real XE 11.2 listener's replies (PROTOCOL.md §4.1). Rather than store the whole
DATA packets verbatim, the server's fixed identity is kept as named pieces —
the version banner, charset, the server capability vectors, and the
type-conversion table — and the builders below assemble the TTC payload (the
packet header is added by ``encode_packet``). Two dialects (§4.1):

- **TTI_PRO (0x01)** — python-oracledb / seerdb. The same capability block is the
  thin PRO reply *and* the sqlplus/deadbeef DTY reply (byte-identical, so one
  builder serves both). The thin DTY reply is the type-conversion table.
- **sqlplus `deadbeef`** — the PRO reply is an ANO null-negotiation response
  (built field-by-field from the ANO codec, §4.1.1); the extra third-round type
  reply is a DTY reply carrying the DB time zone and timezone-file version (§4.2),
  built field-by-field.

The values are the server's identity, captured once from a live XE 11.2 server;
``tests/test_handshake_generation.py`` pins the builders to those captures
byte-for-byte so the Mirror stays wire-identical to the real server.
"""

import struct

from seerdb.common import ano
from seerdb.common.tns import (
    _DB_TZ_FRAME_PAD,
    _PRO_CHARSET_ELEMENTS,
    _PRO_FDO,
    _SERVER_COMPILE_CAPS,
    _SERVER_DTY_TABLE,
    _SERVER_RUNTIME_CAPS,
    CCAP_FIELD_VERSION,
)
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    FIELD_VERSION_11_2,
    TTI_DTY,
    TTI_PRO,
)

# --- the deadbeef PRO reply: an ANO null-negotiation response (§4.1.1) ---
# sqlplus / thick OCI leads its login with an ANO negotiation whose container
# stamps version 0x00000000 (vs a thin client's 0x0B200200); the server answers
# by selecting the null algorithm for every service, so the session stays
# plaintext. This same reply doubles as the deadbeef PRO reply. The container
# version is 0, but each service still echoes the modern VERSION_11_2_0_2.
_DEADBEEF_CONTAINER_VERSION = 0x00000000  # sqlplus/OCI stamp (not VERSION_11_2_0_2)
_NULL_ALGO = 0  # null cipher / null checksum selected → plaintext

# --- the deadbeef third-round type reply: a DTY reply (§4.2) ---
# After DTY, sqlplus / thick OCI runs a third negotiation round the server answers
# with this 16-byte TTC payload (a 26-byte DATA packet). It is a data-type reply
# carrying the server's DB session time zone (UTC here) and its timezone-file
# version. Each of the h/m/s offset fields is biased by +60 (Oracle's TZ
# encoding), so a stored 60 means a zero offset.
_DTY_TZ_BIAS = 60  # Oracle biases each of hours/min/sec by +60
_DB_TZ_HMS = (0, 0, 0)  # DB session time zone = UTC (+00:00:00)
_TZFILE_VERSION = 14  # the 11.2 default timezone-file (DST rules) version


def build_caps_block_reply(field_version: int = FIELD_VERSION_11_2) -> bytes:
    """The TTI_PRO capability block as a TTC payload (no packet header): version
    banner, charset, the charset-element array, the fixed descriptor, and the
    server 11g capability vectors. Serves both the thin PRO reply and the
    sqlplus/deadbeef DTY reply (they are byte-identical).

    ``field_version`` is the field version the Mirror advertises — the byte at
    ``CCAP_FIELD_VERSION`` in the compile capabilities, which is what a thin
    client negotiates down to and gates its 12c+ / 23ai wire formats on. The
    rest of the block is the pinned 11.2 identity whatever the version."""
    compile_caps = bytearray(_SERVER_COMPILE_CAPS)
    compile_caps[CCAP_FIELD_VERSION] = field_version
    return (
        # TTI_PRO, the negotiated field version (6 = 11g), a zero, then the
        # NUL-terminated version banner.
        bytes([TTI_PRO, FIELD_VERSION_11_2, 0])
        + b'x86_64/Linux 2.4.xx'
        + b'\x00'
        + struct.pack('<H', AL32UTF8_CHARSET)  # charset id, LE
        + bytes([1])  # flags
        + struct.pack('<H', len(_PRO_CHARSET_ELEMENTS) // 5)
        + _PRO_CHARSET_ELEMENTS
        + struct.pack('>H', len(_PRO_FDO))
        + _PRO_FDO
        + bytes([len(compile_caps)])
        + bytes(compile_caps)
        + bytes([len(_SERVER_RUNTIME_CAPS)])
        + _SERVER_RUNTIME_CAPS
    )


def build_dty_type_reply() -> bytes:
    """The thin DTY reply as a TTC payload: TTI_DTY then the server's
    type-conversion table."""
    return bytes([TTI_DTY]) + _SERVER_DTY_TABLE


def build_pro_sqlplus_reply() -> bytes:
    """The sqlplus/deadbeef PRO reply payload — an ANO null-negotiation response
    (§4.1.1), built field-by-field from the ANO codec (#564).

    Four services (supervisor, auth, encryption, data-integrity); encryption and
    data-integrity both select the null algorithm, so no cipher/MAC is activated
    and the session stays plaintext. The container stamps version 0x00000000 (the
    sqlplus/OCI form); each service echoes VERSION_11_2_0_2. This is the same reply the
    thin ANO path replays as its null-negotiation response — it *is* that response.
    """
    services = [
        ano.encode_service(
            ano.SERVICE_SUPERVISOR,
            [
                ano.sp_version(),  # VERSION_11_2_0_2
                ano.sp_status(ano.SUPERVISOR_STATUS_OK),  # 31
                ano.sp_ub2_array([ano.SERVICE_SUPERVISOR, ano.SERVICE_AUTH]),  # [4,1]
            ],
        ),
        ano.encode_service(
            ano.SERVICE_AUTH,
            [ano.sp_version(), ano.sp_status(ano.AUTH_STATUS_DEADBEEF)],
        ),
        ano.encode_service(
            ano.SERVICE_ENCRYPTION,
            [ano.sp_version(), ano.sp_ub1(_NULL_ALGO)],
        ),
        ano.encode_service(
            ano.SERVICE_DATA_INTEGRITY,
            [ano.sp_version(), ano.sp_ub1(_NULL_ALGO)],
        ),
    ]
    return ano.encode_ano(services, ContainerVersion=_DEADBEEF_CONTAINER_VERSION)


def build_type_reply_sqlplus() -> bytes:
    """The deadbeef dialect's third-round type reply payload (#265, #565).

    A DTY (data-type negotiation) reply carrying the server's DB session time zone
    and its timezone-file version (§4.2): the ``TTI_DTY`` message code, an 11-byte
    time-zone block (its h/m/s offset fields at bytes 4..6, each biased by +60),
    then the timezone-file version as a big-endian ub4.
    """
    (Hours, Minutes, Seconds) = _DB_TZ_HMS
    tz_block = (
        _DB_TZ_FRAME_PAD
        + bytes([Hours + _DTY_TZ_BIAS, Minutes + _DTY_TZ_BIAS, Seconds + _DTY_TZ_BIAS])
        + _DB_TZ_FRAME_PAD
    )
    return bytes([TTI_DTY]) + tz_block + struct.pack('>I', _TZFILE_VERSION)
