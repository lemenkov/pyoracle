# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""What the Mirror answers when a client asks which server it is.

The login result carries the server's release (``AUTH_VERSION_NO``, the value a
client turns into ``connection.version``) and sqlplus prints a banner after
"Connected to:". Those were pinned to the captured XE 11.2 server, so a Mirror
advertising a 12c field version still introduced itself as 11.2.0.2.0. They now
follow the advertised field version instead.

**The packed release format**: ``major<<24 | minor<<20 | update<<12 | patch<<8 |
port``. Verified by decoding what three live servers send — XE 11.2 ->
11.2.0.2.0, XE 21c -> 21.0.48.0.0, 23ai -> 23.1.162.0.0.

``AUTH_VERSION_SQL`` is a small counter that moves with the release; the captured
anchors are 11.2 -> 22, 21c -> 25, 23ai -> 26. **12.2's value is not captured**
(there is no 12.2 testbed here), so 23 is taken from the gap between those
anchors. Nothing reads it back — a client decodes only ``AUTH_VERSION_NO`` into
its version property — so it is descriptive, not load-bearing.
"""

from __future__ import annotations

from dataclasses import dataclass

from seerdb.common.tns_consts import FIELD_VERSION_12_2


@dataclass(frozen=True)
class ServerIdentity:
    """The release a Mirror session claims to be."""

    version_no: int
    """Packed release, sent as ``AUTH_VERSION_NO`` and decoded by the client."""

    version_sql: bytes
    """``AUTH_VERSION_SQL`` — descriptive; nothing reads it back."""

    version_string: bytes
    """``AUTH_VERSION_STRING`` — the build suffix, e.g. ``- 64bit Production``."""

    banner: bytes
    """What sqlplus prints after "Connected to:"."""


IDENTITY_11_2 = ServerIdentity(
    version_no=0x0B200200,  # 11.2.0.2.0
    version_sql=b'22',
    version_string=b'- 64bit Production',
    banner=(
        b'Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production'
    ),
)

IDENTITY_12_2 = ServerIdentity(
    version_no=0x0C200100,  # 12.2.0.1.0
    version_sql=b'23',
    version_string=b'- 64bit Production',
    banner=(
        b'Oracle Database 12c Enterprise Edition Release 12.2.0.1.0 - 64bit Production'
    ),
)


def server_identity(field_version: int) -> ServerIdentity:
    """The identity a Mirror advertising ``field_version`` introduces itself with.

    Two tiers for now. A field version below 12.2 keeps the captured 11.2
    identity; 12.2 and anything above it reports 12.2, because that is the
    highest release the Mirror has an identity for — a session advertising a
    21c or 23ai field version would rather say 12.2 than claim to be 11.2, which
    is what it did before. Adding those tiers is a later step; the captured
    anchors for them are in this module's docstring.
    """
    if field_version >= FIELD_VERSION_12_2:
        return IDENTITY_12_2
    return IDENTITY_11_2
