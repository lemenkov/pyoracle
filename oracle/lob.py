# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Represents an Oracle LOB (CLOB / NCLOB / BLOB / BFILE) value returned by a
# SELECT. The wire layout is:
#
#   ub4 num_bytes | num_bytes raw bytes | 1 trailing byte
#
# where the `num_bytes` block is the locator plus — for small LOBs — the
# content inline as a sub-section. The locator's fixed overhead is 102
# bytes on Oracle 11g, so content_size = num_bytes - 102 (in UTF-16BE
# bytes for CLOB, in raw bytes for BLOB).
#
# This module extracts the inline content section from the raw block; the
# server-side TTI_LOBOPS round-trip needed to read content that doesn't
# arrive inline (large LOBs) is on the roadmap — see docs/PROTOCOL.md §14
# and the README's "still in progress" list.

from oracle.tns_consts import (
    TNS_TYPE_BFILE, TNS_TYPE_BLOB, TNS_TYPE_CLOB,
)

# Empirically: on 11g the locator metadata around the inline content is
# always 103 bytes regardless of LOB content size.
_LOCATOR_OVERHEAD = 103


class LOB:
    __slots__ = ("data_type", "raw", "_connection")

    def __init__(self, data_type: int, raw: bytes, connection=None):
        # `data_type` is the column's TNS data type code (112 CLOB, 113 BLOB,
        # 114 BFILE; NCLOB shares 112 + a national charset form). `raw` is
        # the locator block the server sent in the RXD row data. The full
        # block includes inline content for small LOBs and would normally be
        # handed back to the server in a TTI_LOBOPS round-trip to materialise
        # out-of-line content; `connection` is reserved for that future
        # round-trip and is unused today.
        self.data_type = data_type
        self.raw = bytes(raw)
        self._connection = connection

    @property
    def is_binary(self) -> bool:
        return self.data_type in (TNS_TYPE_BLOB, TNS_TYPE_BFILE)

    @property
    def is_character(self) -> bool:
        return self.data_type == TNS_TYPE_CLOB

    @property
    def content_size(self) -> int:
        # The number of bytes of LOB content carried inline. Will be 0 for
        # EMPTY_CLOB() / EMPTY_BLOB() and for any LOB larger than the
        # locator's inline budget (which would require a TTI_LOBOPS
        # round-trip we don't make yet).
        if len(self.raw) <= _LOCATOR_OVERHEAD:
            return 0
        return len(self.raw) - _LOCATOR_OVERHEAD

    def read(self) -> str | bytes:
        # Return the actual LOB content. CLOBs decode UTF-16BE to `str`,
        # BLOBs surface as raw `bytes`. Empty LOBs return `""` / `b""`.
        # Large LOBs (whose content doesn't fit inline) currently come back
        # truncated to whatever the inline section carried; see the roadmap.
        Content = self._extract_inline()
        if self.is_character:
            return Content.decode('utf-16-be', errors='replace')
        return Content

    def _extract_inline(self) -> bytes:
        # The locator block ends with the inline content section. The 103
        # bytes preceding it are locator metadata (rowid-style references,
        # SCN, flags, charset info, content-length marker, padding, and an
        # `01` inline-content marker — see comments at the top of this
        # module for the rough layout). Just slice the last content_size
        # bytes — much simpler than trying to disambiguate length markers
        # from the marker-byte values embedded throughout the metadata.
        Want = self.content_size
        if Want == 0:
            return b""
        return bytes(self.raw[-Want:])

    def __repr__(self) -> str:
        Kind = "BLOB" if self.is_binary else ("CLOB" if self.is_character
                                              else f"LOB(type={self.data_type})")
        return f"<{Kind} {len(self.raw)}B>"

    def __len__(self) -> int:
        return len(self.raw)

    def __eq__(self, other) -> bool:
        if not isinstance(other, LOB):
            return NotImplemented
        return self.data_type == other.data_type and self.raw == other.raw

    def __hash__(self) -> int:
        return hash((self.data_type, self.raw))
