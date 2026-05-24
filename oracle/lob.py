# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Represents an Oracle LOB (CLOB / NCLOB / BLOB / BFILE) value returned by a
# SELECT. The actual content of a LOB does NOT travel inline with the row
# data the way a VARCHAR2 does; instead the server sends a locator block
# (~40 bytes), optional size/chunk-size metadata, and — for small LOBs —
# the content inline as a secondary section inside the locator block.
#
# Today this class holds the raw locator+content bytes as-is. Future work:
#
#   1. Parse the inline content section so `lob.read()` returns the actual
#      str / bytes for small LOBs that came inline (no extra round trip).
#   2. Implement TTI_LOBOPS READ to fetch out-of-line content for large
#      LOBs (see docs/PROTOCOL.md §14).
#
# Until those land, callers that bind a LOB column will see a `LOB` object
# in their row rather than the value itself.

from oracle.tns_consts import (
    TNS_TYPE_BFILE, TNS_TYPE_BLOB, TNS_TYPE_CLOB,
)


class LOB:
    __slots__ = ("data_type", "raw")

    def __init__(self, data_type: int, raw: bytes):
        # data_type is the column's TNS data type code (112 CLOB, 113 BLOB,
        # 114 BFILE, plus the NCLOB variant which shares 112 + a national
        # charset form). raw is the entire locator + inline-content block as
        # received from the server.
        self.data_type = data_type
        self.raw = bytes(raw)

    @property
    def is_binary(self) -> bool:
        return self.data_type in (TNS_TYPE_BLOB, TNS_TYPE_BFILE)

    @property
    def is_character(self) -> bool:
        return self.data_type == TNS_TYPE_CLOB

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
