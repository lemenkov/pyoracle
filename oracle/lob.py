# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Represents an Oracle LOB (CLOB / NCLOB / BLOB / BFILE) value returned by a
# SELECT. The raw locator the server emits in RXD is exactly what it expects
# back in a TTI_LOBOPS round-trip (verified by diffing against sqlplus's
# LOBOPS request locator), so we keep it verbatim and hand it back as the
# source pointer when reading.
#
# The locator's fixed metadata overhead is 102 bytes on Oracle 11g; for
# LOBs whose content fits inside the locator's inline budget the content
# is woven into the same block and we could pluck it out without a round-
# trip. We don't bother — going through TTI_LOBOPS works for inline and
# out-of-line content uniformly and is simpler.

from oracle.tns_consts import (
    TNS_TYPE_BFILE, TNS_TYPE_BLOB, TNS_TYPE_CLOB,
)

_LOCATOR_OVERHEAD = 102


class LOB:
    __slots__ = ("data_type", "raw", "_connection")

    def __init__(self, data_type: int, raw: bytes, connection=None):
        # `data_type` is the column's TNS data type code (112 CLOB, 113 BLOB,
        # 114 BFILE; NCLOB shares 112 + a national charset form). `raw` is
        # the locator block from RXD — same bytes go back to the server for
        # TTI_LOBOPS. `connection` is the OracleConnect used to round-trip
        # in `read()`; `Cursor.execute` injects it after fetching rows.
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
        # Size of the inline content section, in bytes. Used as a fast path
        # for EMPTY_CLOB() / EMPTY_BLOB() (returns 0) without round-tripping.
        if len(self.raw) <= _LOCATOR_OVERHEAD:
            return 0
        return len(self.raw) - _LOCATOR_OVERHEAD

    def read(self) -> str | bytes:
        # Round-trip TTI_LOBOPS READ to materialise the actual content.
        # CLOB / NCLOB decode UTF-16BE to `str`; BLOB / BFILE surface as
        # raw `bytes`. Empty LOBs short-circuit without a round-trip.
        if self.content_size == 0:
            return "" if self.is_character else b""
        if self._connection is None:
            from oracle.exceptions import InterfaceError
            raise InterfaceError("LOB has no connection to read from")
        return self._connection.lob_read(self.raw, self.data_type)

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
