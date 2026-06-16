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
#
# BFILE locators have a different layout (43+ bytes carrying the directory
# name and filename in plain ASCII) and require an explicit FILEOPEN before
# READ. We read them natively over TTI_LOBOPS — FILE_OPEN -> READ ->
# FILE_CLOSE (#46, OracleConnect.bfile_read_native) — using the open-flagged
# locator the server returns from FILE_OPEN.

from oracle.tns_consts import (
    TNS_TYPE_BFILE, TNS_TYPE_BLOB, TNS_TYPE_CLOB, TNS_TYPE_JSON,
    TNS_TYPE_VECTOR,
)

# Column types whose value is delivered as a LOB locator but decoded from the
# fetched binary image into a Python object (not returned as a LOB).
_DECODED_IMAGE_TYPES = (TNS_TYPE_JSON, TNS_TYPE_VECTOR)

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
    def is_file(self) -> bool:
        return self.data_type == TNS_TYPE_BFILE

    @property
    def directory_name(self) -> str | None:
        # BFILE only: the DIRECTORY object name from the locator. Returns
        # None for non-BFILE LOBs and for malformed BFILE locators.
        parts = self._parse_bfile_locator()
        return parts[0] if parts else None

    @property
    def filename(self) -> str | None:
        # BFILE only: the filename portion of the locator.
        parts = self._parse_bfile_locator()
        return parts[1] if parts else None

    def _parse_bfile_locator(self) -> tuple[str, str] | None:
        # BFILE locator wire format (43+ bytes):
        #   ub2 BE  inner_length      offset 0..1
        #   16 bytes  flags / metadata
        #   ub1     dir_name_length   offset 17
        #   N bytes dir_name (ASCII)
        #   ub1 0x00
        #   ub1     filename_length
        #   M bytes filename (ASCII)
        # Anchored by parsing the two length-prefixed ASCII strings.
        if not self.is_file or len(self.raw) < 19:
            return None
        try:
            DirLen = self.raw[17]
            DirStart = 18
            DirEnd = DirStart + DirLen
            if DirEnd + 1 >= len(self.raw):
                return None
            Directory = self.raw[DirStart:DirEnd].decode("ascii")
            # next byte is a 0x00 separator, then the filename length
            FileLen = self.raw[DirEnd + 1]
            FileStart = DirEnd + 2
            FileEnd = FileStart + FileLen
            if FileEnd > len(self.raw):
                return None
            Filename = self.raw[FileStart:FileEnd].decode("ascii")
            return (Directory, Filename)
        except (UnicodeDecodeError, IndexError):
            return None

    @property
    def content_size(self) -> int:
        # Size of the inline content section for *regular* CLOB / BLOB
        # locators. Always 0 for BFILE and temporary-LOB locators (those
        # are shorter than the regular 102-byte overhead and don't carry
        # inline content — their content lives server-side and only
        # comes back via the TTI_LOBOPS round-trip).
        if len(self.raw) <= _LOCATOR_OVERHEAD:
            return 0
        return len(self.raw) - _LOCATOR_OVERHEAD

    def read(self) -> str | bytes:
        # Sync read. See `aread` below for the async equivalent.
        if self.data_type in _DECODED_IMAGE_TYPES:
            return self._decode_image(self._fetch_content())
        if len(self.raw) == _LOCATOR_OVERHEAD:
            return "" if self.is_character else b""
        if self._connection is None:
            from oracle.exceptions import InterfaceError
            raise InterfaceError("LOB has no connection to read from")
        if self.is_file:
            return self._connection.bfile_read_native(self.raw)
        return self._connection.lob_read(self.raw, self.data_type)

    def _fetch_content(self) -> bytes:
        # Fetch the raw locator content over TTI_LOBOPS (the OSON image for a
        # JSON column). Shared by the sync read() path.
        if self._connection is None:
            from oracle.exceptions import InterfaceError
            raise InterfaceError("LOB has no connection to read from")
        return self._connection.lob_read(self.raw, self.data_type)

    def _decode_image(self, content: bytes) -> object:
        # A native JSON (#30) or VECTOR (#55) column comes back as a binary
        # image over the LOB locator path; decode it to a Python value.
        # lob_read returns bytes for these non-CLOB types.
        if self.data_type == TNS_TYPE_JSON:
            from oracle.oson import decode_oson
            return decode_oson(content)
        from oracle.vector import decode_vector
        return decode_vector(content)

    async def aread(self) -> str | bytes:
        """Async equivalent of `read()`. Use this when the LOB came
        out of an `AsyncCursor`; the `_connection` attached to it is
        an `AsyncOracleConnect` whose `lob_read` / `bfile_read` are
        coroutines."""
        if self.data_type in _DECODED_IMAGE_TYPES:
            if self._connection is None:
                from oracle.exceptions import InterfaceError
                raise InterfaceError("LOB has no connection to read from")
            content = await self._connection.lob_read(self.raw, self.data_type)
            return self._decode_image(content)
        if len(self.raw) == _LOCATOR_OVERHEAD:
            return "" if self.is_character else b""
        if self._connection is None:
            from oracle.exceptions import InterfaceError
            raise InterfaceError("LOB has no connection to read from")
        if self.is_file:
            return await self._connection.bfile_read_native(self.raw)
        return await self._connection.lob_read(self.raw, self.data_type)

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
