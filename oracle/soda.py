# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""SODA (Simple Oracle Document Access), #163.

A thin-mode SODA layer built on the database's ``DBMS_SODA`` PL/SQL package —
python-oracledb only offers SODA in thick mode, so there is no native thin wire
to speak; the documented PL/SQL API is the thin path and pyoracle already drives
PL/SQL blocks + binds. The public surface mirrors oracledb's SODA API (camelCase,
following the cross-language SODA spec): ``connection.getSodaDatabase()`` returns
a `SodaDatabase`, whose collections are `SodaCollection` objects holding
`SodaDocument` objects.

SODA needs an Oracle 18c+ server (``DBMS_SODA``); `getSodaDatabase` raises
``NotSupportedError`` below that. This module covers collection management (#199)
and the document model — insert + read by key (#200). QBE find, update and
delete land in the follow-up sub-tickets of #163.

A document's content is bound into ``DBMS_SODA`` as bytes; a value over the
32767-byte PL/SQL limit rides pyoracle's transparent temp-LOB bind (#91), so
*inserting* large documents works. *Reading* content back comes through a single
``DBMS_LOB.SUBSTR`` and is therefore capped at 32767 bytes — a document whose
stored content exceeds that raises rather than silently truncating; chunked
large-content reads are a follow-up.
"""

import json

from oracle.datatypes import DB_TYPE_NUMBER, DB_TYPE_RAW, DB_TYPE_VARCHAR
from oracle.exceptions import NotSupportedError

# DBMS_SODA / SODA shipped in Oracle 18c (server major version 18).
_SODA_MIN_MAJOR = 18
# A single DBMS_LOB.SUBSTR / cast_to_raw read tops out at the 32767-byte PL/SQL
# VARCHAR2/RAW limit.
_MAX_INLINE = 32767
_DEFAULT_MEDIA_TYPE = "application/json"

# --- PL/SQL templates (shared by the sync and async classes) ---------------
_CREATE = ("DECLARE c SODA_COLLECTION_T; BEGIN "
           "c := DBMS_SODA.create_collection(:name); END;")
_CREATE_MD = ("DECLARE c SODA_COLLECTION_T; BEGIN "
              "c := DBMS_SODA.create_collection(:name, :metadata); END;")
_OPEN = ("DECLARE c SODA_COLLECTION_T; BEGIN "
         "c := DBMS_SODA.open_collection(:name); "
         ":missing := CASE WHEN c IS NULL THEN 1 ELSE 0 END; END;")
_DROP = "BEGIN :status := DBMS_SODA.drop_collection(:name); END;"
_METADATA = ("DECLARE c SODA_COLLECTION_T; BEGIN "
             "c := DBMS_SODA.open_collection(:name); "
             ":md := c.get_metadata(); END;")
_TRUNCATE = ("DECLARE c SODA_COLLECTION_T; n NUMBER; BEGIN "
             "c := DBMS_SODA.open_collection(:name); n := c.truncate(); END;")
_INSERT_ONE = (
    "DECLARE c SODA_COLLECTION_T; d SODA_DOCUMENT_T; n NUMBER; BEGIN "
    "c := DBMS_SODA.open_collection(:name); "
    "d := SODA_DOCUMENT_T(key => :key, b_content => :content, "
    "media_type => :mt); n := c.insert_one(d); END;")
_INSERT_ONE_AND_GET = (
    "DECLARE c SODA_COLLECTION_T; d SODA_DOCUMENT_T; r SODA_DOCUMENT_T; BEGIN "
    "c := DBMS_SODA.open_collection(:name); "
    "d := SODA_DOCUMENT_T(key => :key, b_content => :content, "
    "media_type => :mt); r := c.insert_one_and_get(d); "
    ":rkey := r.get_key(); :rver := r.get_version(); :rmt := r.get_media_type();"
    " :rcreated := r.get_created_on; :rmodified := r.get_last_modified; END;")
_GET_ONE = (
    "DECLARE c SODA_COLLECTION_T; d SODA_DOCUMENT_T; b BLOB; BEGIN "
    "c := DBMS_SODA.open_collection(:name); "
    "d := c.find().key(:key).get_one(); "
    "IF d IS NULL THEN :missing := 1; ELSE :missing := 0; "
    "b := d.get_blob(); :clen := DBMS_LOB.GETLENGTH(b); "
    ":content := DBMS_LOB.SUBSTR(b, 32767, 1); "
    ":rkey := d.get_key(); :rver := d.get_version(); :rmt := d.get_media_type();"
    " :rcreated := d.get_created_on; :rmodified := d.get_last_modified; "
    "END IF; END;")


def _names_query(start_name, limit):
    # SELECT for getCollectionNames: collections live in USER_SODA_COLLECTIONS,
    # keyed by URI_NAME. Optional start (>=, case-sensitive, oracledb semantics)
    # and a row cap.
    sql = "SELECT uri_name FROM user_soda_collections"
    binds = []
    if start_name is not None:
        # NB: :start is an ORA-01745 reserved-word bind name; use :start_name.
        sql += " WHERE uri_name >= :start_name"
        binds.append(start_name)
    sql += " ORDER BY uri_name"
    if limit and int(limit) > 0:
        sql += f" FETCH FIRST {int(limit)} ROWS ONLY"
    return sql, binds


def _check_soda_supported(connection) -> None:
    if (connection.server_version >> 24) < _SODA_MIN_MAJOR:
        raise NotSupportedError(
            "SODA requires an Oracle 18c+ server (DBMS_SODA)")


def _norm_metadata(metadata):
    # createCollection accepts a dict (serialised to a JSON string) or a ready
    # JSON string; DBMS_SODA wants the metadata as text.
    if metadata is None:
        return None
    if isinstance(metadata, (dict, list)):
        return json.dumps(metadata)
    return metadata


def _encode_content(content) -> bytes:
    # A document's content as UTF-8 bytes for binding: dict/list -> JSON text,
    # str -> encoded, bytes -> as-is.
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    if isinstance(content, str):
        return content.encode("utf-8")
    return json.dumps(content).encode("utf-8")


class SodaDocument:
    """A SODA document (#200). Either built client-side by
    `SodaDatabase.createDocument` (content set; no key/version/timestamps until
    inserted) or returned by an insert / read (server metadata populated).

    `content` is held as raw bytes; `getContent()` parses it as JSON for a JSON
    media type, `getContentAsString()` / `getContentAsBytes()` return it as
    text / bytes."""

    def __init__(self, content=None, key=None, version=None,
                 mediaType=_DEFAULT_MEDIA_TYPE, createdOn=None,
                 lastModified=None):
        self._content = content            # bytes or None
        self.key = key
        self.version = version
        self.mediaType = mediaType
        self.createdOn = createdOn
        self.lastModified = lastModified

    def __repr__(self) -> str:
        return f"SodaDocument(key={self.key!r}, mediaType={self.mediaType!r})"

    def getContentAsBytes(self) -> bytes | None:
        return self._content

    def getContentAsString(self, encoding: str = "utf-8") -> str | None:
        if self._content is None:
            return None
        return self._content.decode(encoding)

    def getContent(self):
        """The parsed content: a Python value for a JSON document, otherwise the
        decoded string."""
        if self._content is None:
            return None
        if self.mediaType == _DEFAULT_MEDIA_TYPE:
            return json.loads(self._content)
        return self.getContentAsString()


def _doc_to_bind(doc) -> tuple:
    # A SodaDocument or a bare content value -> (key, content_bytes, mediaType)
    # for the insert templates.
    if isinstance(doc, SodaDocument):
        return doc.key, _encode_content(doc._content), doc.mediaType
    return None, _encode_content(doc), _DEFAULT_MEDIA_TYPE


def _content_or_raise(content, length):
    # Guard against a silently truncated read: the single SUBSTR maxes at
    # _MAX_INLINE bytes (#200 limitation).
    if length is not None and int(length) > _MAX_INLINE:
        raise NotSupportedError(
            f"SODA document content is {int(length)} bytes; reading content "
            f"over {_MAX_INLINE} bytes is not yet supported")
    if content is None:
        return None
    return bytes(content)


# --------------------------------------------------------------------------
# Sync
# --------------------------------------------------------------------------

class SodaOperation:
    """A SODA read operation builder (#200): `collection.find()` returns one;
    chain a terminal like `.key(k).getOne()`. QBE filters / counts / multi-doc
    reads extend this in the #163 follow-ups."""

    def __init__(self, collection: "SodaCollection"):
        self._collection = collection
        self._connection = collection._connection
        self._key = None

    def key(self, value: str) -> "SodaOperation":
        self._key = value
        return self

    def getOne(self) -> "SodaDocument | None":
        """The single document matched by `.key(...)`, or None if there is
        none."""
        cur = self._connection.cursor()
        b = _new_doc_out_binds(cur)
        b.update({"name": self._collection.name, "key": self._key})
        cur.execute(_GET_ONE, b)
        if b["missing"].getvalue():
            return None
        return _doc_from_binds(b, with_content=True)


class SodaCollection:
    """A SODA collection (#163). Obtain one from `SodaDatabase.createCollection`
    / `openCollection`. Covers name / metadata / drop / truncate (#199) and
    document insert + read by key (#200)."""

    def __init__(self, database: "SodaDatabase", name: str, metadata=None):
        self._database = database
        self._connection = database._connection
        self.name = name
        self._metadata = metadata

    def __repr__(self) -> str:
        return f"SodaCollection({self.name!r})"

    @property
    def metadata(self) -> dict:
        """The collection's metadata as a dict (lazily fetched)."""
        if self._metadata is None:
            cur = self._connection.cursor()
            md = cur.var(DB_TYPE_VARCHAR)
            cur.execute(_METADATA, {"name": self.name, "md": md})
            self._metadata = json.loads(md.getvalue())
        return self._metadata

    def drop(self) -> bool:
        """Drop the collection. Returns True if it was dropped, False if it did
        not exist."""
        cur = self._connection.cursor()
        status = cur.var(DB_TYPE_NUMBER)
        cur.execute(_DROP, {"status": status, "name": self.name})
        return bool(status.getvalue())

    def truncate(self) -> None:
        """Remove every document from the collection (keeping the collection)."""
        cur = self._connection.cursor()
        cur.execute(_TRUNCATE, {"name": self.name})

    def insertOne(self, doc) -> None:
        """Insert a document (a `SodaDocument` or a bare content value)."""
        key, content, mt = _doc_to_bind(doc)
        cur = self._connection.cursor()
        cur.execute(_INSERT_ONE,
                    {"name": self.name, "key": key, "content": content,
                     "mt": mt})

    def insertOneAndGet(self, doc) -> SodaDocument:
        """Insert a document and return a `SodaDocument` carrying the resulting
        key / version / metadata (no content, matching oracledb)."""
        key, content, mt = _doc_to_bind(doc)
        cur = self._connection.cursor()
        b = _new_doc_out_binds(cur, content=False)
        b.update({"name": self.name, "key": key, "content": content, "mt": mt})
        cur.execute(_INSERT_ONE_AND_GET, b)
        return _doc_from_binds(b, with_content=False)

    def find(self) -> SodaOperation:
        """Begin a read operation (chain `.key(k).getOne()`)."""
        return SodaOperation(self)


class SodaDatabase:
    """The SODA entry point for a connection (oracledb's SodaDatabase, #163).
    Returned by `connection.getSodaDatabase()`."""

    def __init__(self, connection):
        self._connection = connection

    def createCollection(self, name: str, metadata=None) -> SodaCollection:
        """Create (or open, if it already exists with matching metadata) a
        collection. `metadata` is an optional dict / JSON string."""
        cur = self._connection.cursor()
        md = _norm_metadata(metadata)
        if md is None:
            cur.execute(_CREATE, {"name": name})
        else:
            cur.execute(_CREATE_MD, {"name": name, "metadata": md})
        return SodaCollection(self, name)

    def openCollection(self, name: str) -> SodaCollection | None:
        """Open an existing collection, or None if there is no such collection."""
        cur = self._connection.cursor()
        missing = cur.var(DB_TYPE_NUMBER)
        cur.execute(_OPEN, {"name": name, "missing": missing})
        if missing.getvalue():
            return None
        return SodaCollection(self, name)

    def getCollectionNames(self, startName: str | None = None,
                           limit: int = 0) -> list[str]:
        """The collection names, sorted; optionally starting at `startName`
        (inclusive) and capped at `limit`."""
        cur = self._connection.cursor()
        sql, binds = _names_query(startName, limit)
        cur.execute(sql, binds)
        return [Row[0] for Row in cur.fetchall()]

    def createDocument(self, content, key: str | None = None,
                       mediaType: str = _DEFAULT_MEDIA_TYPE) -> SodaDocument:
        """Build a client-side `SodaDocument` from `content` (a dict / str /
        bytes), ready to insert."""
        return SodaDocument(content=_encode_content(content), key=key,
                            mediaType=mediaType)


# --- helpers shared by the document-returning operations -------------------

def _new_doc_out_binds(cur, content: bool = True) -> dict:
    # The OUT binds the insert/read templates fill: key, version, media type,
    # created/last-modified timestamps, and (for a read) the content + length.
    binds = {"rkey": cur.var(DB_TYPE_VARCHAR), "rver": cur.var(DB_TYPE_VARCHAR),
             "rmt": cur.var(DB_TYPE_VARCHAR),
             "rcreated": cur.var(DB_TYPE_VARCHAR),
             "rmodified": cur.var(DB_TYPE_VARCHAR)}
    if content:
        binds["content"] = cur.var(DB_TYPE_RAW)
        binds["clen"] = cur.var(DB_TYPE_NUMBER)
        binds["missing"] = cur.var(DB_TYPE_NUMBER)
    return binds


def _doc_from_binds(b: dict, with_content: bool) -> SodaDocument:
    content = None
    if with_content:
        content = _content_or_raise(b["content"].getvalue(),
                                    b["clen"].getvalue())
    return SodaDocument(
        content=content, key=b["rkey"].getvalue(), version=b["rver"].getvalue(),
        mediaType=b["rmt"].getvalue() or _DEFAULT_MEDIA_TYPE,
        createdOn=b["rcreated"].getvalue(),
        lastModified=b["rmodified"].getvalue())


# --------------------------------------------------------------------------
# Async (mirrors the sync surface; same PL/SQL, awaited)
# --------------------------------------------------------------------------

class AsyncSodaOperation:
    """Async counterpart to `SodaOperation` (#200)."""

    def __init__(self, collection: "AsyncSodaCollection"):
        self._collection = collection
        self._connection = collection._connection
        self._key = None

    def key(self, value: str) -> "AsyncSodaOperation":
        self._key = value
        return self

    async def getOne(self) -> "SodaDocument | None":
        cur = self._connection.cursor()
        b = _new_doc_out_binds(cur)
        b.update({"name": self._collection.name, "key": self._key})
        await cur.execute(_GET_ONE, b)
        if b["missing"].getvalue():
            return None
        return _doc_from_binds(b, with_content=True)


class AsyncSodaCollection:
    """Async counterpart to `SodaCollection` (#163 / #200)."""

    def __init__(self, database: "AsyncSodaDatabase", name: str, metadata=None):
        self._database = database
        self._connection = database._connection
        self.name = name
        self._metadata = metadata

    def __repr__(self) -> str:
        return f"AsyncSodaCollection({self.name!r})"

    async def get_metadata(self) -> dict:
        """The collection's metadata as a dict. (A coroutine, so it can't be a
        property like the sync class.)"""
        if self._metadata is None:
            cur = self._connection.cursor()
            md = cur.var(DB_TYPE_VARCHAR)
            await cur.execute(_METADATA, {"name": self.name, "md": md})
            self._metadata = json.loads(md.getvalue())
        return self._metadata

    async def drop(self) -> bool:
        cur = self._connection.cursor()
        status = cur.var(DB_TYPE_NUMBER)
        await cur.execute(_DROP, {"status": status, "name": self.name})
        return bool(status.getvalue())

    async def truncate(self) -> None:
        cur = self._connection.cursor()
        await cur.execute(_TRUNCATE, {"name": self.name})

    async def insertOne(self, doc) -> None:
        key, content, mt = _doc_to_bind(doc)
        cur = self._connection.cursor()
        await cur.execute(_INSERT_ONE,
                          {"name": self.name, "key": key, "content": content,
                           "mt": mt})

    async def insertOneAndGet(self, doc) -> SodaDocument:
        key, content, mt = _doc_to_bind(doc)
        cur = self._connection.cursor()
        b = _new_doc_out_binds(cur, content=False)
        b.update({"name": self.name, "key": key, "content": content, "mt": mt})
        await cur.execute(_INSERT_ONE_AND_GET, b)
        return _doc_from_binds(b, with_content=False)

    def find(self) -> AsyncSodaOperation:
        return AsyncSodaOperation(self)


class AsyncSodaDatabase:
    """Async counterpart to `SodaDatabase` (#163)."""

    def __init__(self, connection):
        self._connection = connection

    async def createCollection(self, name: str,
                               metadata=None) -> AsyncSodaCollection:
        cur = self._connection.cursor()
        md = _norm_metadata(metadata)
        if md is None:
            await cur.execute(_CREATE, {"name": name})
        else:
            await cur.execute(_CREATE_MD, {"name": name, "metadata": md})
        return AsyncSodaCollection(self, name)

    async def openCollection(self, name: str) -> AsyncSodaCollection | None:
        cur = self._connection.cursor()
        missing = cur.var(DB_TYPE_NUMBER)
        await cur.execute(_OPEN, {"name": name, "missing": missing})
        if missing.getvalue():
            return None
        return AsyncSodaCollection(self, name)

    async def getCollectionNames(self, startName: str | None = None,
                                 limit: int = 0) -> list[str]:
        cur = self._connection.cursor()
        sql, binds = _names_query(startName, limit)
        await cur.execute(sql, binds)
        return [Row[0] for Row in await cur.fetchall()]

    def createDocument(self, content, key: str | None = None,
                       mediaType: str = _DEFAULT_MEDIA_TYPE) -> SodaDocument:
        return SodaDocument(content=_encode_content(content), key=key,
                            mediaType=mediaType)
