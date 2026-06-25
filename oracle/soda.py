# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""SODA (Simple Oracle Document Access), #163.

A thin-mode SODA layer built on the database's ``DBMS_SODA`` PL/SQL package —
python-oracledb only offers SODA in thick mode, so there is no native thin wire
to speak; the documented PL/SQL API is the thin path and pyoracle already drives
PL/SQL blocks + binds. The public surface mirrors oracledb's SODA API (camelCase,
following the cross-language SODA spec): ``connection.getSodaDatabase()`` returns
a `SodaDatabase`, whose collections are `SodaCollection` objects.

SODA needs an Oracle 18c+ server (``DBMS_SODA``); `getSodaDatabase` raises
``NotSupportedError`` below that. This module is collection management (#199);
documents / QBE / updates land in the follow-up sub-tickets of #163.
"""

import json

from oracle.datatypes import DB_TYPE_NUMBER, DB_TYPE_VARCHAR
from oracle.exceptions import NotSupportedError

# DBMS_SODA / SODA shipped in Oracle 18c (server major version 18).
_SODA_MIN_MAJOR = 18

# PL/SQL templates shared by the sync and async collection/database classes.
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


# --------------------------------------------------------------------------
# Sync
# --------------------------------------------------------------------------

class SodaCollection:
    """A SODA collection (#163). Obtain one from `SodaDatabase.createCollection`
    / `openCollection`. This step covers name / metadata / drop / truncate;
    document operations arrive in the #163 follow-ups."""

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


# --------------------------------------------------------------------------
# Async (mirrors the sync surface; same PL/SQL, awaited)
# --------------------------------------------------------------------------

class AsyncSodaCollection:
    """Async counterpart to `SodaCollection` (#163)."""

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
