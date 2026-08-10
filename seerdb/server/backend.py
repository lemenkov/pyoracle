# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The Backend contract — how the Mirror reaches an underlying database.

The Mirror speaks Oracle's wire protocol; a :class:`Backend` executes the SQL
behind it. One backend instance serves one client session. Concrete backends
(SQLite, PostgreSQL, …) live outside ``seerdb`` core, owning their driver
dependency; only this contract lives here.

Backends are **not** a least-common-denominator. Each declares its
:class:`Capability` set, and anything it cannot do is reported as a clean
``ORA-`` error (:class:`BackendError`) on a still-healthy connection — never a
desync. So SQLite legitimately refuses more than PostgreSQL, and that is
correct, not a failure.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Protocol, runtime_checkable

from seerdb.server.query import ColumnMeta

# A username → secret map, the usual shape a backend authenticates against.
Credentials = Mapping[str, str]


def credential_lookup(credentials: Credentials, username: str) -> str | None:
    """Case-insensitive credential match — the usual body of a backend's
    :meth:`Backend.authenticate`. Oracle folds unquoted identifiers to
    upper-case, so ``PYO``, ``pyo`` and ``Pyo`` all match one entry. Returns the
    stored secret, or ``None`` when the user is unknown."""
    for name, secret in credentials.items():
        if name.upper() == username.upper():
            return secret
    return None


class Capability(Enum):
    """A feature a backend may support. Absent → the Mirror answers a request
    that needs it with an ORA error instead of pretending."""

    TRANSACTIONS = auto()
    # Grow this as the Mirror's protocol surface does: LOBS, SEQUENCES,
    # PLSQL, SCROLLABLE_CURSORS, …


@dataclass(frozen=True)
class Result:
    """A backend execute outcome: query columns + rows, or a DML row count."""

    columns: list[ColumnMeta] = field(default_factory=list)
    rows: list[tuple] = field(default_factory=list)
    rowcount: int = 0


class BackendError(Exception):
    """A backend failure surfaced to the client as an ORA error.

    The Mirror turns it into an OER (``ORA-<ora_code>: <message>``) and keeps
    the connection usable — the client sees a normal, recoverable error rather
    than a dropped connection. Defaults to ``ORA-00900`` (invalid SQL statement).
    """

    def __init__(self, message: str, *, ora_code: int = 900) -> None:
        super().__init__(message)
        self.ora_code = ora_code
        self.ora_message = f'ORA-{ora_code:05d}: {message}'


class UnsupportedFeature(BackendError):
    """The backend cannot fulfil a request — reported as ``ORA-03001``
    (unimplemented feature). A clean "no", not a crash."""

    def __init__(self, message: str) -> None:
        super().__init__(message, ora_code=3001)


@runtime_checkable
class Backend(Protocol):
    """What the Mirror needs from an underlying database (one per session)."""

    capabilities: frozenset[Capability]

    def authenticate(self, username: str) -> str | None:
        """Return the O5LOGON secret (plaintext password) for ``username``, or
        ``None`` to reject the login.

        The Mirror stores no credentials of its own — auth lives with the
        backend, mirroring how Oracle keeps it. O5LOGON is *mutual*: the Mirror
        must know the secret to prove itself to the client (it never sees the
        client's password), so this returns the secret rather than validating a
        supplied one. :func:`credential_lookup` covers the common map-backed case.
        """
        ...

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        """Run ``sql`` and return its columns + rows (or a DML row count).

        Raise :class:`BackendError` (or :class:`UnsupportedFeature`) for
        anything the backend cannot do — the Mirror maps it to an ORA error.
        """
        ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...
