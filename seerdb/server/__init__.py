# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server side of the TNS/TTC protocol — the "Mirror".

seerdb is a *client*: it decodes what an Oracle server puts on the wire. This
subpackage is the inverse — it *answers* that protocol for real Oracle clients
(sqlplus, python-oracledb, SeerODBC), so a non-Oracle backend (e.g. SQLite or
PostgreSQL) can sit behind it.

**Experimental and unstable.** Unlike the client (DB-API 2.0) surface, which
follows semantic versioning, the Mirror's API may change or break in any release.
Treat :func:`~seerdb.server.service.serve` / :class:`~seerdb.server.service.Server`
and everything under ``seerdb.server`` accordingly.

A live client logs in and runs SQL end-to-end against a pluggable
:class:`~seerdb.server.backend.Backend`: the handshake, O5LOGON auth (both the
thin and the sqlplus/OCI dialects), describe, rows, bind variables, DML / DDL,
transactions, batched fetch, and LOBs. ``python -m seerdb.server`` still runs the
observation listener that decodes and logs what a client puts on the wire.
"""

from __future__ import annotations

from seerdb.common.tns import (
    ColumnMeta,
    ExecRequest,
    FetchRequest,
    encode_describe,
    encode_error,
    encode_fetch_response,
    encode_more_rows,
    encode_query_response,
    encode_rows,
    encode_status,
    parse_exec,
    parse_fetch,
)
from seerdb.server.backend import (
    Backend,
    BackendError,
    BindVar,
    Capability,
    Credentials,
    CursorResult,
    Result,
    UnsupportedFeature,
    credential_lookup,
)
from seerdb.server.framing import PacketStream
from seerdb.server.handshake import (
    ConnectRequest,
    encode_accept,
    encode_dty_reply,
    encode_pro_reply,
    parse_connect,
)
from seerdb.server.listener import Listener
from seerdb.server.service import BackendFactory, Server, serve
from seerdb.server.session import handle_login, serve_session

__all__ = [
    'Backend',
    'BackendError',
    'BackendFactory',
    'BindVar',
    'Capability',
    'ColumnMeta',
    'ConnectRequest',
    'Credentials',
    'CursorResult',
    'ExecRequest',
    'FetchRequest',
    'Listener',
    'PacketStream',
    'Result',
    'Server',
    'UnsupportedFeature',
    'credential_lookup',
    'encode_accept',
    'encode_describe',
    'encode_error',
    'encode_dty_reply',
    'encode_fetch_response',
    'encode_more_rows',
    'encode_pro_reply',
    'encode_query_response',
    'encode_rows',
    'encode_status',
    'handle_login',
    'parse_connect',
    'parse_exec',
    'parse_fetch',
    'serve',
    'serve_session',
]
