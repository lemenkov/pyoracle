# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server side of the TNS/TTC protocol — the "Mirror".

seerdb is a *client*: it decodes what an Oracle server puts on the wire. This
subpackage is the inverse — it *answers* that protocol for real Oracle clients
(sqlplus, python-oracledb, SeerODBC), so a non-Oracle backend (e.g. PostgreSQL)
can sit behind it. See the Tier-A design proposal.

Bring-up is staged. Today this provides:

* :class:`~seerdb.server.framing.PacketStream` — the read/write mirror of the
  client's ``recv()`` / ``send()``, so the server and client share one framing
  implementation.
* an observation listener (:func:`~seerdb.server.listener.serve`) that decodes
  and logs what a client puts on the wire — the capture tool that drives the
  rest of the bring-up.

Not yet: the ACCEPT / PRO / DTY handshake replies, auth, describe, or rows —
those land in later increments, each authored against a real-Oracle capture.
"""

from __future__ import annotations

from seerdb.server.backend import (
    Backend,
    BackendError,
    Capability,
    Result,
    UnsupportedFeature,
)
from seerdb.server.framing import PacketStream
from seerdb.server.handshake import (
    ConnectRequest,
    encode_accept,
    encode_dty_reply,
    encode_pro_reply,
    parse_connect,
)
from seerdb.server.listener import Listener, serve
from seerdb.server.query import (
    ColumnMeta,
    ExecRequest,
    encode_describe,
    encode_error,
    encode_query_response,
    encode_rows,
    parse_exec,
)
from seerdb.server.session import Credentials, handle_login, serve_session

__all__ = [
    'Backend',
    'BackendError',
    'Capability',
    'ColumnMeta',
    'ConnectRequest',
    'Credentials',
    'ExecRequest',
    'Listener',
    'PacketStream',
    'Result',
    'UnsupportedFeature',
    'encode_accept',
    'encode_describe',
    'encode_error',
    'encode_dty_reply',
    'encode_pro_reply',
    'encode_query_response',
    'encode_rows',
    'handle_login',
    'parse_connect',
    'parse_exec',
    'serve',
    'serve_session',
]
