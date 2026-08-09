# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side query path — parse the client's OALL8 execute (11g).

The inverse of ``tns.encode_dictionary_exec`` for the 11g wire shape: an
``OALL8`` (TTI_ALL8) function message whose fixed header carries the SQL length
and option/bind counts, followed by the raw SQL text. The describe / row
encoders that answer it are layered on separately.
"""

from __future__ import annotations

from dataclasses import dataclass

from seerdb.exceptions import InterfaceError
from seerdb.tns import decode_ub4
from seerdb.tns_consts import TTI_ALL8, TTI_FUN

# The 11g tail between the fixed header and the SQL: a [0, 0, 1] marker and a
# 5-byte server-version slot (empty only when the client thinks it is talking to
# 10g; an 11g-pinned Mirror always gets the 5-byte form).
_MARKER_LEN = 3
_SERVER_VERSION_SLOT = 5


@dataclass(frozen=True)
class ExecRequest:
    """A parsed execute: the SQL text and the surrounding execute options."""

    sql: str
    cursor: int
    bind_count: int
    fetch: int


def parse_exec(payload: bytes) -> ExecRequest:
    """Parse an OALL8 execute payload (the TTC message from ``read_packet``).

    Extracts the SQL text; bind *values* are not decoded yet (``bind_count``
    reports how many there are). Raises :class:`InterfaceError` if the message
    is not a TTI_ALL8 execute.
    """
    if len(payload) < 3 or payload[0] != TTI_FUN or payload[1] != TTI_ALL8:
        raise InterfaceError('not an OALL8 execute')

    rest = payload[3:]  # skip TTI_FUN, TTI_ALL8, seq
    _opt, rest = decode_ub4(rest)
    cursor, rest = decode_ub4(rest)
    query_flag, rest = rest[0], rest[1:]
    query_len, rest = decode_ub4(rest)
    _all8_flag, rest = rest[0], rest[1:]
    _all8_len, rest = decode_ub4(rest)
    rest = rest[2:]  # two reserved bytes
    _lmax, rest = decode_ub4(rest)
    fetch, rest = decode_ub4(rest)
    _max, rest = decode_ub4(rest)
    _bind_flag, rest = rest[0], rest[1:]
    bind_count, rest = decode_ub4(rest)
    rest = rest[5:]  # five reserved bytes
    _def_flag, rest = rest[0], rest[1:]
    _def_len, rest = decode_ub4(rest)

    rest = rest[_MARKER_LEN + _SERVER_VERSION_SLOT :]
    sql = rest[:query_len].decode('utf-8') if query_flag else ''
    return ExecRequest(sql=sql, cursor=cursor, bind_count=bind_count, fetch=fetch)
