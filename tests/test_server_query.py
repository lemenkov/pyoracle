# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side query-path parsing."""

from __future__ import annotations

import pytest

from seerdb.exceptions import InterfaceError
from seerdb.server.query import parse_exec

# A real 11g OALL8 execute for `select * from dual`, captured from seerdb 11.2
# through tools/capture_proxy.py (the TTC payload after the DATA prefix).
_DUAL_EXEC = bytes.fromhex(
    '035e070280210001011201010d000004ffffffff010f047fffffff00000000000000000000'
    '0001000000000073656c656374202a2066726f6d206475616c010100000000000001010000'
    '000000'
)


def test_parse_real_dual_exec() -> None:
    req = parse_exec(_DUAL_EXEC)
    assert req.sql == 'select * from dual'
    assert req.cursor == 0
    assert req.bind_count == 0
    assert req.fetch == 15


def test_non_exec_raises() -> None:
    with pytest.raises(InterfaceError):
        parse_exec(b'\x06\x00not an exec')
