# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline unit tests for the Oracle-passthrough example backend's error relay.

The passthrough is the Mirror's conformance harness (it relays each statement to
a real Oracle). A real Oracle error already reads ``ORA-NNNNN: ...``; the Mirror
(``BackendError``) re-adds that prefix from the code, so relaying the text
verbatim doubled it. ``_relay_error`` strips the leading prefix so exactly one is
emitted — the behaviour these tests pin without needing a database.
"""

from __future__ import annotations

import sys
from pathlib import Path

import seerdb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'examples'))
from oracle_passthrough_backend import _relay_error  # noqa: E402


def test_strips_the_redundant_ora_prefix():
    exc = seerdb.DatabaseError('ORA-00904: "X": invalid identifier', 904)
    err = _relay_error(exc)
    # The Mirror re-adds "ORA-00904: " from the code — the relayed message must be
    # bare so the final text carries the prefix exactly once.
    assert err.ora_code == 904
    assert err.ora_message == 'ORA-00904: "X": invalid identifier'


def test_recovers_the_code_from_the_prefix_when_absent():
    # Some client exceptions carry no numeric code; take it from the text.
    exc = seerdb.DatabaseError('ORA-01008: not all variables bound', None)
    err = _relay_error(exc)
    assert err.ora_code == 1008
    assert err.ora_message == 'ORA-01008: not all variables bound'


def test_message_without_a_prefix_is_left_alone():
    exc = seerdb.DatabaseError('some non-Oracle failure', None)
    err = _relay_error(exc)
    assert err.ora_code == 900  # ORA-00900, the BackendError default
    assert err.ora_message == 'ORA-00900: some non-Oracle failure'


def test_code_argument_wins_over_the_prefix_digits():
    # exc.code is authoritative when present, even if the text's digits differ.
    exc = seerdb.DatabaseError('ORA-00942: table or view does not exist', 942)
    err = _relay_error(exc)
    assert err.ora_code == 942
    assert err.ora_message == 'ORA-00942: table or view does not exist'
