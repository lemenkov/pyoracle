# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The release a Mirror session introduces itself as follows its field version."""

from __future__ import annotations

from seerdb.client.connection import _format_version
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_12_2,
    FIELD_VERSION_23_1,
)
from seerdb.server.identity import IDENTITY_11_2, IDENTITY_12_2, server_identity


def test_packed_versions_decode_to_the_releases_they_name() -> None:
    # The client turns AUTH_VERSION_NO into connection.version with this same
    # decoder, so this is what a client would actually report.
    assert _format_version(IDENTITY_11_2.version_no) == '11.2.0.2.0'
    assert _format_version(IDENTITY_12_2.version_no) == '12.2.0.1.0'


def test_11_2_field_version_keeps_the_captured_11g_identity() -> None:
    assert server_identity(FIELD_VERSION_11_2) is IDENTITY_11_2
    assert b'11g' in IDENTITY_11_2.banner
    assert b'11.2.0.2.0' in IDENTITY_11_2.banner


def test_12_2_and_above_report_12_2() -> None:
    # 12.2 is the highest release the Mirror has an identity for, so a session
    # advertising a newer field version reports it rather than claiming 11.2.
    assert server_identity(FIELD_VERSION_12_2) is IDENTITY_12_2
    assert server_identity(FIELD_VERSION_23_1) is IDENTITY_12_2
    assert b'12c' in IDENTITY_12_2.banner
    assert b'12.2.0.1.0' in IDENTITY_12_2.banner


def test_12_1_still_reports_11_2() -> None:
    # There is no captured 12.1 anchor, so 12.1 keeps the 11.2 identity rather
    # than inventing a release number.
    assert server_identity(FIELD_VERSION_12_1) is IDENTITY_11_2


def test_auth_result_table_carries_the_identity_release() -> None:
    from seerdb.server.auth import _result_params

    for identity in (IDENTITY_11_2, IDENTITY_12_2):
        params = dict(_result_params(identity))
        assert params[b'AUTH_VERSION_NO'] == str(identity.version_no).encode()
        assert params[b'AUTH_VERSION_SQL'] == identity.version_sql
        assert params[b'AUTH_VERSION_STRING'] == identity.version_string
