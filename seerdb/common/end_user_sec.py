# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""End-user security context objects for Deep Data Security (TTC func 205, #460).

The context bundles an end-user identity plus authorization details (a database
access token, optional data roles and attributes) and is attached to a session
with :meth:`OracleConnect.set_end_user_security_context`. On the wire the whole
context travels as the OSON image of a small dict, carried by a func-205
piggyback (see :func:`seerdb.common.tns.encode_end_user_sec_piggyback`).

The dict shape and key order mirror the reference thin client's
``EndUserSecurityContextImpl.create`` so the server parses it identically.
This module is sans-io: it only builds the OSON image; the connection layer
handles negotiation, the tcps guard, and the piggyback framing.
"""

from typing import Dict, List, Optional, Tuple, Union

from .oson import encode_oson

# The OSON image is length-prefixed by a ub2 on the wire, so it cannot exceed
# 65535 bytes (matches oracledb's ERR_INVALID_END_USER_SECURITY_CONTEXT_LENGTH).
_MAX_CONTEXT_LEN = 65535


class EndUserSecurityContext:
    """An opaque, already-encoded end-user security context.

    Construct one with :func:`create_end_user_security_context`; the OSON image
    is built at creation time and held in ``oson_bytes``.
    """

    __slots__ = ('oson_bytes',)

    def __init__(self, oson_bytes: bytes) -> None:
        self.oson_bytes = oson_bytes

    def __repr__(self) -> str:
        return f'<EndUserSecurityContext {len(self.oson_bytes)} bytes>'


def create_end_user_security_context(
    end_user_identity: Union[str, Tuple[str, str], List[str]],
    database_access_token: str,
    data_roles: Optional[List[str]] = None,
    attributes: Optional[Dict] = None,
) -> EndUserSecurityContext:
    """Create an :class:`EndUserSecurityContext` from its component values.

    ``end_user_identity`` is either a token string (OCI IAM / Microsoft Entra ID
    user) or a ``(end_user_name, key)`` two-tuple/list (database-managed user).
    ``database_access_token`` is the security token authorizing the application
    to access the database (required, non-empty). ``data_roles`` is an optional
    list of data-role names; ``attributes`` an optional dict of extra
    attribute-value pairs. Mirrors oracledb's
    ``oracledb.create_end_user_security_context``.
    """
    end_user_token = end_user_name = key = None

    if isinstance(end_user_identity, str) and end_user_identity:
        end_user_token = end_user_identity
    elif (
        isinstance(end_user_identity, (tuple, list))
        and len(end_user_identity) == 2
        and all(isinstance(v, str) and v for v in end_user_identity)
    ):
        end_user_name, key = end_user_identity
    else:
        raise ValueError(
            'end_user_identity must be a token string or a tuple/list of '
            '(end_user_name, key).'
        )

    if not isinstance(database_access_token, str) or not database_access_token:
        raise ValueError('database_access_token must be a non-empty string.')

    # Key insertion order matches the reference client so the OSON field table
    # lines up: ver, then the identity keys, then the token, roles, attributes.
    value: Dict = {'ver': '1.0'}
    if end_user_token is not None:
        value['end_user_token'] = end_user_token
    if end_user_name is not None:
        value['end_user_name'] = end_user_name
    if key is not None:
        value['end_user_contextid'] = key
    value['database_access_token'] = database_access_token
    if data_roles is not None:
        value['data_roles'] = list(data_roles)
    if attributes is not None:
        value['attributes'] = [{'name': k, 'values': v} for k, v in attributes.items()]

    oson_bytes = encode_oson(value)
    if len(oson_bytes) > _MAX_CONTEXT_LEN:
        raise ValueError('end user security context exceeds 65535 bytes.')
    return EndUserSecurityContext(oson_bytes)
