# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Token-based authentication helpers (OAuth2 / OCI IAM) — #125.

Oracle token auth replaces the O5LOGON challenge/response with a single AUTH
message carrying the token. Two shapes (python-oracledb parity):

  * **OAuth2 / DB token** — a bare JWT string; the AUTH message carries just
    ``AUTH_TOKEN``.
  * **OCI IAM** — a ``(token, private_key)`` pair; the AUTH message adds
    ``AUTH_HEADER`` (a ``date`` / ``(request-target)`` / ``host`` block) and
    ``AUTH_SIGNATURE`` (base64 of an RSA-SHA256 / PKCS#1 v1.5 signature over the
    header, proving possession of the key that matches the token).

This module is the sans-io crypto: build the header, sign it, and (for the
Mirror's server half) verify it. The wire framing of the AUTH message lives in
:mod:`seerdb.common.tns`. The header layout + signing scheme were re-expressed
from the go-ora driver (MIT); they are the format the ADB server enforces.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class TokenAuthError(Exception):
    """A malformed token, key, or signature."""


def token_auth_header(
    host: str, service: str, port: int, now: datetime | None = None
) -> str:
    """Build the string an OCI IAM token signature is computed over.

    ``date`` is the current time in RFC 1123 form with ``GMT`` (not ``UTC``) as
    the zone name — matching what the server recomputes and checks against.
    ``now`` is only for deterministic tests.
    """
    when = now or datetime.now(timezone.utc)
    date = when.strftime('%a, %d %b %Y %H:%M:%S GMT')
    return f'date:{date}\n(request-target):{service}\nhost:{host}:{port}'


def sign_token_header(header: str, private_key_pem: bytes) -> str:
    """Sign ``header`` with an RSA private key (PEM, PKCS#1 or PKCS#8).

    Returns the base64 of an RSA-SHA256 PKCS#1 v1.5 signature — the value the
    ``AUTH_SIGNATURE`` pair carries.
    """
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except Exception as exc:  # noqa: BLE001 - normalize to our error type
        raise TokenAuthError(f'invalid private key: {exc}') from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TokenAuthError('token private key must be RSA')
    signature = key.sign(header.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode('ascii')


def verify_token_header(header: str, signature_b64: str, public_key_pem: bytes) -> bool:
    """Server side (the Mirror): verify an ``AUTH_SIGNATURE`` over ``header``.

    Returns True iff the base64 signature is a valid RSA-SHA256 signature of the
    header under the given RSA public key. Never raises on a bad signature — a
    malformed key still raises :class:`TokenAuthError`.
    """
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except Exception as exc:  # noqa: BLE001 - normalize to our error type
        raise TokenAuthError(f'invalid public key: {exc}') from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise TokenAuthError('token public key must be RSA')
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:  # noqa: BLE001 - a non-base64 signature is simply invalid
        return False
    try:
        key.verify(
            signature, header.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256()
        )
        return True
    except Exception:  # noqa: BLE001 - cryptography raises InvalidSignature
        return False


def token_subject(jwt: str) -> str | None:
    """Best-effort ``sub`` claim from a JWT (``header.payload.signature``).

    The real IAM service is what validates the token; a server that accepts a
    token only needs a label to identify the session by, so this decodes the
    unverified payload and returns None on anything that is not a plain JWT.
    """
    try:
        parts = jwt.split('.')
        if len(parts) < 2:
            return None
        payload = parts[1]
        payload += '=' * (-len(payload) % 4)  # restore base64url padding
        claims = json.loads(base64.urlsafe_b64decode(payload))
        sub = claims.get('sub')
        return str(sub) if sub is not None else None
    except Exception:  # noqa: BLE001 - any decode failure just means "no subject"
        return None


def normalize_access_token(access_token: object) -> tuple[str, bytes | None]:
    """Resolve the ``access_token`` connect parameter to ``(token, private_key)``.

    Accepts a plain JWT ``str`` (OAuth2 — no key), a ``(token, private_key)``
    pair (OCI IAM), or a zero-arg callable returning either (refreshable tokens,
    python-oracledb parity). The private key is returned as PEM bytes or None.
    """
    if callable(access_token):
        access_token = access_token()
    if isinstance(access_token, str):
        return (access_token, None)
    if isinstance(access_token, (tuple, list)) and len(access_token) == 2:
        token, key = access_token
        if not isinstance(token, str):
            raise TokenAuthError('access_token[0] (the token) must be a str')
        if isinstance(key, str):
            key = key.encode('utf-8')
        if key is not None and not isinstance(key, (bytes, bytearray)):
            raise TokenAuthError('access_token[1] (the private key) must be PEM bytes')
        return (token, bytes(key) if key is not None else None)
    raise TokenAuthError(
        'access_token must be a JWT str, a (token, private_key) pair, or a '
        'callable returning one'
    )
