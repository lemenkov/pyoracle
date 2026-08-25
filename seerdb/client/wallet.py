# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Oracle wallet reader for wallet-based mutual TLS (#127).

An Oracle "wallet" (the Autonomous Database connection wallet, or any
``mkstore``/``orapki`` wallet) is a directory that bundles a client identity
plus the connect metadata needed to reach the database over TLS:

  * ``tnsnames.ora``  — named connect descriptors (host, port, service name,
                        and the server certificate DN to match).
  * ``sqlnet.ora``    — network options, notably ``SSL_SERVER_DN_MATCH`` and
                        the ``WALLET_LOCATION`` back-reference.
  * ``ewallet.pem``   — the client certificate, its CA chain and the private
                        key, PEM-encoded (the key optionally password-encrypted).
  * ``ewallet.p12``   — the same identity as a password-protected PKCS#12 store.
  * ``cwallet.sso``   — Oracle's proprietary auto-login form (not read here;
                        thin-mode drivers use ``ewallet.pem`` / ``ewallet.p12``).

This module is deliberately *sans-io at the core*: the descriptor grammar and
the identity decode are pure functions over ``str`` / ``bytes`` (so they unit
-test without touching disk), and only :func:`open_wallet` reads the directory.

The heavy lifting of decoding X.509 / PKCS#8 / PKCS#12 is delegated to ``pyca``
``cryptography`` — the same library python-oracledb-thin uses for this, so the
formats we accept line up with what an ADB wallet actually ships.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TypeAlias

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

# A parsed descriptor node is either a leaf string or a *branch*: a list of
# ``(key, node)`` pairs. Keys are lower-cased; the list preserves order and
# duplicates (an ADDRESS_LIST may repeat ADDRESS), which a plain dict could not.
Node: TypeAlias = 'str | list[tuple[str, Node]]'


class WalletError(Exception):
    """A wallet directory / descriptor / identity could not be read."""


# --------------------------------------------------------------------------- #
# tnsnames.ora / sqlnet.ora descriptor grammar
# --------------------------------------------------------------------------- #
#
# Both files are the same nested S-expression-ish syntax Oracle Net uses
# everywhere::
#
#     alias = (DESCRIPTION = (ADDRESS = (PROTOCOL = tcps)(HOST = h)(PORT = 1522))
#                            (CONNECT_DATA = (SERVICE_NAME = svc)))
#
# A parameter is ``(NAME = VALUE)`` where VALUE is either a run of child
# parameters or a single atom (bareword or double-quoted string — the server
# certificate DN arrives quoted because it is full of spaces and commas).


def _tokenize(Text: str) -> list[tuple[str, str]]:
    """Split descriptor text into ``(kind, value)`` tokens.

    ``kind`` is one of ``lparen`` / ``rparen`` / ``eq`` / ``comma`` / ``atom``.
    ``#`` starts a comment to end-of-line; whitespace is insignificant.
    """
    Tokens: list[tuple[str, str]] = []
    i = 0
    N = len(Text)
    Punct = {'(': 'lparen', ')': 'rparen', '=': 'eq', ',': 'comma'}
    while i < N:
        Ch = Text[i]
        if Ch.isspace():
            i += 1
            continue
        if Ch == '#':
            # Comment: skip to (and including) the newline.
            End = Text.find('\n', i)
            i = N if End < 0 else End + 1
            continue
        if Ch in Punct:
            Tokens.append((Punct[Ch], Ch))
            i += 1
            continue
        if Ch == '"':
            End = Text.find('"', i + 1)
            if End < 0:
                raise WalletError('unterminated quoted string in descriptor')
            Tokens.append(('atom', Text[i + 1 : End]))
            i = End + 1
            continue
        # Bareword: everything up to whitespace or a structural character.
        Start = i
        while i < N and not Text[i].isspace() and Text[i] not in '()=,#"':
            i += 1
        Tokens.append(('atom', Text[Start:i]))
    return Tokens


def _parse_value(Tokens: list[tuple[str, str]], i: int) -> tuple[Node, int]:
    """Parse the VALUE that follows an ``=`` at ``Tokens[i]``.

    A value is either a sequence of child parameters (when it opens with
    ``(``) or a single atom. Returns ``(node, next_index)``.
    """
    if i < len(Tokens) and Tokens[i][0] == 'lparen':
        Children: list[tuple[str, Node]] = []
        while i < len(Tokens) and Tokens[i][0] == 'lparen':
            (Param, i) = _parse_param(Tokens, i)
            Children.append(Param)
        return (Children, i)
    if i < len(Tokens) and Tokens[i][0] == 'atom':
        return (Tokens[i][1], i + 1)
    raise WalletError('expected a value in descriptor')


def _parse_param(Tokens: list[tuple[str, str]], i: int) -> tuple[tuple[str, Node], int]:
    """Parse one ``(NAME = VALUE)`` parameter. Returns ``((name, node), next)``."""
    if i >= len(Tokens) or Tokens[i][0] != 'lparen':
        raise WalletError("expected '(' in descriptor")
    i += 1
    if i >= len(Tokens) or Tokens[i][0] != 'atom':
        raise WalletError('expected a parameter name in descriptor')
    Name = Tokens[i][1].lower()
    i += 1
    if i >= len(Tokens) or Tokens[i][0] != 'eq':
        raise WalletError(f"expected '=' after {Name!r} in descriptor")
    i += 1
    (Value, i) = _parse_value(Tokens, i)
    if i >= len(Tokens) or Tokens[i][0] != 'rparen':
        raise WalletError(f"expected ')' closing {Name!r} in descriptor")
    return ((Name, Value), i + 1)


def parse_tnsnames(Text: str) -> dict[str, Node]:
    """Parse a ``tnsnames.ora`` into ``{alias: descriptor_node}``.

    Aliases are lower-cased. A comma-separated alias list (``a, b = (...)``)
    binds every name to the same descriptor.
    """
    Tokens = _tokenize(Text)
    Entries: dict[str, Node] = {}
    i = 0
    while i < len(Tokens):
        # Left-hand side: one or more comma-separated alias names.
        Names: list[str] = []
        if Tokens[i][0] != 'atom':
            raise WalletError('expected an alias name in tnsnames.ora')
        Names.append(Tokens[i][1].lower())
        i += 1
        while i < len(Tokens) and Tokens[i][0] == 'comma':
            i += 1
            if i >= len(Tokens) or Tokens[i][0] != 'atom':
                raise WalletError('expected an alias name after comma')
            Names.append(Tokens[i][1].lower())
            i += 1
        if i >= len(Tokens) or Tokens[i][0] != 'eq':
            raise WalletError(f"expected '=' after alias {Names[-1]!r}")
        i += 1
        (Value, i) = _parse_value(Tokens, i)
        for Name in Names:
            Entries[Name] = Value
    return Entries


def parse_sqlnet(Text: str) -> dict[str, Node]:
    """Parse a ``sqlnet.ora`` into ``{param: node}`` (params lower-cased)."""
    Tokens = _tokenize(Text)
    Params: dict[str, Node] = {}
    i = 0
    while i < len(Tokens):
        if Tokens[i][0] != 'atom':
            raise WalletError('expected a parameter name in sqlnet.ora')
        Name = Tokens[i][1].lower()
        i += 1
        if i >= len(Tokens) or Tokens[i][0] != 'eq':
            raise WalletError(f"expected '=' after {Name!r} in sqlnet.ora")
        i += 1
        (Value, i) = _parse_value(Tokens, i)
        Params[Name] = Value
    return Params


def _find_all(Node_: Node, Key: str) -> list[Node]:
    """Every value bound to ``Key`` anywhere in the subtree, in document order."""
    Found: list[Node] = []
    if isinstance(Node_, list):
        for K, V in Node_:
            if K == Key:
                Found.append(V)
            Found.extend(_find_all(V, Key))
    return Found


def _find_first(Node_: Node, Key: str) -> Node | None:
    """The first value bound to ``Key`` in the subtree, or ``None``."""
    Matches = _find_all(Node_, Key)
    return Matches[0] if Matches else None


# --------------------------------------------------------------------------- #
# Resolved connect target
# --------------------------------------------------------------------------- #


@dataclass
class ConnectInfo:
    """Connect parameters resolved from a tnsnames alias."""

    host: str
    port: int
    service_name: str | None = None
    sid: str | None = None
    protocol: str = 'tcps'
    # The server certificate DN to match (SSL_SERVER_CERT_DN), and whether DN
    # matching is requested at all (SSL_SERVER_DN_MATCH). Oracle checks the DN
    # against the peer certificate's *subject* — not standard hostname
    # verification — so the caller does this after the TLS handshake.
    server_dn: str | None = None
    dn_match: bool = False


def _truthy(Value: Node | None) -> bool:
    return isinstance(Value, str) and Value.strip().lower() in (
        'yes',
        'on',
        'true',
        '1',
    )


def resolve_dsn(Tnsnames: dict[str, Node], Alias: str) -> ConnectInfo:
    """Resolve ``Alias`` from a parsed tnsnames into a :class:`ConnectInfo`.

    Picks the first ``tcps`` ADDRESS (falling back to the first ADDRESS of any
    protocol), and reads the service name / SID and the DN-match settings from
    the descriptor.
    """
    Key = Alias.lower()
    if Key not in Tnsnames:
        Known = ', '.join(sorted(Tnsnames)) or '(none)'
        raise WalletError(f'alias {Alias!r} not found in tnsnames.ora; known: {Known}')
    Desc = Tnsnames[Key]

    Addresses = _find_all(Desc, 'address')
    if not Addresses:
        raise WalletError(f'no ADDRESS in descriptor for {Alias!r}')

    def _addr_protocol(Addr: Node) -> str:
        Proto = _find_first(Addr, 'protocol')
        return Proto.lower() if isinstance(Proto, str) else ''

    Chosen = next(
        (A for A in Addresses if _addr_protocol(A) == 'tcps'),
        Addresses[0],
    )
    Host = _find_first(Chosen, 'host')
    Port = _find_first(Chosen, 'port')
    if not isinstance(Host, str) or not isinstance(Port, str):
        raise WalletError(f'ADDRESS for {Alias!r} is missing HOST or PORT')

    ServiceName = _find_first(Desc, 'service_name')
    Sid = _find_first(Desc, 'sid')
    ServerDn = _find_first(Desc, 'ssl_server_cert_dn')
    DnMatch = _truthy(_find_first(Desc, 'ssl_server_dn_match'))

    return ConnectInfo(
        host=Host,
        port=int(Port),
        service_name=ServiceName if isinstance(ServiceName, str) else None,
        sid=Sid if isinstance(Sid, str) else None,
        protocol=_addr_protocol(Chosen) or 'tcps',
        server_dn=ServerDn if isinstance(ServerDn, str) else None,
        dn_match=DnMatch,
    )


# --------------------------------------------------------------------------- #
# Client identity (certificate + key + trust chain)
# --------------------------------------------------------------------------- #


@dataclass
class Identity:
    """A decoded client identity plus the CA chain that anchors the server."""

    # PEM: private key (PKCS#8, unencrypted) followed by the client certificate.
    # Suitable for ``SSLContext.load_cert_chain`` once written to a temp file.
    cert_key_pem: bytes
    # PEM of the CA certificate(s) shipped in the wallet — the server trust
    # anchor for ``SSLContext.load_verify_locations(cadata=...)``.
    ca_pem: bytes


def _pem_key(Key) -> bytes:
    return Key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _pem_cert(Cert) -> bytes:
    return Cert.public_bytes(serialization.Encoding.PEM)


def load_identity_pkcs12(Data: bytes, Password: bytes | None) -> Identity:
    """Decode a PKCS#12 (``ewallet.p12``) blob into an :class:`Identity`."""
    try:
        (Key, Cert, CaCerts) = pkcs12.load_key_and_certificates(Data, Password)
    except (ValueError, TypeError) as Exc:
        # cryptography raises ValueError on a bad password or malformed store.
        raise WalletError(f'could not read PKCS#12 wallet: {Exc}') from Exc
    if Key is None or Cert is None:
        raise WalletError('PKCS#12 wallet has no private key or client certificate')
    CaPem = b''.join(_pem_cert(C) for C in (CaCerts or []))
    return Identity(cert_key_pem=_pem_key(Key) + _pem_cert(Cert), ca_pem=CaPem)


def load_identity_pem(Data: bytes, Password: bytes | None) -> Identity:
    """Decode an ``ewallet.pem`` (client key + cert + CA chain) into an Identity.

    The wallet PEM concatenates the private key (possibly password-encrypted),
    the client certificate, and the CA chain. We re-emit the key unencrypted and
    split the client (leaf) certificate from the CA anchors.
    """
    Key = serialization.load_pem_private_key(Data, Password)
    Certs = _split_pem_certs(Data)
    if not Certs:
        raise WalletError('PEM wallet has no certificate')
    from cryptography import x509

    Parsed = [x509.load_pem_x509_certificate(C) for C in Certs]
    # The leaf is the cert whose public key matches the private key; the rest
    # are the CA chain. Fall back to "first is leaf" if none matches.
    KeyPub = Key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    def _is_leaf(Cert) -> bool:
        return (
            Cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            == KeyPub
        )

    LeafIdx = next((I for (I, C) in enumerate(Parsed) if _is_leaf(C)), 0)
    Leaf = Parsed[LeafIdx]
    CaCerts = [C for (I, C) in enumerate(Parsed) if I != LeafIdx]
    CaPem = b''.join(_pem_cert(C) for C in CaCerts)
    return Identity(cert_key_pem=_pem_key(Key) + _pem_cert(Leaf), ca_pem=CaPem)


def _split_pem_certs(Data: bytes) -> list[bytes]:
    """Extract each ``CERTIFICATE`` PEM block from a bytes blob, in order."""
    Begin = b'-----BEGIN CERTIFICATE-----'
    End = b'-----END CERTIFICATE-----'
    Blocks: list[bytes] = []
    Start = Data.find(Begin)
    while Start >= 0:
        Stop = Data.find(End, Start)
        if Stop < 0:
            break
        Stop += len(End)
        Blocks.append(Data[Start:Stop] + b'\n')
        Start = Data.find(Begin, Stop)
    return Blocks


# --------------------------------------------------------------------------- #
# The wallet as a whole
# --------------------------------------------------------------------------- #


@dataclass
class Wallet:
    """A read wallet: the resolved connect target plus the client identity."""

    identity: Identity
    connect: ConnectInfo | None = None
    # Parsed sqlnet.ora params, kept for options a caller may want (e.g. a
    # global SSL_SERVER_DN_MATCH default when the descriptor omits it).
    sqlnet: dict[str, Node] = field(default_factory=dict)


def _read_first(Directory: str, *Names: str) -> tuple[str, bytes] | None:
    for Name in Names:
        Path = os.path.join(Directory, Name)
        if os.path.isfile(Path):
            with open(Path, 'rb') as Fh:
                return (Name, Fh.read())
    return None


def open_wallet(
    Location: str,
    Password: str | None = None,
    Dsn: str | None = None,
) -> Wallet:
    """Read a wallet directory and return a :class:`Wallet`.

    ``Location`` is the wallet directory. ``Password`` decrypts ``ewallet.p12``
    or an encrypted ``ewallet.pem`` (the auto-login PEM needs none). ``Dsn``, if
    given, is resolved against ``tnsnames.ora``; a global ``SSL_SERVER_DN_MATCH``
    from ``sqlnet.ora`` fills in when the descriptor omits it.
    """
    if not os.path.isdir(Location):
        raise WalletError(f'wallet location is not a directory: {Location}')

    PasswordBytes = Password.encode() if Password is not None else None

    # Identity: prefer the PEM form (what thin-mode wallets ship); fall back to
    # PKCS#12. cwallet.sso (Oracle auto-login) is intentionally not attempted.
    Pem = _read_first(Location, 'ewallet.pem')
    if Pem is not None:
        Ident = load_identity_pem(Pem[1], PasswordBytes)
    else:
        P12 = _read_first(Location, 'ewallet.p12')
        if P12 is None:
            raise WalletError(
                f'no ewallet.pem or ewallet.p12 in {Location} '
                '(cwallet.sso auto-login wallets are not supported; export a '
                'PEM/PKCS#12 wallet with a password instead)'
            )
        Ident = load_identity_pkcs12(P12[1], PasswordBytes)

    Sqlnet: dict[str, Node] = {}
    SqlnetRaw = _read_first(Location, 'sqlnet.ora')
    if SqlnetRaw is not None:
        Sqlnet = parse_sqlnet(SqlnetRaw[1].decode('utf-8', 'replace'))

    Connect: ConnectInfo | None = None
    if Dsn is not None:
        TnsRaw = _read_first(Location, 'tnsnames.ora')
        if TnsRaw is None:
            raise WalletError(
                f'dsn {Dsn!r} requested but no tnsnames.ora in {Location}'
            )
        Connect = resolve_dsn(parse_tnsnames(TnsRaw[1].decode('utf-8', 'replace')), Dsn)
        # A descriptor without its own SSL_SERVER_DN_MATCH inherits the sqlnet
        # global, if one is set.
        if not Connect.dn_match and _truthy(Sqlnet.get('ssl_server_dn_match')):
            Connect.dn_match = True

    return Wallet(identity=Ident, connect=Connect, sqlnet=Sqlnet)


# --------------------------------------------------------------------------- #
# TLS context + server DN matching
# --------------------------------------------------------------------------- #


def build_client_context(Wal: Wallet):
    """Build a client ``ssl.SSLContext`` presenting the wallet's identity.

    The wallet CA anchors the server certificate; ``check_hostname`` is off
    because Oracle authenticates the server by its certificate DN
    (:func:`server_dn_matches`), not by hostname, and the ADB server cert CN is
    not the connect host. The client key+cert are handed to the stdlib ``ssl``
    stack through a short-lived 0600 temp file — it has no in-memory cert API.
    """
    import ssl
    import tempfile

    Ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    Ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    Ctx.check_hostname = False
    Ctx.verify_mode = ssl.CERT_REQUIRED
    if Wal.identity.ca_pem:
        Ctx.load_verify_locations(cadata=Wal.identity.ca_pem.decode())
    (Fd, Path) = tempfile.mkstemp(suffix='.pem')  # mkstemp creates it 0600
    try:
        with os.fdopen(Fd, 'wb') as Fh:
            Fh.write(Wal.identity.cert_key_pem)
        try:
            Ctx.load_cert_chain(Path)
        except ssl.SSLError as Exc:
            raise WalletError(
                f'wallet identity is not a usable cert/key: {Exc}'
            ) from Exc
    finally:
        try:
            os.unlink(Path)
        except OSError:
            # Best-effort cleanup: the temp file is gone or never landed.
            pass
    return Ctx


# LDAP/X.500 attribute names as they may appear in a tnsnames SSL_SERVER_CERT_DN
# (short forms) vs. how ``ssl.getpeercert()`` reports them (long forms), mapped
# to a single canonical key so the two can be compared.
_DN_CANON = {
    'CN': 'CN',
    'COMMONNAME': 'CN',
    'O': 'O',
    'ORGANIZATIONNAME': 'O',
    'OU': 'OU',
    'ORGANIZATIONALUNITNAME': 'OU',
    'C': 'C',
    'COUNTRYNAME': 'C',
    'ST': 'ST',
    'STATEORPROVINCENAME': 'ST',
    'L': 'L',
    'LOCALITYNAME': 'L',
    'DC': 'DC',
    'DOMAINCOMPONENT': 'DC',
}


def _canon_attr(Name: str) -> str:
    return _DN_CANON.get(Name.upper(), Name.upper())


def _parse_dn(Dn: str) -> set[tuple[str, str]]:
    """Parse a DN string (``CN=a, OU=b, O=c``) into a set of canonical pairs.

    Values here never contain commas (Oracle would quote such a DN, and the ADB
    DNs do not), so a plain comma split is sufficient.
    """
    Pairs: set[tuple[str, str]] = set()
    for Part in Dn.split(','):
        Part = Part.strip()
        if not Part or '=' not in Part:
            continue
        (Attr, Value) = Part.split('=', 1)
        Pairs.add((_canon_attr(Attr.strip()), Value.strip()))
    return Pairs


def _peercert_pairs(PeerCert: dict) -> set[tuple[str, str]]:
    Pairs: set[tuple[str, str]] = set()
    for Rdn in PeerCert.get('subject', ()):
        for Name, Value in Rdn:
            Pairs.add((_canon_attr(Name), Value))
    return Pairs


def server_dn_matches(ExpectedDn: str, PeerCert: dict | None) -> bool:
    """True when the peer certificate's subject satisfies ``ExpectedDn``.

    Mirrors Oracle's ``SSL_SERVER_DN_MATCH``: every RDN named in the expected DN
    must be present in the server certificate's subject (attribute order is
    irrelevant). An empty expected DN or a certificate with no subject fails.
    """
    Expected = _parse_dn(ExpectedDn)
    if not Expected or not PeerCert:
        return False
    return Expected <= _peercert_pairs(PeerCert)
