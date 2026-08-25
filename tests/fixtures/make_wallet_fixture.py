# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Regenerate the committed wallet mTLS fixture (#127).

Run ``python3 tests/fixtures/make_wallet_fixture.py`` to (re)write
``tests/fixtures/wallet/``. The committed output is what the mutual-TLS tests
consume; this script exists so the fixture is reproducible rather than a set of
opaque binaries.

It builds one CA that signs *both* halves of the handshake:

  * ``server_cert.pem`` — the TLS-terminating proxy's server certificate
    (CN=seerdb-test-server, SANs localhost / 127.0.0.1). The client anchors it
    via the wallet's CA, and matches its DN for SSL_SERVER_DN_MATCH.
  * ``ewallet.pem`` / ``ewallet.p12`` — the client identity (CN=seerdb-test-
    client) the wallet presents. The proxy verifies it against the same CA.

Validity is pinned to a fixed, far-future window so the committed certs are
stable and do not expire during the project's lifetime.
"""

import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

WALLET_DIR = os.path.join(os.path.dirname(__file__), 'wallet')

SERVER_CN = 'seerdb-test-server'
CLIENT_CN = 'seerdb-test-client'
P12_PASSWORD = b'fixturepw'

NOT_BEFORE = datetime.datetime(2020, 1, 1)
NOT_AFTER = datetime.datetime(2050, 1, 1)

TNSNAMES = f"""# Committed wallet fixture for the mutual-TLS tests (#127).
# The port is nominal; the integration test overrides it with the proxy's
# ephemeral listen port. Host and server DN are what matter here.
seerdb_test =
  (description =
    (address = (protocol = tcps)(host = localhost)(port = 1522))
    (connect_data = (service_name = seerdb_test_svc))
    (security = (ssl_server_dn_match = yes)(ssl_server_cert_dn = "CN={SERVER_CN}")))
"""

SQLNET = """SSL_SERVER_DN_MATCH = yes
"""


def _name(Cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, Cn)])


def _gen_ca():
    Key = ec.generate_private_key(ec.SECP256R1())
    Name = _name('seerdb Test Wallet CA')
    Cert = (
        x509.CertificateBuilder()
        .subject_name(Name)
        .issuer_name(Name)
        .public_key(Key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(Key, hashes.SHA256())
    )
    return (Key, Cert)


def _gen_leaf(Cn, CaKey, CaCert, Sans=None):
    Key = ec.generate_private_key(ec.SECP256R1())
    Builder = (
        x509.CertificateBuilder()
        .subject_name(_name(Cn))
        .issuer_name(CaCert.subject)
        .public_key(Key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if Sans:
        Builder = Builder.add_extension(
            x509.SubjectAlternativeName(Sans), critical=False
        )
    return (Key, Builder.sign(CaKey, hashes.SHA256()))


def _pem_cert(Cert):
    return Cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(Key):
    return Key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _write(Name, Data):
    Path = os.path.join(WALLET_DIR, Name)
    Mode = 'wb' if isinstance(Data, bytes) else 'w'
    with open(Path, Mode) as Fh:
        Fh.write(Data)
    print(f'wrote {Path}')


def main():
    os.makedirs(WALLET_DIR, exist_ok=True)
    (CaKey, CaCert) = _gen_ca()
    (ServerKey, ServerCert) = _gen_leaf(
        SERVER_CN,
        CaKey,
        CaCert,
        Sans=[
            x509.DNSName('localhost'),
            x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
        ],
    )
    (ClientKey, ClientCert) = _gen_leaf(CLIENT_CN, CaKey, CaCert)

    _write('ca_cert.pem', _pem_cert(CaCert))
    _write('server_cert.pem', _pem_cert(ServerCert))
    _write('server_key.pem', _pem_key(ServerKey))

    # Auto-login PEM wallet: client key + client cert + CA chain, key unencrypted.
    _write(
        'ewallet.pem',
        _pem_key(ClientKey) + _pem_cert(ClientCert) + _pem_cert(CaCert),
    )
    # Password-protected PKCS#12 form of the same identity.
    _write(
        'ewallet.p12',
        pkcs12.serialize_key_and_certificates(
            b'seerdb-test-client',
            ClientKey,
            ClientCert,
            [CaCert],
            serialization.BestAvailableEncryption(P12_PASSWORD),
        ),
    )
    _write('tnsnames.ora', TNSNAMES)
    _write('sqlnet.ora', SQLNET)


if __name__ == '__main__':
    main()
