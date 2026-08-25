# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Unit tests for the wallet reader (#127, phase 1).

Everything here is offline: each test builds a throwaway wallet on disk with
``cryptography`` (a CA, a CA-signed client identity, and the tnsnames.ora /
sqlnet.ora text an ADB wallet ships), then exercises the pure parsers and the
identity decode against it. No Oracle server and no live ADB are involved.
"""

import datetime
import os
import ssl
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from seerdb.client.wallet import (
    ConnectInfo,
    WalletError,
    load_identity_pem,
    load_identity_pkcs12,
    open_wallet,
    parse_sqlnet,
    parse_tnsnames,
    resolve_dsn,
)

# A realistic ADB-style tnsnames.ora: two aliases sharing a descriptor via a
# comma list, a tcps ADDRESS, a quoted server-certificate DN, and a comment.
TNSNAMES = """
# ADB connection descriptors
mydb_high, mydb_primary =
  (description =
    (retry_count = 20)(retry_delay = 3)
    (address = (protocol = tcps)(port = 1522)(host = adb.example.oraclecloud.com))
    (connect_data = (service_name = abc123_mydb_high.adb.oraclecloud.com))
    (security =
      (ssl_server_dn_match = yes)
      (ssl_server_cert_dn = "CN=adb.example.oraclecloud.com, OU=Oracle, O=Oracle Corp, L=Redwood City, ST=California, C=US")))

mydb_plain =
  (description =
    (address = (protocol = tcp)(port = 1521)(host = plain.example.com))
    (connect_data = (sid = ORCL)))
"""

SQLNET = """
WALLET_LOCATION = (SOURCE = (METHOD = file) (METHOD_DATA = (DIRECTORY = "?/network/admin")))
SSL_SERVER_DN_MATCH = yes
"""


def _gen_ca():
    Key = ec.generate_private_key(ec.SECP256R1())
    Name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test Wallet CA')])
    Now = datetime.datetime(2020, 1, 1)
    Cert = (
        x509.CertificateBuilder()
        .subject_name(Name)
        .issuer_name(Name)
        .public_key(Key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(Now)
        .not_valid_after(Now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(Key, hashes.SHA256())
    )
    return (Key, Cert)


def _gen_signed(Cn, CaKey, CaCert):
    Key = ec.generate_private_key(ec.SECP256R1())
    Now = datetime.datetime(2020, 1, 1)
    Cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, Cn)]))
        .issuer_name(CaCert.subject)
        .public_key(Key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(Now)
        .not_valid_after(Now + datetime.timedelta(days=3650))
        .sign(CaKey, hashes.SHA256())
    )
    return (Key, Cert)


def _pem_key(Key, Password=None):
    Enc = (
        serialization.BestAvailableEncryption(Password)
        if Password
        else serialization.NoEncryption()
    )
    return Key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, Enc
    )


def _pem_cert(Cert):
    return Cert.public_bytes(serialization.Encoding.PEM)


def _write_wallet(
    Directory,
    Form='pem',
    Password=None,
    WithTnsnames=True,
    WithSqlnet=True,
):
    """Materialise a wallet directory; return (ca_key, ca_cert, client_cert)."""
    (CaKey, CaCert) = _gen_ca()
    (ClientKey, ClientCert) = _gen_signed('client', CaKey, CaCert)
    PwBytes = Password.encode() if Password else None

    if Form == 'pem':
        # ADB PEM order: key, then client cert, then CA chain.
        Blob = _pem_key(ClientKey, PwBytes) + _pem_cert(ClientCert) + _pem_cert(CaCert)
        with open(os.path.join(Directory, 'ewallet.pem'), 'wb') as Fh:
            Fh.write(Blob)
    elif Form == 'p12':
        Enc = (
            serialization.BestAvailableEncryption(PwBytes)
            if PwBytes
            else serialization.NoEncryption()
        )
        Blob = pkcs12.serialize_key_and_certificates(
            b'client', ClientKey, ClientCert, [CaCert], Enc
        )
        with open(os.path.join(Directory, 'ewallet.p12'), 'wb') as Fh:
            Fh.write(Blob)

    if WithTnsnames:
        with open(os.path.join(Directory, 'tnsnames.ora'), 'w') as Fh:
            Fh.write(TNSNAMES)
    if WithSqlnet:
        with open(os.path.join(Directory, 'sqlnet.ora'), 'w') as Fh:
            Fh.write(SQLNET)
    return (CaKey, CaCert, ClientCert)


class TestDescriptorParsing(unittest.TestCase):
    def test_alias_comma_list_shares_descriptor(self):
        Entries = parse_tnsnames(TNSNAMES)
        self.assertIn('mydb_high', Entries)
        self.assertIn('mydb_primary', Entries)
        self.assertIn('mydb_plain', Entries)
        # The comma list binds both names to the same node.
        self.assertEqual(Entries['mydb_high'], Entries['mydb_primary'])

    def test_resolve_tcps_address(self):
        Info = resolve_dsn(parse_tnsnames(TNSNAMES), 'mydb_high')
        self.assertEqual(Info.host, 'adb.example.oraclecloud.com')
        self.assertEqual(Info.port, 1522)
        self.assertEqual(Info.protocol, 'tcps')
        self.assertEqual(Info.service_name, 'abc123_mydb_high.adb.oraclecloud.com')
        self.assertIsNone(Info.sid)
        self.assertTrue(Info.dn_match)
        self.assertIn('CN=adb.example.oraclecloud.com', Info.server_dn)

    def test_case_insensitive_alias(self):
        Info = resolve_dsn(parse_tnsnames(TNSNAMES), 'MyDB_High')
        self.assertEqual(Info.port, 1522)

    def test_sid_descriptor_without_service(self):
        Info = resolve_dsn(parse_tnsnames(TNSNAMES), 'mydb_plain')
        self.assertEqual(Info.host, 'plain.example.com')
        self.assertEqual(Info.sid, 'ORCL')
        self.assertIsNone(Info.service_name)
        self.assertFalse(Info.dn_match)

    def test_unknown_alias_raises(self):
        with self.assertRaises(WalletError) as Ctx:
            resolve_dsn(parse_tnsnames(TNSNAMES), 'nope')
        self.assertIn('not found', str(Ctx.exception))

    def test_parse_sqlnet_dn_match(self):
        Params = parse_sqlnet(SQLNET)
        self.assertEqual(Params.get('ssl_server_dn_match'), 'yes')
        # WALLET_LOCATION parses as a nested branch, not a scalar.
        self.assertIsInstance(Params.get('wallet_location'), list)

    def test_unterminated_quote_raises(self):
        with self.assertRaises(WalletError):
            parse_tnsnames('a = (b = "oops)')


class TestIdentityDecode(unittest.TestCase):
    def test_pem_splits_leaf_from_ca(self):
        with tempfile.TemporaryDirectory() as Dir:
            (_CaKey, CaCert, ClientCert) = _write_wallet(Dir, Form='pem')
            with open(os.path.join(Dir, 'ewallet.pem'), 'rb') as Fh:
                Ident = load_identity_pem(Fh.read(), None)
        # The leaf PEM must carry the client cert and a private key...
        self.assertIn(b'BEGIN CERTIFICATE', Ident.cert_key_pem)
        self.assertIn(b'PRIVATE KEY', Ident.cert_key_pem)
        # ...and the CA PEM must be exactly the CA cert, not the leaf.
        self.assertEqual(Ident.ca_pem.strip(), _pem_cert(CaCert).strip())
        LeafCert = x509.load_pem_x509_certificate(
            Ident.cert_key_pem.split(b'-----BEGIN PRIVATE KEY-----')[0]
            or Ident.cert_key_pem
        )
        self.assertEqual(LeafCert.subject, ClientCert.subject)

    def test_pkcs12_decode(self):
        with tempfile.TemporaryDirectory() as Dir:
            (_CaKey, CaCert, _ClientCert) = _write_wallet(
                Dir, Form='p12', Password='walletpw'
            )
            with open(os.path.join(Dir, 'ewallet.p12'), 'rb') as Fh:
                Ident = load_identity_pkcs12(Fh.read(), b'walletpw')
        self.assertIn(b'PRIVATE KEY', Ident.cert_key_pem)
        self.assertEqual(Ident.ca_pem.strip(), _pem_cert(CaCert).strip())

    def test_pkcs12_wrong_password_raises(self):
        with tempfile.TemporaryDirectory() as Dir:
            _write_wallet(Dir, Form='p12', Password='right')
            with open(os.path.join(Dir, 'ewallet.p12'), 'rb') as Fh:
                Data = Fh.read()
        with self.assertRaises(WalletError):
            load_identity_pkcs12(Data, b'wrong')

    def test_identity_pem_loads_into_sslcontext(self):
        """The produced cert+key PEM must be accepted by the stdlib ssl stack
        — this is the exact artefact phase 3 feeds to load_cert_chain."""
        with tempfile.TemporaryDirectory() as Dir:
            _write_wallet(Dir, Form='pem')
            with open(os.path.join(Dir, 'ewallet.pem'), 'rb') as Fh:
                Ident = load_identity_pem(Fh.read(), None)
            PemPath = os.path.join(Dir, 'combined.pem')
            with open(PemPath, 'wb') as Fh:
                Fh.write(Ident.cert_key_pem)
            Ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            Ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            Ctx.check_hostname = False
            Ctx.verify_mode = ssl.CERT_NONE
            Ctx.load_cert_chain(PemPath)  # raises if key/cert don't pair up


class TestOpenWallet(unittest.TestCase):
    def test_pem_wallet_end_to_end(self):
        with tempfile.TemporaryDirectory() as Dir:
            _write_wallet(Dir, Form='pem')
            Wal = open_wallet(Dir, Dsn='mydb_high')
        self.assertIsInstance(Wal.connect, ConnectInfo)
        self.assertEqual(Wal.connect.host, 'adb.example.oraclecloud.com')
        self.assertTrue(Wal.connect.dn_match)
        self.assertIn(b'PRIVATE KEY', Wal.identity.cert_key_pem)

    def test_p12_wallet_with_password(self):
        with tempfile.TemporaryDirectory() as Dir:
            _write_wallet(Dir, Form='p12', Password='walletpw', WithTnsnames=True)
            Wal = open_wallet(Dir, Password='walletpw', Dsn='mydb_plain')
        self.assertEqual(Wal.connect.sid, 'ORCL')

    def test_dn_match_inherits_from_sqlnet(self):
        # mydb_plain's descriptor has no SSL_SERVER_DN_MATCH; the sqlnet global
        # (yes) must fill it in.
        with tempfile.TemporaryDirectory() as Dir:
            _write_wallet(Dir, Form='pem')
            Wal = open_wallet(Dir, Dsn='mydb_plain')
        self.assertTrue(Wal.connect.dn_match)

    def test_no_dsn_leaves_connect_none(self):
        with tempfile.TemporaryDirectory() as Dir:
            _write_wallet(Dir, Form='pem')
            Wal = open_wallet(Dir)
        self.assertIsNone(Wal.connect)
        self.assertIn(b'PRIVATE KEY', Wal.identity.cert_key_pem)

    def test_missing_identity_raises(self):
        with tempfile.TemporaryDirectory() as Dir:
            # Only metadata, no ewallet.pem / ewallet.p12.
            with open(os.path.join(Dir, 'tnsnames.ora'), 'w') as Fh:
                Fh.write(TNSNAMES)
            with self.assertRaises(WalletError) as Ctx:
                open_wallet(Dir, Dsn='mydb_high')
        self.assertIn('ewallet', str(Ctx.exception))

    def test_dsn_without_tnsnames_raises(self):
        with tempfile.TemporaryDirectory() as Dir:
            _write_wallet(Dir, Form='pem', WithTnsnames=False)
            with self.assertRaises(WalletError):
                open_wallet(Dir, Dsn='mydb_high')

    def test_location_not_a_directory_raises(self):
        with self.assertRaises(WalletError):
            open_wallet('/nonexistent/wallet/dir', Dsn='mydb_high')


if __name__ == '__main__':
    unittest.main()
