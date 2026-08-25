#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
#
# Configure an Oracle 23ai Free container for TCPS mutual TLS so the committed
# client wallet (tests/fixtures/wallet) authenticates. Reuses the fixture CA:
# the server identity is the fixture server_cert/server_key (already CA-signed),
# and the fixture ca_cert is added as a trusted cert so the server verifies the
# client. No CA private key is needed (it is deliberately not committed).
#
# Run INSIDE the container as the `oracle` user, with the repo's committed files
# mounted read-only. See docs/wallet_mtls_live_testing.md for the full walk-through.
#
#   FIXTURES  dir holding ca_cert.pem / server_cert.pem / server_key.pem
#             (default: /fixtures — mount tests/fixtures/wallet here)
#   LIVE_DIR  dir holding listener.ora / sqlnet.ora
#             (default: /live — mount tests/live here)
#   PDB       pluggable database to create the user in (default: FREEPDB1)
#   DB_USER / DB_PASSWORD   application user to create (default: PYO / pyo123)

set -euo pipefail

FIXTURES="${FIXTURES:-/fixtures}"
LIVE_DIR="${LIVE_DIR:-/live}"
WALLET="/opt/oracle/tls_wallet"
WALLET_PWD="${WALLET_PWD:-WalletPasswd1}"
P12_PWD="${P12_PWD:-P12Passwd1}"
PDB="${PDB:-FREEPDB1}"
DB_USER="${DB_USER:-PYO}"
DB_PASSWORD="${DB_PASSWORD:-pyo123}"
TNS_ADMIN="${TNS_ADMIN:-${ORACLE_HOME:?ORACLE_HOME not set}/network/admin}"

echo ">> Building server PKCS#12 from the committed fixture identity"
# Just the server leaf + key: the client trusts the CA from its own wallet, so
# the server need not ship the chain. The CA is added below as a *trusted* cert
# only so the server can verify the incoming client certificate.
openssl pkcs12 -export \
  -in "${FIXTURES}/server_cert.pem" \
  -inkey "${FIXTURES}/server_key.pem" \
  -name oracle-server \
  -out /tmp/server.p12 \
  -passout "pass:${P12_PWD}"

echo ">> Creating the auto-login server wallet at ${WALLET}"
rm -rf "${WALLET}"
mkdir -p "${WALLET}"
orapki wallet create -wallet "${WALLET}" -pwd "${WALLET_PWD}" -auto_login

echo ">> Importing the server identity and trusting the fixture CA"
orapki wallet import_pkcs12 -wallet "${WALLET}" -pwd "${WALLET_PWD}" \
  -pkcs12file /tmp/server.p12 -pkcs12pwd "${P12_PWD}"
orapki wallet add -wallet "${WALLET}" -pwd "${WALLET_PWD}" \
  -trusted_cert -cert "${FIXTURES}/ca_cert.pem"
rm -f /tmp/server.p12

echo ">> Installing listener.ora / sqlnet.ora into ${TNS_ADMIN}"
cp "${LIVE_DIR}/listener.ora" "${TNS_ADMIN}/listener.ora"
cp "${LIVE_DIR}/sqlnet.ora" "${TNS_ADMIN}/sqlnet.ora"

echo ">> Restarting the listener (now serving TCPS on 2484)"
# A full stop+start, not `reload`: reload re-reads parameters but does not bind a
# newly added listening endpoint, so the TCPS address would silently not appear.
lsnrctl stop || true
lsnrctl start

echo ">> Forcing service registration and waiting for it"
# After a listener restart the instance has not yet re-registered its services;
# connecting in that window is refused with ORA-12514. Force registration and
# wait for the PDB service to appear before anyone connects.
sqlplus -s / as sysdba >/dev/null 2>&1 <<SQL || true
ALTER SYSTEM REGISTER;
EXIT
SQL
for _ in $(seq 1 30); do
  if lsnrctl status 2>/dev/null | grep -qi "\"${PDB}\""; then break; fi
  sleep 1
done

echo ">> Creating ${DB_USER} in ${PDB}"
sqlplus -s / as sysdba <<SQL
WHENEVER SQLERROR EXIT 1
ALTER SESSION SET CONTAINER = ${PDB};
DECLARE
  n INTEGER;
BEGIN
  SELECT COUNT(*) INTO n FROM dba_users WHERE username = UPPER('${DB_USER}');
  IF n = 0 THEN
    EXECUTE IMMEDIATE 'CREATE USER ${DB_USER} IDENTIFIED BY ${DB_PASSWORD}';
  END IF;
END;
/
GRANT CREATE SESSION TO ${DB_USER};
EXIT
SQL

echo ">> Done. Connect with the client wallet over TCPS:"
echo "   SEERDB_WALLET_LIVE=1 SEERDB_LIVE_SERVICE=${PDB} \\"
echo "   SEERDB_LIVE_USER=${DB_USER} SEERDB_LIVE_PASSWORD=${DB_PASSWORD} \\"
echo "   python3 -m pytest tests/test_wallet_live.py -v"
