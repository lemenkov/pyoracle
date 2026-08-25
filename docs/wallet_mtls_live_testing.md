<!-- SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com> -->
<!-- SPDX-License-Identifier: MIT -->

# Live wallet mutual-TLS testing (#127)

The offline suite proves wallet mTLS end-to-end against an in-process Mirror
behind a TLS proxy. This runbook goes one step further: a **real Oracle server**
speaking TTC over a genuine TCPS (TLS) listener that requires a client
certificate, so the whole path is exercised against a production database engine
— no Oracle Cloud account needed.

It reuses the committed fixture wallet (`tests/fixtures/wallet/`), so the client
side needs no new material.

## Trust model

One CA (the fixture CA) anchors both ends:

```
                 fixture CA (ca_cert.pem)
                 /                      \
       signs server_cert           signs client cert
       (CN=seerdb-test-server)     (CN=seerdb-test-client, in ewallet.pem)
              |                              |
   Oracle server wallet            seerdb client wallet
   presents server_cert            presents client cert + trusts ca_cert
   trusts ca_cert  ───────── mutual TLS ─────────  matches server DN
```

The fixture already ships `server_cert.pem` + `server_key.pem` (CA-signed) and
`ca_cert.pem`. The CA **private** key is intentionally not committed and is not
needed — the server imports the ready-made server identity and merely *trusts*
the CA to verify the incoming client certificate.

## Prerequisites

- Docker / Podman.
- An Oracle Database **23ai** Free image. Pin an explicit 23ai tag —
  `container-registry.oracle.com/database/free:23.5.0.0` (the community
  `gvenzl/oracle-free:23-slim`, used by CI, works too — adjust
  `ORACLE_HOME`/service names). **Do not use `:latest`**: it is now 26ai,
  which seerdb does not yet fully support (a session drops just after
  authentication — see #434). seerdb is validated against 11g / 21c / 23ai.
- This repository checked out.

## 1. Start the database

```bash
docker run -d --name seerdb-tcps \
  -p 1521:1521 -p 2484:2484 \
  -e ORACLE_PWD=OraFree1 \
  container-registry.oracle.com/database/free:23.5.0.0
# wait until healthy (first boot initialises the DB):
docker logs -f seerdb-tcps   # until "DATABASE IS READY TO USE!"
```

## 2. Configure TCPS mutual TLS

Mount the committed fixture wallet and the config templates, then run the setup
script inside the container. It builds the server wallet from the fixture
identity, installs `listener.ora` / `sqlnet.ora`, restarts the listener (a full
stop+start — `reload` does not bind a newly added endpoint), and creates the
`PYO` user:

```bash
docker cp tests/fixtures/wallet seerdb-tcps:/fixtures
docker cp tests/live            seerdb-tcps:/live
docker exec -it seerdb-tcps bash /live/setup_oracle_tcps.sh
```

If `TNS_ADMIN` in the container is not `$ORACLE_HOME/network/admin` (check with
`docker exec seerdb-tcps bash -lc 'echo $TNS_ADMIN'` or `lsnrctl status`), pass
it through: `docker exec -e TNS_ADMIN=/that/dir -it seerdb-tcps bash
/live/setup_oracle_tcps.sh`.

Verify the TCPS endpoint is up:

```bash
docker exec seerdb-tcps lsnrctl status | grep -i tcps
```

## 3. Run the live test

From the host, against the committed client wallet:

```bash
SEERDB_WALLET_LIVE=1 python3 -m pytest tests/test_wallet_live.py -v
```

Defaults (host `127.0.0.1`, TCPS port `2484`, service `FREEPDB1`, user `PYO`,
DSN `seerdb_test`, wallet `tests/fixtures/wallet`) match the steps above. The
test opens a wallet mTLS connection — presenting the client certificate,
matching the server DN `CN=seerdb-test-server` — and runs a real `SELECT`, sync
and async. Override any piece with the `SEERDB_LIVE_*` variables documented at
the top of `tests/test_wallet_live.py`.

## Optional: certificate-only login (externally identified user)

The steps above use mutual TLS as the *channel* and a password for database
auth. To authenticate the user **by certificate DN** instead, create an
externally identified user and connect with no password:

```sql
ALTER SESSION SET CONTAINER = FREEPDB1;
CREATE USER seerdb_cert IDENTIFIED EXTERNALLY AS 'CN=seerdb-test-client';
GRANT CREATE SESSION TO seerdb_cert;
```

(Full DN-based mapping and `nz`/`OID` configuration is beyond this runbook; the
password path is the simpler smoke test.)

## Troubleshooting

- **`ORA-28860` / TLS handshake fails** — the server wallet is missing or the
  listener did not pick it up. Re-check `WALLET_LOCATION` in both `.ora` files
  and `lsnrctl reload`.
- **`ORA-28864` / peer certificate rejected** — the fixture CA is not trusted by
  the server; re-run the `orapki wallet add -trusted_cert` step.
- **Client raises `server certificate DN does not match`** — the server is
  presenting a different cert than the fixture `server_cert.pem`; confirm the
  PKCS#12 import used the fixture identity.
- **`ORA-12560` / no TCPS** — the listener has no TCPS address; confirm
  `listener.ora` landed in the active `TNS_ADMIN` and reload.

## Toward CI

This is structured to become a GitHub Actions job alongside the existing
integration matrix: run the 23ai Free image as a service container, `docker cp`
the fixture wallet + `tests/live`, exec `setup_oracle_tcps.sh`, then run
`tests/test_wallet_live.py` with `SEERDB_WALLET_LIVE=1`. The only inputs are
already in the repo, so no secrets are required.
