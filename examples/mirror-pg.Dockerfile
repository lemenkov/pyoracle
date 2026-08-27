# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# PostgreSQL for the Mirror's PostgresBackend, with the orafce extension the
# backend leans on for Oracle-compatible SQL functions (nvl, decode, to_char /
# to_date, add_months, instr, …). The Alpine `postgresql-orafce` package targets
# Alpine's own PostgreSQL major, which differs from the official image's, so
# orafce is built from source against this image's server (PGXS).
#
#   podman build -f examples/mirror-pg.Dockerfile -t mirror-pg .
#   podman run -d --name mirror-pg -p 5433:5432 \
#       -e POSTGRES_USER=pyo -e POSTGRES_PASSWORD=pyo123 -e POSTGRES_DB=mirror \
#       mirror-pg
#
# The PostgresBackend runs `CREATE EXTENSION IF NOT EXISTS orafce` and puts the
# `oracle` schema on the search_path itself, so no further setup is needed.

FROM postgres:16-alpine

ARG ORAFCE_VERSION=VERSION_4_10_0

RUN set -eux; \
    apk add --no-cache --virtual .orafce-build \
        build-base icu-dev openssl-dev curl; \
    curl -fsSL -o /tmp/orafce.tar.gz \
        "https://github.com/orafce/orafce/archive/refs/tags/${ORAFCE_VERSION}.tar.gz"; \
    mkdir -p /tmp/orafce && tar xzf /tmp/orafce.tar.gz -C /tmp/orafce --strip-components=1; \
    cd /tmp/orafce; \
    make USE_PGXS=1 with_llvm=no; \
    make USE_PGXS=1 with_llvm=no install; \
    cd /; rm -rf /tmp/orafce /tmp/orafce.tar.gz; \
    apk del .orafce-build
