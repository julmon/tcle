#!/bin/bash -eux

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

PGVERSION="${PGVERSION:-12}"
PGPATH=/usr/local/pgsql-$PGVERSION

PG_CONFIG=$PGPATH/bin/pg_config make -C ${DIR}/.. clean install
