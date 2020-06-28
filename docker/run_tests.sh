#!/bin/bash -eux

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

PGVERSION="${PGVERSION:-12}"
PGDATA=/var/lib/pgsql/$PGVERSION/data
PGPATH=/usr/local/pgsql-$PGVERSION

sudo -u postgres $PGPATH/bin/pg_ctl -l /tmp/pg.log -D $PGDATA start

PG_CONFIG=$PGPATH/bin/pg_config make -C ${DIR}/.. clean install

sudo -u postgres $PGPATH/bin/psql -c "ALTER SYSTEM SET shared_preload_libraries TO 'tcle';"
sudo -u postgres $PGPATH/bin/pg_ctl -D $PGDATA restart
sudo -u postgres PG_CONFIG=$PGPATH/bin/pg_config make -C ${DIR}/.. installcheck ||
{
	res=$?
	cat ${DIR}/../regression.diffs
	exit $res
}
