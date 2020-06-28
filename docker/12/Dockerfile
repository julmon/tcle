FROM debian:buster-slim

# Proxy to APT cacher: e.g. http://apt-cacher-ng.docker:3142
ARG APT_CACHER

# Set the env variables to non-interactive
ENV DEBIAN_FRONTEND noninteractive
ENV DEBIAN_PRIORITY critical
ENV DEBCONF_NOWARNINGS yes

RUN set -x && \
	# Setup a cacher to speed up build
	if [ -n "${APT_CACHER}" ] ; then \
		echo "Acquire::http::Proxy \"${APT_CACHER}\";" | tee /etc/apt/apt.conf.d/01proxy ; \
	fi; \
	apt-get -qq update && \
	apt-get -qy install --no-install-recommends \
		wget \
		fakeroot \
		sudo \
		bzip2 \
		make \
		gcc \
		bison \
		flex \
		libreadline-dev \
		libssl-dev \
		zlib1g-dev && \
	wget --no-check-certificate https://ftp.postgresql.org/pub/source/v12.3/postgresql-12.3.tar.bz2 -O /tmp/postgresql-12.3.tar.bz2 && \
	tar xvf /tmp/postgresql-12.3.tar.bz2 -C /tmp && \
	cd /tmp/postgresql-12.3 && \
	./configure --prefix=/usr/local/pgsql-12 --with-openssl && \
	make -j 4 && \
	make install && \
	rm -rf /tmp/postgresql* && \
	useradd postgres && \
	mkdir -p /var/lib/pgsql/12/data && \
	chown -R postgres /var/lib/pgsql && \
	cd /tmp && \
	sudo -u postgres /usr/local/pgsql-12/bin/initdb -E UTF-8 -D /var/lib/pgsql/12/data
