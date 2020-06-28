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
	wget --no-check-certificate https://ftp.postgresql.org/pub/source/v13beta2/postgresql-13beta2.tar.bz2 -O /tmp/postgresql-13beta2.tar.bz2 && \
	tar xvf /tmp/postgresql-13beta2.tar.bz2 -C /tmp && \
	cd /tmp/postgresql-13beta2 && \
	./configure --prefix=/usr/local/pgsql-13 --with-openssl && \
	make -j 4 && \
	make install && \
	rm -rf /tmp/postgresql* && \
	useradd postgres && \
	mkdir -p /var/lib/pgsql/13/data && \
	chown -R postgres /var/lib/pgsql && \
	cd /tmp && \
	sudo -u postgres /usr/local/pgsql-13/bin/initdb -E UTF-8 -D /var/lib/pgsql/13/data
