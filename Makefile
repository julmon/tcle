EXTENSION  = tcle
EXTVERSION = $(grep default_version tcle.control | sed "s/^default_version = '\([^']\+\)'$/\1/g")

SHLIB_LINK += $(filter -lssl -lcrypto -lssleay32 -leay32, $(LIBS))

PGFILEDESC = "TCLE - Transparent Cell-Level Encryption"
MODULE_big = tcle
OBJS       = tcle.o tcleheap.o aes.o kms.o utils.o
REGRESS    = 001-create-extension \
             002-set-passphrase \
             003-create-table \
             004-update \
             005-create-table-as \
             006-vacuum-full \
             007-drop-table \
             008-fetch-by-index-scan \
             009-op-class \
             010-err-set-passphrase \
             011-copy \
             012-change-passphrase \

PG_CONFIG ?= pg_config

all:

DATA = $(wildcard *--*.sql)
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
