EXTENSION  = tcle
EXTVERSION = $(grep default_version tcle.control | sed "s/^default_version = '\([^']\+\)'$/\1/g")

SHLIB_LINK += $(filter -lssl -lcrypto -lssleay32 -leay32, $(LIBS))

PGFILEDESC = "TCLE - Transparent Cell-Level Encryption"
MODULE_big = tcle
OBJS       = tcle.o tcleheap.o aes.o kms.o utils.o
REGRESS    = tcle

PG_CONFIG ?= pg_config

all:

DATA = $(wildcard *--*.sql)
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
