[![CircleCI](https://circleci.com/gh/julmon/tcle.svg?style=shield)](https://app.circleci.com/pipelines/github/julmon/tcle?branch=master)
![Experimental](https://img.shields.io/badge/status-experimental-orange)
[![License](https://img.shields.io/github/license/julmon/tcle?color=%23008bb9)](https://github.com/julmon/tcle/blob/master/LICENSE.txt)

# Transparent Cell-Level Encryption for PostgreSQL

TCLE is an experimental PostgreSQL extension implementing data encryption at
column level. Data encryption and decryption are processed through a dedicated
table access method when the tuples are written to or fetched from the OS. This
table access method (AM) extends core Heap AM and preserves original MVCC
behaviour.

TCLE relies on OpenSSL's libcrypto EVP functions. Only one cryptographic method
is currently supported: AES 256b CBC.

## Key Management System

TCLE embes a lightweight Key Management System and implements a 2-tier
key-based architecture:

  1. Each database where the extension's been created got its own master key.
     This master key is never stored on disk but resides in PostgreSQL shared
     memory.
     Only database owner or superusers can set a master key. For this prototype,
     the master key is derivated from a user passphrase, but we could imagine
     more sophisticated ways to do it in the future.

  2. Each table using TCLE access method owns a table key. Table keys are
     stored encrypted with database master key into dedicated table, inside the
     database. This kind of key is generated using strong RNG provided by
     OpenSSL.

## Data types

TCLE provides 3 new data types to identify the columns to be encrypted:

  * `ENCRYPT_TEXT` is a pseudo TEXT type. The main differences with TEXT
    type are: data are stored with plain storage while with TEXT type they are
    stored with extended storage (TOAST), and, this type has size limitation
    to 2kB.

  * `ENCRYPT_NUMERIC` is a pseudo NUMERIC type and behaves like it.

  * `ENCRYPT_TIMESTAMPTZ` is a pseudo TIMESTAMPTZ type. Internal representation
    of this type is a bit different of TIMESTAMPTZ's: we use variable length
    representation while TIMESTAMPTZ internal representation is 64 bits
    integer. AES encryption needs extra bytes for AES padding and IV storage.

## PostgreSQL versions support

TCLE works with PostgreSQL 12 and 13 (currently in beta2 stage - 2020-06-25).

## Installation

PostgreSQL needs to be compiled with OpenSSL support.

TCLE compilation:
```console
$ sudo PG_CONFIG=/path/to/pg_config make clean install
```

Once the extension is installed, TCLE library must be loaded by adding `tcle`
into `shared_preload_libraries` parameter and restart PostgreSQL cluster.

## Regression tests

Once the extension compiled and installed, PostgreSQL server configured,
regression tests can be run with `make installcheck` like this:
```console
$ PG_CONFIG=/path/to/pg_config make installcheck
...
============== dropping database "contrib_regression" ==============
DROP DATABASE
============== creating database "contrib_regression" ==============
CREATE DATABASE
ALTER DATABASE
============== running regression test queries        ==============
test 001-create-extension         ... ok           47 ms
test 002-set-passphrase           ... ok           27 ms
test 003-create-table             ... ok           43 ms
test 004-update                   ... ok           14 ms
test 005-create-table-as          ... ok           21 ms
test 006-vacuum-full              ... ok           52 ms
test 007-drop-table               ... ok           14 ms
test 008-fetch-by-index-scan      ... ok           33 ms
test 009-op-class                 ... ok           18 ms
test 010-err-set-passphrase       ... ok            7 ms
test 011-copy                     ... ok           28 ms

======================
 All 11 tests passed. 
======================
```

## Usage

1. Extension creation:
```sql
CREATE EXTENSION tcle;
```

2. Set a master key:
```sql
SELECT tcle_set_passphrase('my private passphrase');
```

3. Table creation:
```sql
CREATE TABLE t (
  id    ENCRYPTED_NUMERIC,
  label ENCRYPTED_TEXT,
  ts    ENCRYPTED_TIMESTAMPTZ
) USING tcleam;
```

## Limitations

Due to its experimental status, there are some limitations:

  * DO NOT USE IT IN PRODUCTION.
  * No support for key rotation.
  * Master key passphrase could leak in PostgreSQL logs.

Concept limitations:

  * Indexing encrypted data not supported.
  * Data could reside not encrypted into PostgreSQL temporary files.
  * Data are not encrypted into dump files.
  * Statements containing clear data could leak into PostgreSQL logs.
