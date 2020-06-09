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

  1. Each database where the extension is created got its own master key. This
     master key is never stored on disk but resides in PostgreSQL shared memory.
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
    stored with extended storage (TOAST), and, this type has a size limitation
    to 2kB.

  * `ENCRYPT_NUMERIC` is a pseudo NUMERIC type and behaves like it.

  * `ENCRYPT_TIMESTAMPTZ` is a pseudo TIMESTAMPTZ type. Internal representation
    of this type is a bit different of TIMESTAMPTZ one: we use a variable
    length representation while TIMESTAMPTZ internal representation is a 64
    bits integer. AES encryption needs extra bytes for AES padding and IV
    storage.

## PostgreSQL versions support

TCLE works only with PostgreSQL 13. With some efforts, it could works with
PostgreSQL 12.

## Installation

PostgreSQL needs to be compiled with OpenSSL support.

TCLE compilation:
```console
$ sudo PG_CONFIG=/path/to/pg_config make clean install
```

Once the extension is installed, TCLE library must be loaded by adding `tcle`
into `shared_preload_library` parameter and restart PostgreSQL cluster.

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
  * Lack of operators and cast for these new data types, some explicit cast are
    still needed.
  * Master key passphrase could leak in PostgreSQL logs.

Concept limitations:

  * Indexing encrypted data not supported.
  * Data could reside not encrypted into PostgreSQL temporary files.
  * Data are not encrypted into dump files.
  * Statements containing clear text data could leak into PostgreSQL logs.
