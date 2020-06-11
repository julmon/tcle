/* tcle/tcle--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION tcle" to load this file. \quit

-- ENCRYPT_TEXT type definition
CREATE TYPE encrypt_text;

CREATE FUNCTION encrypt_text_in(cstring)
RETURNS encrypt_text
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_text_out(encrypt_text)
RETURNS cstring
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_text_recv(internal)
RETURNS encrypt_text
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_text_send(encrypt_text)
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE TYPE encrypt_text (
  INPUT=encrypt_text_in,
  OUTPUT=encrypt_text_out,
  RECEIVE=encrypt_text_recv,
  SEND=encrypt_text_send,
  STORAGE=plain,
  CATEGORY='S'
);

CREATE CAST (ENCRYPT_TEXT AS TEXT) WITH INOUT AS IMPLICIT;
CREATE CAST (TEXT AS ENCRYPT_TEXT) WITH INOUT AS IMPLICIT;


-- ENCRYPT_NUMERIC type definition
CREATE TYPE encrypt_numeric;

CREATE FUNCTION encrypt_numeric_in(cstring)
RETURNS encrypt_numeric
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_numeric_out(encrypt_numeric)
RETURNS cstring
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_numeric_recv(internal)
RETURNS encrypt_numeric
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_numeric_send(encrypt_numeric)
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE TYPE encrypt_numeric (
  INPUT=encrypt_numeric_in,
  OUTPUT=encrypt_numeric_out,
  RECEIVE=encrypt_numeric_recv,
  SEND=encrypt_numeric_send,
  CATEGORY='N'
);

CREATE CAST (ENCRYPT_NUMERIC AS NUMERIC) WITH INOUT AS IMPLICIT;
CREATE CAST (NUMERIC AS ENCRYPT_NUMERIC) WITH INOUT AS IMPLICIT;
CREATE CAST (INTEGER AS ENCRYPT_NUMERIC) WITH INOUT AS IMPLICIT;


-- ENCRYPT_TIMESTAMPTZ type definition
CREATE TYPE encrypt_timestamptz;

CREATE FUNCTION encrypt_timestamptz_in(cstring)
RETURNS encrypt_timestamptz
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_timestamptz_out(encrypt_timestamptz)
RETURNS cstring
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_timestamptz_recv(internal)
RETURNS encrypt_timestamptz
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_timestamptz_send(encrypt_timestamptz)
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE TYPE encrypt_timestamptz (
  INPUT=encrypt_timestamptz_in,
  OUTPUT=encrypt_timestamptz_out,
  RECEIVE=encrypt_timestamptz_recv,
  SEND=encrypt_timestamptz_send,
  CATEGORY='D'
);

CREATE CAST (ENCRYPT_TIMESTAMPTZ AS TIMESTAMPTZ) WITH INOUT AS IMPLICIT;
CREATE CAST (ENCRYPT_TIMESTAMPTZ AS DATE) WITH INOUT AS IMPLICIT;
CREATE CAST (ENCRYPT_TIMESTAMPTZ AS TIMESTAMP) WITH INOUT AS IMPLICIT;
CREATE CAST (TIMESTAMPTZ AS ENCRYPT_TIMESTAMPTZ) WITH INOUT AS IMPLICIT;


CREATE FUNCTION tcle_set_passphrase(text)
RETURNS BOOLEAN
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION tcleam_handler(internal)
RETURNS table_am_handler
AS 'MODULE_PATHNAME'
LANGUAGE C;

-- Table Access Method
CREATE ACCESS METHOD tcleam TYPE TABLE HANDLER tcleam_handler;
COMMENT ON ACCESS METHOD tcleam IS 'Transparent Cell-Level Encryption';

CREATE TABLE tcle_table_keys(
  nspname NAME NOT NULL,
  relname NAME NOT NULL,
  cipher_key BYTEA,
  PRIMARY KEY(nspname, relname)
);
COMMENT ON TABLE tcle_table_keys IS
'Transparent Cell-Level Encryption internal table';
