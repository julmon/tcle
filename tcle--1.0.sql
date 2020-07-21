/* tcle/tcle--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION tcle" to load this file. \quit


-------------------------------------------------------------------------------
--                  ENCRYPT_TEXT type definition
-------------------------------------------------------------------------------

CREATE TYPE encrypt_text;

CREATE FUNCTION encrypt_text_in(cstring)
RETURNS encrypt_text
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_text_out(encrypt_text)
RETURNS cstring
AS 'textout'
LANGUAGE INTERNAL IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_text_recv(internal)
RETURNS encrypt_text
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_text_send(encrypt_text)
RETURNS bytea
AS 'textsend'
LANGUAGE INTERNAL IMMUTABLE PARALLEL SAFE;

CREATE TYPE encrypt_text (
  INPUT=encrypt_text_in,
  OUTPUT=encrypt_text_out,
  RECEIVE=encrypt_text_recv,
  SEND=encrypt_text_send,
  STORAGE=plain,
  CATEGORY='S',
  COLLATABLE=true
);

CREATE CAST (ENCRYPT_TEXT AS TEXT) WITH INOUT AS IMPLICIT;
CREATE CAST (TEXT AS ENCRYPT_TEXT) WITH INOUT AS IMPLICIT;

CREATE FUNCTION encrypt_text_eq(encrypt_text, encrypt_text)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'texteq';
CREATE FUNCTION encrypt_text_ne(encrypt_text, encrypt_text)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'textne';
CREATE FUNCTION encrypt_text_lt(encrypt_text, encrypt_text)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'text_lt';
CREATE FUNCTION encrypt_text_le(encrypt_text, encrypt_text)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'text_le';
CREATE FUNCTION encrypt_text_gt(encrypt_text, encrypt_text)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'text_gt';
CREATE FUNCTION encrypt_text_ge(encrypt_text, encrypt_text)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'text_ge';
CREATE FUNCTION encrypt_text_cmp(encrypt_text, encrypt_text)
RETURNS integer LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'bttextcmp';

CREATE OPERATOR = (
  LEFTARG = encrypt_text,
  RIGHTARG = encrypt_text,
  PROCEDURE = encrypt_text_eq,
  COMMUTATOR = '=',
  NEGATOR = '<>',
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES, MERGES
);

CREATE OPERATOR <> (
  LEFTARG = encrypt_text,
  RIGHTARG = encrypt_text,
  PROCEDURE = encrypt_text_ne,
  COMMUTATOR = '<>',
  NEGATOR = '=',
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);

CREATE OPERATOR < (
  LEFTARG = encrypt_text,
  RIGHTARG = encrypt_text,
  PROCEDURE = encrypt_text_lt,
  COMMUTATOR = > ,
  NEGATOR = >= ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  LEFTARG = encrypt_text,
  RIGHTARG = encrypt_text,
  PROCEDURE = encrypt_text_le,
  COMMUTATOR = >= ,
  NEGATOR = > ,
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  LEFTARG = encrypt_text,
  RIGHTARG = encrypt_text,
  PROCEDURE = encrypt_text_gt,
  COMMUTATOR = < ,
  NEGATOR = <= ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  LEFTARG = encrypt_text,
  RIGHTARG = encrypt_text,
  PROCEDURE = encrypt_text_ge,
  COMMUTATOR = <= ,
  NEGATOR = < ,
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);

CREATE OPERATOR CLASS encrypt_text_ops
DEFAULT FOR TYPE encrypt_text USING btree
AS
  OPERATOR 1 <  ,
  OPERATOR 2 <= ,
  OPERATOR 3 =  ,
  OPERATOR 4 >= ,
  OPERATOR 5 >  ,
  FUNCTION 1 encrypt_text_cmp(encrypt_text, encrypt_text);


-------------------------------------------------------------------------------
--                  ENCRYPT_NUMERIC type definition
-------------------------------------------------------------------------------

CREATE TYPE encrypt_numeric;

CREATE FUNCTION encrypt_numeric_in(cstring)
RETURNS encrypt_numeric
AS 'numeric_in'
LANGUAGE INTERNAL IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_numeric_out(encrypt_numeric)
RETURNS cstring
AS 'numeric_out'
LANGUAGE INTERNAL IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_numeric_recv(internal)
RETURNS encrypt_numeric
AS 'numeric_recv'
LANGUAGE INTERNAL IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION encrypt_numeric_send(encrypt_numeric)
RETURNS bytea
AS 'numeric_send'
LANGUAGE INTERNAL IMMUTABLE PARALLEL SAFE;

CREATE TYPE encrypt_numeric (
  INPUT=encrypt_numeric_in,
  OUTPUT=encrypt_numeric_out,
  RECEIVE=encrypt_numeric_recv,
  SEND=encrypt_numeric_send,
  CATEGORY='N',
  LIKE=numeric
);

CREATE CAST (ENCRYPT_NUMERIC AS NUMERIC) WITH INOUT AS IMPLICIT;
CREATE CAST (NUMERIC AS ENCRYPT_NUMERIC) WITH INOUT AS IMPLICIT;
CREATE CAST (INTEGER AS ENCRYPT_NUMERIC) WITH INOUT AS IMPLICIT;

CREATE FUNCTION encrypt_numeric_eq(encrypt_numeric, encrypt_numeric)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_eq';
CREATE FUNCTION encrypt_numeric_ne(encrypt_numeric, encrypt_numeric)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_ne';
CREATE FUNCTION encrypt_numeric_lt(encrypt_numeric, encrypt_numeric)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_lt';
CREATE FUNCTION encrypt_numeric_le(encrypt_numeric, encrypt_numeric)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_le';
CREATE FUNCTION encrypt_numeric_gt(encrypt_numeric, encrypt_numeric)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_gt';
CREATE FUNCTION encrypt_numeric_ge(encrypt_numeric, encrypt_numeric)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_ge';
CREATE FUNCTION encrypt_numeric_cmp(encrypt_numeric, encrypt_numeric)
RETURNS integer LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_cmp';

CREATE OPERATOR = (
  LEFTARG = encrypt_numeric,
  RIGHTARG = encrypt_numeric,
  PROCEDURE = encrypt_numeric_eq,
  COMMUTATOR = '=',
  NEGATOR = '<>',
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES, MERGES
);

CREATE OPERATOR <> (
  LEFTARG = encrypt_numeric,
  RIGHTARG = encrypt_numeric,
  PROCEDURE = encrypt_numeric_ne,
  COMMUTATOR = '<>',
  NEGATOR = '=',
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);

CREATE OPERATOR < (
  LEFTARG = encrypt_numeric,
  RIGHTARG = encrypt_numeric,
  PROCEDURE = encrypt_numeric_lt,
  COMMUTATOR = > ,
  NEGATOR = >= ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  LEFTARG = encrypt_numeric,
  RIGHTARG = encrypt_numeric,
  PROCEDURE = encrypt_numeric_le,
  COMMUTATOR = >= ,
  NEGATOR = > ,
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  LEFTARG = encrypt_numeric,
  RIGHTARG = encrypt_numeric,
  PROCEDURE = encrypt_numeric_gt,
  COMMUTATOR = < ,
  NEGATOR = <= ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  LEFTARG = encrypt_numeric,
  RIGHTARG = encrypt_numeric,
  PROCEDURE = encrypt_numeric_ge,
  COMMUTATOR = <= ,
  NEGATOR = < ,
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);

CREATE OPERATOR CLASS encrypt_numeric_ops
DEFAULT FOR TYPE encrypt_numeric USING btree
AS
  OPERATOR 1 <  ,
  OPERATOR 2 <= ,
  OPERATOR 3 =  ,
  OPERATOR 4 >= ,
  OPERATOR 5 >  ,
  FUNCTION 1 encrypt_numeric_cmp(encrypt_numeric, encrypt_numeric);


-------------------------------------------------------------------------------
--                 ENCRYPT_TIMESTAMPTZ type definition
-------------------------------------------------------------------------------

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

CREATE FUNCTION encrypt_timestamptz_eq(encrypt_timestamptz, encrypt_timestamptz)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_eq';
CREATE FUNCTION encrypt_timestamptz_ne(encrypt_timestamptz, encrypt_timestamptz)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_ne';
CREATE FUNCTION encrypt_timestamptz_lt(encrypt_timestamptz, encrypt_timestamptz)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_lt';
CREATE FUNCTION encrypt_timestamptz_le(encrypt_timestamptz, encrypt_timestamptz)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_le';
CREATE FUNCTION encrypt_timestamptz_gt(encrypt_timestamptz, encrypt_timestamptz)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_gt';
CREATE FUNCTION encrypt_timestamptz_ge(encrypt_timestamptz, encrypt_timestamptz)
RETURNS boolean LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_ge';
CREATE FUNCTION encrypt_timestamptz_cmp(encrypt_timestamptz, encrypt_timestamptz)
RETURNS integer LANGUAGE internal IMMUTABLE PARALLEL SAFE AS 'numeric_cmp';

CREATE OPERATOR = (
  LEFTARG = encrypt_timestamptz,
  RIGHTARG = encrypt_timestamptz,
  PROCEDURE = encrypt_timestamptz_eq,
  COMMUTATOR = '=',
  NEGATOR = '<>',
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES, MERGES
);

CREATE OPERATOR <> (
  LEFTARG = encrypt_timestamptz,
  RIGHTARG = encrypt_timestamptz,
  PROCEDURE = encrypt_timestamptz_ne,
  COMMUTATOR = '<>',
  NEGATOR = '=',
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);

CREATE OPERATOR < (
  LEFTARG = encrypt_timestamptz,
  RIGHTARG = encrypt_timestamptz,
  PROCEDURE = encrypt_timestamptz_lt,
  COMMUTATOR = > ,
  NEGATOR = >= ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  LEFTARG = encrypt_timestamptz,
  RIGHTARG = encrypt_timestamptz,
  PROCEDURE = encrypt_timestamptz_le,
  COMMUTATOR = >= ,
  NEGATOR = > ,
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  LEFTARG = encrypt_timestamptz,
  RIGHTARG = encrypt_timestamptz,
  PROCEDURE = encrypt_timestamptz_gt,
  COMMUTATOR = < ,
  NEGATOR = <= ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  LEFTARG = encrypt_timestamptz,
  RIGHTARG = encrypt_timestamptz,
  PROCEDURE = encrypt_timestamptz_ge,
  COMMUTATOR = <= ,
  NEGATOR = < ,
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);

CREATE OPERATOR CLASS encrypt_timestamptz_ops
DEFAULT FOR TYPE encrypt_timestamptz USING btree
AS
  OPERATOR 1 <  ,
  OPERATOR 2 <= ,
  OPERATOR 3 =  ,
  OPERATOR 4 >= ,
  OPERATOR 5 >  ,
  FUNCTION 1 encrypt_timestamptz_cmp(encrypt_timestamptz, encrypt_timestamptz);


CREATE FUNCTION tcle_set_passphrase(text)
RETURNS BOOLEAN
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION tcle_change_passphrase(text, text)
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
