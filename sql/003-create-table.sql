SET search_path TO public, s1;
-- Test CREATE TABLE statement and implicit casts
CREATE TABLE t (p INTEGER, n ENCRYPT_NUMERIC, l ENCRYPT_TEXT, d ENCRYPT_TIMESTAMPTZ) USING tcleam;
INSERT INTO t SELECT i, i * 2, 'Text input number '||i, '2020-06-23 22:56:50'::TIMESTAMPTZ + make_interval(days => i) FROM generate_series(1, 100) i;
SELECT COUNT(*) FROM t;
SELECT ctid, * FROM t LIMIT 10;
