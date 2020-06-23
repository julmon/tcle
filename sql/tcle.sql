CREATE EXTENSION tcle;
SELECT tcle_set_passphrase('my secret passphrase');
-- Test CREATE TABLE statement and implicit casts
CREATE TABLE t (p INTEGER, n ENCRYPT_NUMERIC, l ENCRYPT_TEXT, d ENCRYPT_TIMESTAMPTZ) USING tcleam;
INSERT INTO t SELECT i, i * 2, 'Text input number '||i, '2020-06-23 22:56:50'::TIMESTAMPTZ + make_interval(days => i) FROM generate_series(1, 10) i;
SELECT COUNT(*) FROM t;
SELECT p, n, l, d FROM t WHERE n = 6;
-- Test UPDATE statement
UPDATE t SET l = 'Updated text' WHERE n = 6;
SELECT COUNT(*) FROM t WHERE l ILIKE '%updated%';
-- Test VACUM FULL
VACUUM FULL t;
SELECT * FROM t WHERE l ILIKE '%updated%';
-- Test CREATE TABLE AS statement
CREATE TABLE t2 (n, l, d) USING tcleam AS SELECT n, l, d FROM t WHERE n > 6;
SELECT * FROM t2;
-- After t2 been dropped, attached record from KMS table should have been
-- deleted
DROP TABLE t2;
SELECT COUNT(*) FROM tcle_table_keys WHERE relname = 't2';
-- Test row access by index scan
CREATE TABLE t_i (i INTEGER PRIMARY KEY, l ENCRYPT_TEXT) USING tcleam;
INSERT INTO t_i SELECT n, 'Message n°'||n FROM generate_series(1, 10) n;
SET enable_seqscan TO off;
SELECT * FROM t_i WHERE i = 5;
-- Setting a new passphrase when a master key is already in use should raise
-- an error
SELECT tcle_set_passphrase('wrong secret passphrase');
