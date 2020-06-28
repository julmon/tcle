SET search_path TO public, s1;
-- Test row access by index scan
CREATE TABLE t_i (i INTEGER PRIMARY KEY, l ENCRYPT_TEXT) USING tcleam;
INSERT INTO t_i SELECT n, 'Message n°'||n FROM generate_series(1, 10) n;
SET enable_seqscan TO off;
SELECT * FROM t_i WHERE i = 5;
DROP TABLE t_i;
SET enable_seqscan TO on;
