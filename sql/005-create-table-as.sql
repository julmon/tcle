SET search_path TO public, s1;
-- Test CREATE TABLE AS statement
CREATE TABLE t2 (n, l, d) USING tcleam AS SELECT n, l, d FROM t WHERE n > 6;
SELECT ctid, * FROM t2;
