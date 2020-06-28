SET search_path TO public, s1;
-- After t2 been dropped, attached record from KMS table should have been
-- deleted
DROP TABLE t2;
SELECT COUNT(*) FROM tcle_table_keys WHERE relname = 't2';
