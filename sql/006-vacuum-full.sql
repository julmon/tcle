SET search_path TO public, s1;
-- Test VACUM FULL
VACUUM FULL t;
SELECT * FROM t WHERE l ILIKE '%updated%';
