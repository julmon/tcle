SET search_path TO public, s1;
-- Test opertor classes
SELECT * FROM t WHERE n >= 50 ORDER BY n DESC;
SELECT * FROM t WHERE l < 'Text input number 3' ORDER BY l DESC;
SELECT * FROM t WHERE d > '2020-08-01 00:00:00' ORDER BY d DESC;
