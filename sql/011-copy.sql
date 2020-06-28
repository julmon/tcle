SET search_path TO public, s1;
CREATE TABLE t_cpy (id ENCRYPT_NUMERIC, label ENCRYPT_TEXT, date ENCRYPT_TIMESTAMPTZ) USING tcleam;;
COPY t_cpy (id, label, date) FROM stdin DELIMITER ';';
1;Message for copy n°1;2020-06-29 21:47:10.25555+02
2;Message for copy n°2;2020-06-30 21:47:10.25555+02
3;Message for copy n°3;2020-07-01 21:47:10.25555+02
4;Message for copy n°4;2020-07-02 21:47:10.25555+02
5;Message for copy n°5;2020-07-03 21:47:10.25555+02
6;Message for copy n°6;2020-07-04 21:47:10.25555+02
7;Message for copy n°7;2020-07-05 21:47:10.25555+02
8;Message for copy n°8;2020-07-06 21:47:10.25555+02
9;Message for copy n°9;2020-07-07 21:47:10.25555+02
10;Message for copy n°10;2020-07-08 21:47:10.25555+02
11;Message for copy n°11;2020-07-09 21:47:10.25555+02
12;Message for copy n°12;2020-07-10 21:47:10.25555+02
13;Message for copy n°13;2020-07-11 21:47:10.25555+02
14;Message for copy n°14;2020-07-12 21:47:10.25555+02
15;Message for copy n°15;2020-07-13 21:47:10.25555+02
\.
SELECT * FROM t_cpy ORDER BY id ASC;
COPY t_cpy TO '/dev/null';
