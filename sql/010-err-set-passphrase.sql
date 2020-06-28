SET search_path TO public, s1;
-- Trying to set  a new passphrase when a master key is already in use should
-- raise an error
SELECT tcle_set_passphrase('wrong secret passphrase');
