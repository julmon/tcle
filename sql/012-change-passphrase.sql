SET search_path TO public, s1;
-- Changing the passphrase is not allowed in a transaction block, an error is
-- raised
BEGIN;
SELECT tcle_change_passphrase('my secret passphrase', 'new passphrase');
ROLLBACK;
-- First argument must be the current passphrase, an error is raised
SELECT tcle_change_passphrase('wrong passphrase', 'new passphrase');
-- Success
SELECT tcle_change_passphrase('my secret passphrase', 'new passphrase');
-- Should fail with the old passphrase
SELECT tcle_set_passphrase('my secret passphrase');
-- Success
SELECT tcle_set_passphrase('new passphrase');
