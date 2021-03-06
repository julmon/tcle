/*----------------------------------------------------------------------------
 *
 *                         Key Management System
 *
 * Portions Copyright (c) 2020, Julien Tachoires
 *
 * IDENTIFICATION
 *	  kms.c
 *
 *----------------------------------------------------------------------------
 */

#include "postgres.h"
#include "catalog/namespace.h"
#if (PG_VERSION_NUM >= 120000 && PG_VERSION_NUM < 130000)
#include "catalog/pg_type_d.h"
#endif
#include "commands/extension.h"
#include "executor/spi.h"
#include "utils/lsyscache.h"

#include "aes.h"
#include "kms.h"
#include "utils.h"

/*
 * Allocates a new KMSKeyAction struct and intializes it.
 */
KMSKeyAction *
new_kkact(void)
{
	KMSKeyAction   *kkact = (KMSKeyAction *) palloc(sizeof(KMSKeyAction));

	kkact->relid = InvalidOid;	/* table oid */
	kkact->nspid = InvalidOid;	/* schema oid */
	kkact->relname = NULL;		/* table name */
	kkact->nspname = NULL;		/* schema name */
	kkact->new_nspname = NULL;	/* new table name */
	kkact->new_relname = NULL;	/* new schema name */
	kkact->ctas_key = NULL;		/* CREATE TABLE AS transient key */

	return kkact;
}

/*
 * Returns a new KMSKeyAction filled with relation's name, id, namespace name
 * and namespace id. If the namespace name hasn't been specified earlier, we
 * need to find it. As far as this function is called by the process utility
 * hook function, we don't need to raise error if relation name or namespace do
 * not exist: standard_processUtility() is already doing this job.
 */
KMSKeyAction *
RelationGetKMSKeyAction(RangeVar *rel)
{
	KMSKeyAction   *kkact = new_kkact();
	char		   *nspname;

	if (rel->schemaname)
	{
		kkact->relname = strdup(rel->relname);
		kkact->nspname = strdup(rel->schemaname);

		kkact->nspid = get_namespace_oid(kkact->nspname, true);

		if (OidIsValid(kkact->nspid))
			kkact->relid = get_relname_relid(kkact->relname, kkact->nspid);
	}
	else
	{
		/*
		 * Get relid from current search_path.
		 */
		kkact->relname = strdup(rel->relname);
		kkact->relid = RelnameGetRelid(kkact->relname);

		if (OidIsValid(kkact->relid))
			kkact->nspid = get_rel_namespace(kkact->relid);
		if (OidIsValid(kkact->nspid) &&
				(nspname = get_namespace_name(kkact->nspid)) != NULL)
			kkact->nspname = strdup(nspname);
	}

	return kkact;
}

/*
 * Apply KMS actions that have been built during process utility hook function
 * execution. When a new table using tcleam access method is created, the
 * action will be: generate a random AES key, encrypt this key with the master
 * key and insert a new row in KMS table (tcle_table_keys). On drop table DDL,
 * we have to delete the corresponding row from KMS table. Finally, when a
 * table or a namespace is renamed, we need to apply this change to KMS table.
 */
void
ApplyKMSKeyActions(List *actions, unsigned char *master_key)
{

	ListCell   *cell;

	foreach(cell, actions)
	{
		KMSKeyAction *kkact = (KMSKeyAction *) lfirst(cell);

		switch (kkact->action_tag)
		{
			case AT_ADD_KEY:
			case AT_ADD_CTAS_KEY:
			{
				/*
				 * Table using tcleam AM creation case: we have to build a new
				 * random AES key, encrypt it with the master key and store it
				 * into KMS table.
				 */
				bytea		   *cipher_key;
				bool			res;
				unsigned char	iv[AES_IVLEN];
				unsigned char	plain_key[AES_KEYLEN];
				int				crypt_len;

				cipher_key = (bytea *) palloc(VARHDRSZ + AES_IVLEN + AES_KEYLEN
											  + AES_BLOCKLEN);

				/* Generate random IV and AES key */
				if (!pg_strong_random(iv, AES_IVLEN))
				{
					ereport(ERROR,
							(errmsg("tcle: could not generate random AES IV")));
				}
				memcpy(VARDATA(cipher_key), iv, AES_IVLEN);

				if (kkact->action_tag == AT_ADD_KEY)
				{
					if (!pg_strong_random(plain_key, AES_KEYLEN))
					{
						ereport(ERROR,
								(errmsg("tcle: could not generate random key")));
					}
				}
				else if (kkact->action_tag == AT_ADD_CTAS_KEY)
				{
					/*
					 * In CREATE TABLE AS context, transient key has been
					 * already generated and used to encrypt data. So, we have
					 * to store this key into KMS table now.
					 */
					if (kkact->ctas_key == NULL)
						ereport(ERROR,
								(errmsg("tcle: transient CTAS key not set")));

					memcpy(plain_key, kkact->ctas_key, AES_KEYLEN);
				}

				/* AES encryption of the key */
				crypt_len = AES_CBC_encrypt(plain_key,
											AES_KEYLEN,
											master_key,
											iv,
											(unsigned char *) VARDATA(cipher_key)
											+ AES_IVLEN);
				if (crypt_len == -1)
					ereport(ERROR,
							(errmsg("tcle: could not encrypt table key")));

				SET_VARSIZE(cipher_key, crypt_len + VARHDRSZ + AES_IVLEN);

				/* Insert a new entry into KMS table */
				res = AddKMSCipherKey(kkact->nspname, kkact->relname,
									  cipher_key);
				if (!res)
					ereport(ERROR,
							(errmsg("tcle: could not save table key")));

				pfree(cipher_key);

				break;
			}

			case AT_DEL_KEY:
			{
				if (!DeleteKMSKey(kkact->nspname, kkact->relname))
					ereport(ERROR,
							(errmsg("tcle: could not delete table key")));
				break;
			}

			case AT_MOV_KEY:
			{
				if (kkact->new_relname != NULL)
				{
					if (!MoveKMSKey(kkact->nspname, kkact->relname,
									kkact->new_relname))
						ereport(ERROR,
								(errmsg("tcle: could not change table key relname")));
				}
				else if (kkact->new_nspname != NULL)
				{
					if (!MoveNamespaceKMSKey(kkact->nspname, kkact->relname,
											 kkact->new_nspname))
						ereport(ERROR,
								(errmsg("tcle: could not change table key nspname")));
				}
				break;
			}

			case AT_DEL_NSP_KEY:
			{
				if (!DeleteNamespaceKMSKeys(kkact->nspname))
					ereport(ERROR,
							(errmsg("tcle: could not delete table keys by nspname")));
				break;
			}

			case AT_MOV_NSP_KEY:
			{
				if (!MoveNamespaceKMSKeys(kkact->nspname, kkact->new_nspname))
					ereport(ERROR,
							(errmsg("tcle: could not change table keys nspname")));
				break;
			}

			default:
			{
				break;
			}
		}
		pfree(kkact);
	}
}

/*
 * Insert a new entry into KMS table.
 */
bool
AddKMSCipherKey(char *nspname, char *relname, bytea *cipher_key)
{
	int				spi_res;
	Oid			   *argstypes;
	Datum		   *values;
	const char	   *nulls;
	const char	   *query;
	Oid				extensionId;
	Oid				namespaceId;
	char		   *namespaceName;

	/* Fetch extension namespace name */
	extensionId = get_extension_oid("tcle", false);
	namespaceId = get_extension_schema(extensionId);
	namespaceName = get_namespace_name(namespaceId);

	if (SPI_connect() != SPI_OK_CONNECT)
		return false;

	argstypes = (Oid *) palloc(sizeof(Oid) * 3);
	values = (Datum *) palloc(sizeof(Datum) * 3);
	nulls = NULL;

	argstypes[0] = NAMEOID;
	argstypes[1] = NAMEOID;
	argstypes[2] = BYTEAOID;

	values[0] = CStringGetDatum(nspname);
	values[1] = CStringGetDatum(relname);
	values[2] = PointerGetDatum(cipher_key);

	query = "INSERT INTO \"%s\".tcle_table_keys (nspname, relname, cipher_key) "
			"VALUES ($1, $2, $3)";

	spi_res = SPI_execute_with_args(psprintf(query, namespaceName), 3,
									argstypes, values, nulls, false, 0);

	pfree(argstypes);
	pfree(values);

	SPI_finish();

	return (spi_res == SPI_OK_INSERT);
}

/*
 * Delete an entry from KMS table.
 */
bool
DeleteKMSKey(char *nspname, char *relname)
{
	int				spi_res;
	Oid			   *argstypes;
	Datum		   *values;
	const char	   *nulls;
	const char	   *query;
	Oid				extensionId;
	Oid				namespaceId;
	char		   *namespaceName;

	/* Fetch extension namespace name */
	extensionId = get_extension_oid("tcle", false);
	namespaceId = get_extension_schema(extensionId);
	namespaceName = get_namespace_name(namespaceId);

	if (SPI_connect() != SPI_OK_CONNECT)
		return false;

	argstypes = (Oid *) palloc(sizeof(Oid) * 2);
	values = (Datum *) palloc(sizeof(Datum) * 2);
	nulls = NULL;

	argstypes[0] = NAMEOID;
	argstypes[1] = NAMEOID;

	values[0] = CStringGetDatum(nspname);
	values[1] = CStringGetDatum(relname);

	query = "DELETE FROM \"%s\".tcle_table_keys "
			"WHERE nspname = $1 AND relname = $2";

	spi_res = SPI_execute_with_args(psprintf(query, namespaceName), 2,
									argstypes, values, nulls, false, 0);

	pfree(argstypes);
	pfree(values);

	SPI_finish();

	return (spi_res == SPI_OK_DELETE);
}

/*
 * Change relname of a KMS table entry.
 */
bool
MoveKMSKey(char *nspname, char *relname, char *new_relname)
{
	int				spi_res;
	Oid			   *argstypes;
	Datum		   *values;
	const char	   *nulls;
	const char	   *query;
	Oid				extensionId;
	Oid				namespaceId;
	char		   *namespaceName;

	/* Fetch extension namespace name */
	extensionId = get_extension_oid("tcle", false);
	namespaceId = get_extension_schema(extensionId);
	namespaceName = get_namespace_name(namespaceId);

	if (SPI_connect() != SPI_OK_CONNECT)
		return false;

	argstypes = (Oid *) palloc(sizeof(Oid) * 3);
	values = (Datum *) palloc(sizeof(Datum) * 3);
	nulls = NULL;

	argstypes[0] = NAMEOID;
	argstypes[1] = NAMEOID;
	argstypes[2] = NAMEOID;

	values[0] = CStringGetDatum(nspname);
	values[1] = CStringGetDatum(relname);
	values[2] = CStringGetDatum(new_relname);

	query = "UPDATE \"%s\".tcle_table_keys SET relname = $3 "
			"WHERE nspname = $1 AND relname = $2";

	spi_res = SPI_execute_with_args(psprintf(query, namespaceName), 3,
									argstypes, values, nulls, false, 0);

	pfree(argstypes);
	pfree(values);

	SPI_finish();

	return (spi_res == SPI_OK_UPDATE);
}

/*
 * Change nspname of a KMS table entry.
 */
bool
MoveNamespaceKMSKey(char *nspname, char *relname, char *new_nspname)
{
	int				spi_res;
	Oid			   *argstypes;
	Datum		   *values;
	const char	   *nulls;
	const char	   *query;
	Oid				extensionId;
	Oid				namespaceId;
	char		   *namespaceName;

	/* Fetch extension namespace name */
	extensionId = get_extension_oid("tcle", false);
	namespaceId = get_extension_schema(extensionId);
	namespaceName = get_namespace_name(namespaceId);

	if (SPI_connect() != SPI_OK_CONNECT)
		return false;

	argstypes = (Oid *) palloc(sizeof(Oid) * 3);
	values = (Datum *) palloc(sizeof(Datum) * 3);
	nulls = NULL;

	argstypes[0] = NAMEOID;
	argstypes[1] = NAMEOID;
	argstypes[2] = NAMEOID;

	values[0] = CStringGetDatum(nspname);
	values[1] = CStringGetDatum(relname);
	values[2] = CStringGetDatum(new_nspname);

	query = "UPDATE \"%s\".tcle_table_keys SET nspname = $3 "
			"WHERE nspname = $1 AND relname = $2";

	spi_res = SPI_execute_with_args(psprintf(query, namespaceName), 3,
									argstypes, values, nulls, false, 0);

	pfree(argstypes);
	pfree(values);

	SPI_finish();

	return (spi_res == SPI_OK_UPDATE);
}

/*
 * Change nspname of a set of KMS table entries.
 */
bool
MoveNamespaceKMSKeys(char *nspname, char *new_nspname)
{
	int				spi_res;
	Oid			   *argstypes;
	Datum		   *values;
	const char	   *nulls;
	const char	   *query;
	Oid				extensionId;
	Oid				namespaceId;
	char		   *namespaceName;

	/* Fetch extension namespace name */
	extensionId = get_extension_oid("tcle", false);
	namespaceId = get_extension_schema(extensionId);
	namespaceName = get_namespace_name(namespaceId);

	if (SPI_connect() != SPI_OK_CONNECT)
		return false;

	argstypes = (Oid *) palloc(sizeof(Oid) * 2);
	values = (Datum *) palloc(sizeof(Datum) * 2);
	nulls = NULL;

	argstypes[0] = NAMEOID;
	argstypes[1] = NAMEOID;

	values[0] = CStringGetDatum(nspname);
	values[1] = CStringGetDatum(new_nspname);

	query = "UPDATE \"%s\".tcle_table_keys SET nspname = $2 WHERE nspname = $1";

	spi_res = SPI_execute_with_args(psprintf(query, namespaceName), 2,
									argstypes, values, nulls, false, 0);

	pfree(argstypes);
	pfree(values);

	SPI_finish();

	return (spi_res == SPI_OK_UPDATE);
}

/*
 * Delete entries from KMS table, based on nspname.
 */
bool
DeleteNamespaceKMSKeys(char *nspname)
{
	int				spi_res;
	Oid			   *argstypes;
	Datum		   *values;
	const char	   *nulls;
	const char	   *query;
	Oid				extensionId;
	Oid				namespaceId;
	char		   *namespaceName;

	/* Fetch extension namespace name */
	extensionId = get_extension_oid("tcle", false);
	namespaceId = get_extension_schema(extensionId);
	namespaceName = get_namespace_name(namespaceId);

	if (SPI_connect() != SPI_OK_CONNECT)
		return false;

	argstypes = (Oid *) palloc(sizeof(Oid) * 1);
	values = (Datum *) palloc(sizeof(Datum) * 1);
	nulls = NULL;

	argstypes[0] = NAMEOID;

	values[0] = CStringGetDatum(nspname);

	query = "DELETE FROM \"%s\".tcle_table_keys WHERE nspname = $1";

	spi_res = SPI_execute_with_args(psprintf(query, namespaceName), 1,
									argstypes, values, nulls, false, 0);

	pfree(argstypes);
	pfree(values);

	SPI_finish();

	return (spi_res == SPI_OK_DELETE);
}

/*
 * Read table's cipher key from KMS table.
 */
bool
GetKMSCipherKey(Oid relid, bytea **cipher_keyPtr)
{
	int				spi_res;
	Oid			   *argstypes;
	Datum		   *values;
	const char	   *nulls;
	const char	   *query;
	bool			isNull;
	Datum			res_data;
	int				data_len;
	Oid				extensionId;
	Oid				namespaceId;
	char		   *namespaceName;

	/* Fetch extension namespace name */
	extensionId = get_extension_oid("tcle", false);
	namespaceId = get_extension_schema(extensionId);
	namespaceName = get_namespace_name(namespaceId);

	if (SPI_connect() != SPI_OK_CONNECT)
		return false;

	argstypes = (Oid *) palloc(sizeof(Oid));
	values = (Datum *) palloc(sizeof(Datum));
	nulls = NULL;

	argstypes[0] = OIDOID;
	values[0] = ObjectIdGetDatum(relid);

	query = "SELECT cipher_key FROM \"%s\".tcle_table_keys "
			"WHERE (nspname||'.'||relname)::regclass::oid = $1";

	spi_res = SPI_execute_with_args(psprintf(query, namespaceName), 1,
									argstypes, values, nulls, true, 0);

	pfree(argstypes);
	pfree(values);

	if (SPI_processed != 1 || spi_res != SPI_OK_SELECT)
	{
		SPI_finish();
		return false;
	}

	res_data = heap_getattr(SPI_tuptable->vals[0], 1, SPI_tuptable->tupdesc,
							&isNull);

	data_len = VARSIZE_ANY(res_data) - 1; /* header size is 1, not VARHDRSZ */
	memcpy(*cipher_keyPtr, (bytea *) VARDATA_ANY(res_data), data_len);

	SPI_finish();

	return true;
}

/*
 * Decrypt a cipher key coming from KMS table.
 */
bool
DecryptKMSCipherKey(bytea *cipher_key,
					unsigned char *master_key,
					unsigned char **plain_keyPtr)
{
	unsigned char	iv[AES_IVLEN];
	int				crypt_len;

	*plain_keyPtr = (unsigned char *) palloc(AES_KEYLEN + AES_BLOCKLEN);
	/* Get AES IV */
	memcpy(iv, (unsigned char *) cipher_key, AES_IVLEN);

	/* AES decryption */
	crypt_len = AES_CBC_decrypt((unsigned char *) cipher_key + AES_IVLEN,
								AES_KEYLEN + AES_BLOCKLEN, master_key, iv,
								*plain_keyPtr);
	return (crypt_len != -1);
}

/*
 * Check input master key by fetching table keys from KMS table and try to
 * decrypt them one by one, the goal here is ensure that there is no other
 * master key already in use, ie: no table key been previously encrypted with
 * another master key.
 */
bool
CheckKMSMasterKey(unsigned char *master_key)
{
	int				spi_res;
	const char	   *query;
	bool			isNull;
	Datum			res_data;
	unsigned char  *plain_buffer;
	Oid				extensionId;
	Oid				namespaceId;
	char		   *namespaceName;

	/* Fetch extension namespace name */
	extensionId = get_extension_oid("tcle", false);
	namespaceId = get_extension_schema(extensionId);
	namespaceName = get_namespace_name(namespaceId);

	if (SPI_connect() != SPI_OK_CONNECT)
		ereport(ERROR, (errmsg("tcle: could not connect to SPI interface")));

	query = "SELECT cipher_key FROM \"%s\".tcle_table_keys";

	spi_res = SPI_execute(psprintf(query, namespaceName), true, 0);

	if (spi_res != SPI_OK_SELECT)
	{
		SPI_finish();
		ereport(ERROR, (errmsg("tcle: KMS table lookup failed")));
	}

	for (int i=0; i < SPI_processed; i++)
	{
		res_data = heap_getattr(SPI_tuptable->vals[i], 1, SPI_tuptable->tupdesc,
								&isNull);

		if (!DecryptKMSCipherKey((bytea *) VARDATA_ANY(res_data), master_key,
								 &plain_buffer))
		{
			pfree(plain_buffer);
			SPI_finish();
			return false;
		}
		pfree(plain_buffer);
	}
	SPI_finish();
	return true;
}

/*
 * Applies master key rotation at KMS table level by reencrypting table keys
 * with the new master key.
 */
void
ChangeKMSMasterKey(unsigned char *master_key, unsigned char *new_master_key)
{
	int				spi_res;
	const char	   *query;
	bool			isNull;
	Oid				extensionId;
	Oid				namespaceId;
	char		   *namespaceName;
	SPITupleTable  *tuptable;
	uint64			numvals;

	/* Fetch extension namespace name */
	extensionId = get_extension_oid("tcle", false);
	namespaceId = get_extension_schema(extensionId);
	namespaceName = get_namespace_name(namespaceId);

	if (SPI_connect() != SPI_OK_CONNECT)
		ereport(ERROR, (errmsg("tcle: could not connect to SPI interface")));

	/*
	 * Hold an exclusive lock on KMS table to prevent race condition when a
	 * long table creation DDL transaction is running and a master key rotation
	 * is asked in the same time. Without this exclusive lock, this situation
	 * will lead to have the brand new table key encrypted with the previous
	 * master key and all the other table keys encrypted with the new master
	 * key, which is a dramatical issue because we won't be able to decrypt
	 * all the table keys with the new master key.
	 */
	query = "LOCK TABLE \"%s\".tcle_table_keys IN EXCLUSIVE MODE NOWAIT";
	spi_res = SPI_execute(psprintf(query, namespaceName), false, 0);

	/* Get the list of table keys */
	query = "SELECT nspname, relname, cipher_key "
			"FROM \"%s\".tcle_table_keys ";
	spi_res = SPI_execute(psprintf(query, namespaceName), true, 0);

	if (spi_res != SPI_OK_SELECT)
	{
		SPI_finish();
		ereport(ERROR, (errmsg("tcle: KMS table lookup failed")));
	}

	if (SPI_tuptable == NULL)
	{
		SPI_finish();
		return;
	}

	tuptable = SPI_tuptable;
#if (PG_VERSION_NUM < 130000)
	numvals = SPI_processed;
#else
	numvals = tuptable->numvals;
#endif
	/*
	 * For each row from KMS table we must decrypt cipher key with the old
	 * master key and reencrypt the plain key with the new master key, BTW, a
	 * new random IV is built.
	 */
	for (int i=0; i < numvals; i++)
	{
		Oid			   *argstypes;
		Datum		   *values;
		const char	   *nulls;
		int				spi_res_upd;
		unsigned char  *plain_key;
		bytea		   *new_cipher_key;
		unsigned char	iv[AES_IVLEN];
		int				crypt_len;
		Datum			cipher_key,
						nspname,
						relname;
		const char	   *upd_query;

		/* Fetch relation namespace, name and cipher key */
		nspname = heap_getattr(tuptable->vals[i], 1, tuptable->tupdesc,
							   &isNull);
		relname = heap_getattr(tuptable->vals[i], 2, tuptable->tupdesc,
							   &isNull);
		cipher_key = heap_getattr(tuptable->vals[i], 3, tuptable->tupdesc,
								  &isNull);

		/* Decrypt table cipher key with current master key */
		if (!DecryptKMSCipherKey((bytea *) VARDATA_ANY(cipher_key),
								 master_key, &plain_key))
			ereport(ERROR, (errmsg("tcle: could not decrypt table key")));

		/* Generate new random IV */
		if (!pg_strong_random(iv, AES_IVLEN))
			ereport(ERROR, (errmsg("tcle: could not generate random AES IV")));

		new_cipher_key = (bytea *) palloc(VARHDRSZ + AES_IVLEN + AES_KEYLEN
										  + AES_BLOCKLEN);
		memcpy(VARDATA(new_cipher_key), iv, AES_IVLEN);

		/* AES encryption of the table key with new IV and master key */
		crypt_len = AES_CBC_encrypt(plain_key, AES_KEYLEN, new_master_key, iv,
									(unsigned char *) VARDATA(new_cipher_key)
									+ AES_IVLEN);
		if (crypt_len == -1)
			ereport(ERROR, (errmsg("tcle: could not encrypt table key")));

		SET_VARSIZE(new_cipher_key, crypt_len + VARHDRSZ + AES_IVLEN);

		argstypes = (Oid *) palloc(sizeof(Oid) * 3);
		values = (Datum *) palloc(sizeof(Datum) * 3);
		nulls = NULL;

		argstypes[0] = BYTEAOID;
		argstypes[1] = NAMEOID;
		argstypes[2] = NAMEOID;

		values[0] = PointerGetDatum(new_cipher_key);
		values[1] = CStringGetDatum(nspname);
		values[2] = CStringGetDatum(relname);

		upd_query = "UPDATE \"%s\".tcle_table_keys SET cipher_key = $1 "
					"WHERE nspname = $2 AND relname = $3";

		spi_res_upd = SPI_execute_with_args(psprintf(upd_query, namespaceName),
											3, argstypes, values, nulls, false,
											0);

		if (spi_res_upd != SPI_OK_UPDATE)
			ereport(ERROR, (errmsg("tcle: could not update table cipher key")));

		/* Memory clean up */
		pfree(argstypes);
		pfree(values);
		pfree(plain_key);
		pfree(new_cipher_key);
	}

	SPI_finish();
}

/*
 * Get table's key from shared memory, returns true if found.
 */
bool
CacheGetRelationKey(ShmemKMSKeyCache *shmkeycache,
					Oid datid,
					Oid relid,
					unsigned char **keyPtr)
{
	bool		found = false;

	LWLockAcquire(shmkeycache->lock, LW_SHARED);
	for (int i=0; i < shmkeycache->n_entries; i++)
	{
		if (shmkeycache->buffer[i].datid == datid
				&& shmkeycache->buffer[i].relid == relid)
		{
			memcpy(*keyPtr, shmkeycache->buffer[i].key, AES_KEYLEN);
			found = true;
			break;
		}
	}
	LWLockRelease(shmkeycache->lock);

	return found;
}

/*
 * Add table's key into shared memory.
 */
void
CacheAddRelationKey(ShmemKMSKeyCache *shmkeycache,
					Oid datid,
					Oid relid,
					unsigned char *key)
{
	LWLockAcquire(shmkeycache->lock, LW_EXCLUSIVE);

	/* Handler wraparound */
	if (unlikely(shmkeycache->position == (KMS_CACHE_SIZE - 1)))
		shmkeycache->position = 0;
	else
		shmkeycache->position++;

	shmkeycache->buffer[shmkeycache->position].relid = relid;
	shmkeycache->buffer[shmkeycache->position].datid = datid;
	memcpy(shmkeycache->buffer[shmkeycache->position].key, key, AES_KEYLEN);

	if (shmkeycache->n_entries < (KMS_CACHE_SIZE - 1))
		shmkeycache->n_entries++;

	LWLockRelease(shmkeycache->lock);
}

/*
 * Get database's master key from shared memory hash tab.
 */
bool
GetDatabaseMasterKey(ShmemKMSMasterKeysLock *shmmasterkeyslock,
					 HTAB *shmmasterkeys,
					 Oid datid,
					 unsigned char **master_keyPtr)
{
	bool		found;
	KMSMasterKeysEntry *entry;
	KMSMasterKeysHashKey hkey = datid;

	LWLockAcquire(shmmasterkeyslock->lock, LW_SHARED);

	entry = (KMSMasterKeysEntry *) hash_search(shmmasterkeys, &hkey, HASH_FIND,
											   &found);
	LWLockRelease(shmmasterkeyslock->lock);

	if (!found)
		return false;

	memcpy(*master_keyPtr, entry->master_key, AES_KEYLEN);

	return true;
}

/*
 * Add database's master key into shmem hash tab.
 */
void
AddDatabaseMasterKey(ShmemKMSMasterKeysLock *shmmasterkeyslock,
					 HTAB *shmmasterkeys,
					 Oid datid,
					 unsigned char master_key[AES_KEYLEN])
{
	KMSMasterKeysEntry *entry;
	KMSMasterKeysHashKey hkey = datid;

	LWLockAcquire(shmmasterkeyslock->lock, LW_EXCLUSIVE);

	entry = (KMSMasterKeysEntry *) hash_search(shmmasterkeys, &hkey, HASH_ENTER,
											   NULL);
	memcpy(entry->master_key, master_key, AES_KEYLEN);

	LWLockRelease(shmmasterkeyslock->lock);
}

/*
 * Remove database's master key from shmem hash tab if exists.
 */
void
RemoveDatabaseMasterKey(ShmemKMSMasterKeysLock *shmmasterkeyslock,
						HTAB *shmmasterkeys,
						Oid datid)
{
	KMSMasterKeysHashKey hkey = datid;

	LWLockAcquire(shmmasterkeyslock->lock, LW_EXCLUSIVE);

	hash_search(shmmasterkeys, &hkey, HASH_REMOVE, NULL);

	LWLockRelease(shmmasterkeyslock->lock);
}

/*
 * Update database's master key from shmem hash tab. Caller is responsible of
 * lock acquisition.
 */
void
UpdateDatabaseMasterKey(HTAB *shmmasterkeys, Oid datid,
						unsigned char new_master_key[AES_KEYLEN])
{
	KMSMasterKeysEntry *entry;
	KMSMasterKeysHashKey hkey = datid;

	/* Remove the entry if exists then add a new entry */
	hash_search(shmmasterkeys, &hkey, HASH_REMOVE, NULL);
	entry = (KMSMasterKeysEntry *) hash_search(shmmasterkeys, &hkey,
											   HASH_ENTER, NULL);
	memcpy(entry->master_key, new_master_key, AES_KEYLEN);
}
