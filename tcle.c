/*----------------------------------------------------------------------------
 *
 *                  Transparent Cell-Level Encryption
 *
 * Portions Copyright (c) 2020, Julien Tachoires
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * This extension implements a new Table Acces Method that extends core Heap AM
 * and applies tuples AES 256 bits CBC encryption / decryption on the fly when
 * column's type matches ENCRYPT_TEXT, ENCRYPT_NUMERIC or ENCRYPT_TIMESTAMPTZ.
 *
 * TCLE extension provides a lighweight key management system (KMS) based on
 * 2-tier architecture: 1 master key per database, 1 table key per user table.
 * Table keys are stored encrypted with database master key in a dedicated
 * table.
 *
 * IDENTIFICATION
 *	  tcle.c
 *
 *----------------------------------------------------------------------------
 */

#include "postgres.h"
#include "miscadmin.h"
#include "port.h"
#include "pgstat.h"
#include "access/genam.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/rewriteheap.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
#include "catalog/pg_am.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_type.h"
#include "common/sha2.h"
#include "commands/dbcommands.h"
#include "commands/progress.h"
#include "libpq/pqformat.h"
#include "storage/ipc.h"
#include "storage/lmgr.h"
#include "storage/bufmgr.h"
#include "storage/smgr.h"
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/datum.h"
#include "utils/fmgrprotos.h"
#include "utils/numeric.h"
#include "utils/syscache.h"

#include "tcleheap.h"
#include "aes.h"
#include "kms.h"

PG_MODULE_MAGIC;

/* Saved hook values in case of unload */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

/* Link to shared memory key */
static ShmemKMSMasterKeysLock *shmmasterkeyslock = NULL;
static ShmemKMSKeyCache *shmkeycache = NULL;
static HTAB	*shmmasterkeys = NULL;

extern Datum encrypt_text_in(PG_FUNCTION_ARGS);
extern Datum encrypt_text_out(PG_FUNCTION_ARGS);
extern Datum tcle_set_passphrase(PG_FUNCTION_ARGS);

static bool RelationAMIsTcleam(Oid relid);

void _PG_init(void);
void _PG_fini(void);

/* Hook function */
static void tcle_shmem_startup(void);
static void tcle_ProcessUtility(PlannedStmt *pstmt,
								const char *queryString,
								ProcessUtilityContext context,
								ParamListInfo params,
								QueryEnvironment *queryEnv,
								DestReceiver *dest,
								QueryCompletion *qc);

PG_FUNCTION_INFO_V1(tcleam_handler);
PG_FUNCTION_INFO_V1(encrypt_text_in);
PG_FUNCTION_INFO_V1(encrypt_text_out);
PG_FUNCTION_INFO_V1(encrypt_text_recv);
PG_FUNCTION_INFO_V1(encrypt_text_send);
PG_FUNCTION_INFO_V1(encrypt_numeric_in);
PG_FUNCTION_INFO_V1(encrypt_numeric_out);
PG_FUNCTION_INFO_V1(encrypt_numeric_recv);
PG_FUNCTION_INFO_V1(encrypt_numeric_send);
PG_FUNCTION_INFO_V1(encrypt_timestamptz_in);
PG_FUNCTION_INFO_V1(encrypt_timestamptz_out);
PG_FUNCTION_INFO_V1(encrypt_timestamptz_recv);
PG_FUNCTION_INFO_V1(encrypt_timestamptz_send);
PG_FUNCTION_INFO_V1(tcle_set_passphrase);

void
_PG_init(void)
{
	RequestNamedLWLockTranche("tcle", 2);

	/* Install hooks. */
	prev_shmem_startup_hook = shmem_startup_hook;
	prev_ProcessUtility = ProcessUtility_hook;

	shmem_startup_hook = tcle_shmem_startup;
	ProcessUtility_hook = tcle_ProcessUtility;
}

void
_PG_fini(void)
{
	/* Uninstall hooks. */
	shmem_startup_hook = prev_shmem_startup_hook;
	ProcessUtility_hook = prev_ProcessUtility;
}

static void
tcle_shmem_startup(void)
{
	bool		found;
	HASHCTL		info;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	/* Reset in case this is a restart within the postmaster */
	shmmasterkeyslock = NULL;
	shmkeycache = NULL;

	/* Create or attach to the shared memory state */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	/* Master keys htab lock */
	shmmasterkeyslock = ShmemInitStruct("tcle master keys htable lock",
										sizeof(shmmasterkeyslock),
										&found);

	if (!found)
	{
		shmmasterkeyslock->lock = &(GetNamedLWLockTranche("tcle")[0].lock);
	}
	memset(&info, 0, sizeof(info));
	info.keysize = sizeof(KMSMasterKeysHashKey);
	info.entrysize = sizeof(KMSMasterKeysEntry);

	shmmasterkeys = ShmemInitHash("tcle master keys",
								  KMS_MAX_DATABASES,
								  KMS_MAX_DATABASES,
								  &info,
								  HASH_ELEM | HASH_BLOBS);

	shmkeycache = ShmemInitStruct("tcle key cache",
								  sizeof(ShmemKMSKeyCache),
								  &found);
	if (!found)
	{
		shmkeycache->lock = &(GetNamedLWLockTranche("tcle")[1].lock);
		shmkeycache->position = 0;
		shmkeycache->n_entries = 0;
	}
	LWLockRelease(AddinShmemInitLock);

	ereport(LOG, (errmsg("tcle: extension loaded")));
}

/*
 * Cache lookup function to check that relation access method is "tcleam"
 */
bool
RelationAMIsTcleam(Oid relid)
{
	Form_pg_class	classform;
	Form_pg_am		aform;
	HeapTuple		tuple_rel, tuple_am;

	tuple_rel = SearchSysCache1(RELOID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(tuple_rel))
		ereport(ERROR,
				(errmsg("tcle: cache lookup failed for relation %u", relid)));

	classform = (Form_pg_class) GETSTRUCT(tuple_rel);
	ReleaseSysCache(tuple_rel);

	if (!classform->relam)
		return false;

	tuple_am = SearchSysCache1(AMOID, ObjectIdGetDatum(classform->relam));
	if (!HeapTupleIsValid(tuple_am))
		ereport(ERROR,
				(errmsg("tcle: cache lookup failed for access method %u",
						classform->relam)));

	aform = (Form_pg_am) GETSTRUCT(tuple_am);
	ReleaseSysCache(tuple_am);

	return (strcmp(NameStr(aform->amname), "tcleam") == 0);
}

/*
 * ProcessUtility hook function in charge of triggering KMS actions when some
 * DDL related to tables using tcleam AM are executed. In some cases, like
 * removing or renaming, we must gather informations before the DDL is really
 * executed by standard_ProcessUtility(). In other cases, like table creation,
 * we must do it after.
 */
void
tcle_ProcessUtility(PlannedStmt *pstmt,
					const char *queryString,
					ProcessUtilityContext context,
					ParamListInfo params,
					QueryEnvironment *queryEnv,
					DestReceiver *dest,
					QueryCompletion *qc)
{
	Node		   *parsetree = pstmt->utilityStmt;
	List		   *actions = NIL;


	switch (nodeTag(parsetree))
	{
		case T_DropStmt:
		{
			/*
			 * Handle DROP TABLE and DROP SCHEMA
			 */

			DropStmt   *stmt;
			ListCell   *cell;

			stmt = (DropStmt *) parsetree;

			if (stmt->removeType == OBJECT_TABLE)
			{
				/*
				 * Handler DROP TABLE. In this case, we can take a look at
				 * table AM.
				 */
				foreach(cell, stmt->objects)
				{
					RangeVar	   *rel;
					KMSKeyAction   *kkact;

					rel = makeRangeVarFromNameList((List *) lfirst(cell));

					kkact = RelationGetKMSKeyAction(rel);

					if (!OidIsValid(kkact->relid)
							|| !RelationAMIsTcleam(kkact->relid))
					{
						pfree(kkact);
						continue;
					}

					kkact->action_tag = AT_DEL_KEY;
					actions = lappend(actions, kkact);
				}

			}
			else if(stmt->removeType == OBJECT_SCHEMA)
			{
				/*
				 * Handle DROP SCHEMA .. CASCADE. No deep inspection here, just
				 * keep a track of schema name, we'll see later if some keys
				 * must be removed.
				 */
				foreach(cell, stmt->objects)
				{
					Node		   *object = lfirst(cell);
					KMSKeyAction   *kkact = new_kkact();

					kkact->nspname = strdup(((Value *) object)->val.str);
					kkact->action_tag = AT_DEL_NSP_KEY;

					actions = lappend(actions, kkact);
				}

			}
			break;
		}

		case T_AlterObjectSchemaStmt:
		{
			/*
			 * Handle ALTER TABLE .. SET SCHEMA
			 */
			AlterObjectSchemaStmt   *stmt;

			stmt = (AlterObjectSchemaStmt *) parsetree;

			if (stmt->objectType == OBJECT_TABLE)
			{
				KMSKeyAction   *kkact;

				kkact = RelationGetKMSKeyAction(stmt->relation);

				if (!OidIsValid(kkact->relid)
						|| !RelationAMIsTcleam(kkact->relid))
				{
					pfree(kkact);
					break;
				}
				kkact->new_nspname = strdup(stmt->newschema);
				kkact->action_tag = AT_MOV_KEY;

				actions = lappend(actions, kkact);
			}
			break;
		}

		case T_RenameStmt:
		{
			/*
			 * Handle ALTER TABLE .. RENAME TO ..
			 */
			RenameStmt	   *stmt;

			stmt = (RenameStmt *) parsetree;

			if (stmt->renameType == OBJECT_TABLE)
			{
				KMSKeyAction   *kkact;
				kkact = RelationGetKMSKeyAction(stmt->relation);

				if (!OidIsValid(kkact->relid)
						|| !RelationAMIsTcleam(kkact->relid))
				{
					pfree(kkact);
					break;
				}
				kkact->new_relname = strdup(stmt->newname);
				kkact->action_tag = AT_MOV_KEY;

				actions = lappend(actions, kkact);
			}
			break;
		}

		case T_CreateTableAsStmt:
		{
			/*
			 * CREATE TABLE .. AS is a special case because we must generate
			 * and store a new AES key right before the DDL is executed by
			 * standard_ProcessUtility().
			 * At the moment, we don't support it.. but we'll have to at some
			 * point.
			 */
			CreateTableAsStmt  *stmt;

			stmt = (CreateTableAsStmt *) parsetree;

			if (stmt->into->accessMethod
					&& strcmp(stmt->into->accessMethod, "tcleam") == 0)
				ereport(ERROR,
						(errmsg("tcle: CREATE TABLE AS not supported for now")));
			break;
		}

		case T_DropdbStmt:
		{
			/*
			 * Handler DROP DATABASE. In this case, we just have to remove the
			 * key from shmem htab if exists.
			 */
			DropdbStmt *stmt;
			Oid			dbid;

			stmt = (DropdbStmt *) parsetree;

			/*
			 * Get database oid by its name and let standard_ProcessUtility()
			 * handle the error if not exists or the user is not the owner.
			 */
			dbid = get_database_oid(stmt->dbname, true);

			if (!OidIsValid(dbid))
				break;

			if (!pg_database_ownercheck(dbid, GetUserId()))
				break;

			/*
			 * Remove the entry from master keys htab if exists.
			 */
			RemoveDatabaseMasterKey(shmmasterkeyslock, shmmasterkeys, dbid);
			break;
		}

		default:
		{
			break;
		}
	}

	if (prev_ProcessUtility)
		prev_ProcessUtility(pstmt, queryString, context, params, queryEnv,
							dest, qc);
	else
		standard_ProcessUtility(pstmt, queryString, context, params, queryEnv,
								dest, qc);

	switch (nodeTag(parsetree))
	{
		case T_CreateStmt:
		{
			/*
			 * Handle CREATE TABLE
			 */
			CreateStmt	   *stmt;
			KMSKeyAction   *kkact;

			stmt = (CreateStmt *) parsetree;

			kkact = RelationGetKMSKeyAction(stmt->relation);

			if (!OidIsValid(kkact->relid)
					|| !RelationAMIsTcleam(kkact->relid))
			{
				pfree(kkact);
				break;
			}

			kkact->action_tag = AT_ADD_KEY;

			actions = lappend(actions, kkact);
			break;
		}

		case T_RenameStmt:
		{
			/*
			 * Handle ALTER SCHEMA .. RENAME TO ..
			 */
			RenameStmt	   *stmt;

			stmt = (RenameStmt *) parsetree;

			if (stmt->renameType == OBJECT_SCHEMA)
			{
				KMSKeyAction   *kkact = new_kkact();

				kkact->nspname = strdup(stmt->subname);
				kkact->new_nspname = strdup(stmt->newname);
				kkact->action_tag = AT_MOV_NSP_KEY;

				actions = lappend(actions, kkact);
			}
			break;
		}

		default:
		{
			break;
		}
	}

	if (actions != NIL)
	{
		unsigned char	*master_key;
		master_key = (unsigned char *) palloc(AES_KEYLEN);

		/* Get master key from shared memory */
		if (!GetDatabaseMasterKey(shmmasterkeyslock, shmmasterkeys,
								  MyDatabaseId, &master_key))
			ereport(ERROR,
					(errmsg("tcle: master key not found for this database")));

		/* Apply KMS changes */
		ApplyKMSKeyActions(actions, master_key);
	}
}

/*
 * encrypt_text type input function.
 */
Datum
encrypt_text_in(PG_FUNCTION_ARGS)
{
	char		*inputText = PG_GETARG_CSTRING(0);

	if (strlen(inputText) > 2048)
		ereport(ERROR,
				(errmsg("tcle: value too long for type encrypt_text, maximum "
						"allowed size is 2048 bytes")));

	PG_RETURN_TEXT_P(cstring_to_text(inputText));
}

/*
 * encrypt_text type output function.
 */
Datum
encrypt_text_out(PG_FUNCTION_ARGS)
{
	/*
	 * Ne need to go with DirectFunctionCall here, just call text type out
	 * function with fcinfo.
	 */
	return textout(fcinfo);
}

/*
 * Converts external binary format to encrypt_text
 */
Datum
encrypt_text_recv(PG_FUNCTION_ARGS)
{
	StringInfo  buf = (StringInfo) PG_GETARG_POINTER(0);
	text	   *result;
	char	   *str;
	int			nbytes;

	str = pq_getmsgtext(buf, buf->len - buf->cursor, &nbytes);

	if (nbytes > 2048)
	{
		pfree(str);
		ereport(ERROR,
				(errmsg("tcle: value too long for type encrypt_text, maximum "
						"allowed size is 2048 bytes")));
	}

	result = cstring_to_text_with_len(str, nbytes);
	pfree(str);
	PG_RETURN_TEXT_P(result);
}

/*
 * Converts encrypt_text to external binary format
 */
Datum
encrypt_text_send(PG_FUNCTION_ARGS)
{
	return textsend(fcinfo);
}

/*
 * encrypt_numeric type input function.
 */
Datum
encrypt_numeric_in(PG_FUNCTION_ARGS)
{
	return numeric_in(fcinfo);
}

/*
 * encrypt_numeric type output function.
 */
Datum
encrypt_numeric_out(PG_FUNCTION_ARGS)
{
	return numeric_out(fcinfo);
}

/*
 * Converts external binary format to encrypt_numeric
 */
Datum
encrypt_numeric_recv(PG_FUNCTION_ARGS)
{
	return numeric_recv(fcinfo);
}

/*
 * Converts encrypt_numeric to external binary format
 */
Datum
encrypt_numeric_send(PG_FUNCTION_ARGS)
{
	return numeric_send(fcinfo);
}

/*
 * encrypt_timestamptz type input function.
 *
 * Internal representation is Numeric because we need to use variable length
 * types when encrypting. Variable length types like Numeric allow us to have
 * extra bytes to store AES IV and padding.
 */
Datum
encrypt_timestamptz_in(PG_FUNCTION_ARGS)
{
	Datum		tstz = timestamptz_in(fcinfo);

	return DirectFunctionCall1(int8_numeric, DatumGetTimestampTz(tstz));
}

/*
 * encrypt_timestamptz type output function.
 */
Datum
encrypt_timestamptz_out(PG_FUNCTION_ARGS)
{
	Numeric		num_tstz = PG_GETARG_NUMERIC(0);
	Datum		int64_tstz;

	int64_tstz = DirectFunctionCall1(numeric_int8, NumericGetDatum(num_tstz));
	return DirectFunctionCall1(timestamptz_out, int64_tstz);
}

/*
 * Converts external binary format to encrypt_timestamptz
 */
Datum
encrypt_timestamptz_recv(PG_FUNCTION_ARGS)
{
	Datum		tstz = timestamptz_recv(fcinfo);

	return DirectFunctionCall1(int8_numeric, DatumGetTimestampTz(tstz));
}

/*
 * Converts encrypt_timestamptz to external binary format
 */
Datum
encrypt_timestamptz_send(PG_FUNCTION_ARGS)
{
	Numeric		num_tstz = PG_GETARG_NUMERIC(0);
	Datum		int64_tstz;

	int64_tstz = DirectFunctionCall1(numeric_int8, NumericGetDatum(num_tstz));
	return DirectFunctionCall1(timestamptz_send, int64_tstz);
}

/*
 * Unsecure (the passphrase could leak in logs) and temporary user function to
 * set a master key using a passphrase.
 * Master key is the result of hashing the passphrase with sha256.
 */
Datum
tcle_set_passphrase(PG_FUNCTION_ARGS)
{
	char		   *passPhrase = PG_GETARG_CSTRING(0);
	const uint8	   *data;
	size_t			len;
	pg_sha256_ctx	ctx;
	unsigned char	buf[PG_SHA256_DIGEST_LENGTH];
	unsigned char	master_key[AES_KEYLEN];

	/*
	 * ACL check against database: only the owner or a superuser can set a
	 * database master key.
	 */
	if (!pg_database_ownercheck(MyDatabaseId, GetUserId()))
		ereport(ERROR,
				(errmsg("tcle: only database owner and superusers are allowed "
						"to set the master key")));

	if (strlen(passPhrase) == 0)
		ereport(ERROR, (errmsg("tcle: passphrase should not be empty")));

	len = VARSIZE_ANY_EXHDR(passPhrase);
	data = (unsigned char *) VARDATA_ANY(passPhrase);

	/* Compute sha256 hash of the passphrase */
	pg_sha256_init(&ctx);
	pg_sha256_update(&ctx, data, len);
	pg_sha256_final(&ctx, buf);

	memcpy(&master_key, buf, sizeof(buf));

	/*
	 * We have to check if another master key is in use for this database,
	 * meaning: we have table keys in tcle_table_keys encrypted with another
	 * master key. If this is the case, we don't allow to set a new master
	 * key.
	 */
	if (!CheckKMSMasterKey(master_key))
		ereport(ERROR,
				(errmsg("tcle: another database master key is in use")));

	/*
	 * Remove from shmem previous master key if any. This can ben done safely
	 * because we're sure at this point that this key is not really in use.
	 */
	RemoveDatabaseMasterKey(shmmasterkeyslock, shmmasterkeys, MyDatabaseId);
	/* Add the brand new master key in shmem */
	AddDatabaseMasterKey(shmmasterkeyslock, shmmasterkeys, MyDatabaseId,
						 master_key);

	PG_RETURN_BOOL(true);
}

/*
 * Encrypt / decrypt tuple attributes from a TupleTableSlot.
 */
static void EncryptDecryptTupleTableSlot(TupleTableSlot *slot, int8 flag)
{
	/* Number of attributes (columns) */
	int				natts;
	/*
	 * Number of attributes corresponding to a candidate type for encryption /
	 * decryption
	 */
	int				natts_c_cryp = 0;
	/*
	 * Number of attributes that really have to be encrypted / decrypted,
	 * excluding null values
	 */
	int				natts_r_cryp = 0;
	/* encrypt_* type and namespace ids */
	Oid				encrypt_text_oid, encrypt_numeric_oid,
					encrypt_timestamptz_oid;

	Oid				namespace_oid;
	/* Variables for tuple manipulation */
	HeapTuple		tuple, new_tuple;
	BufferHeapTupleTableSlot *hslot;

	Datum		   *replvals;
	bool		   *replnuls;
	int			   *replcols;
	int				pos = 0;
	unsigned char  *table_key;
	bytea		   *table_cipher_key;

	natts = slot->tts_tupleDescriptor->natts;

	/* Get type Oid by its name and namespace */
	namespace_oid = get_namespace_oid("public", true);
	encrypt_text_oid = GetSysCacheOid2(TYPENAMENSP,
									   Anum_pg_type_oid,
									   PointerGetDatum("encrypt_text"),
									   ObjectIdGetDatum(namespace_oid));
	encrypt_numeric_oid = GetSysCacheOid2(TYPENAMENSP,
										  Anum_pg_type_oid,
										  PointerGetDatum("encrypt_numeric"),
										  ObjectIdGetDatum(namespace_oid));
	encrypt_timestamptz_oid = GetSysCacheOid2(TYPENAMENSP,
											  Anum_pg_type_oid,
											  PointerGetDatum("encrypt_timestamptz"),
											  ObjectIdGetDatum(namespace_oid));
	/*
	 * Quick attributes list lookup to see if any value should be encrypted /
	 * decrypted later. We need to know maximum number of attributes we will
	 * later update in heap to allocate memory for replvals, replnuls and
	 * replcols.
	 */
	for (int i=0; i < natts; i++)
	{
		Form_pg_attribute att = TupleDescAttr(slot->tts_tupleDescriptor, i);

		if (att->atttypid == encrypt_text_oid
				|| att->atttypid == encrypt_numeric_oid
				|| att->atttypid == encrypt_timestamptz_oid)
			natts_c_cryp++;
	}

	if (natts_c_cryp == 0)
		return;

	/* Fetch tuple from the slot */
	hslot = (BufferHeapTupleTableSlot *) slot;
	tuple = slot->tts_ops->get_heap_tuple(slot);

	table_key = (unsigned char *) palloc(AES_KEYLEN);

	/*
	 * Shared memory lookup for table's key. If not found then we have to load
	 * the master key and fetch table's cipher key from KMS table and finally
	 * push the table's key in shared memory.
	 */
	if (!CacheGetRelationKey(shmkeycache, MyDatabaseId, slot->tts_tableOid,
							 &table_key))
	{
		unsigned char	*master_key;
		master_key = (unsigned char *) palloc(AES_KEYLEN);

		/* Get master key from shared memory */
		if (!GetDatabaseMasterKey(shmmasterkeyslock, shmmasterkeys,
								  MyDatabaseId, &master_key))
			ereport(ERROR,
					(errmsg("tcle: master key not found for this database")));

		table_cipher_key = (bytea *) palloc(AES_IVLEN + AES_KEYLEN
											+ AES_BLOCKLEN);
		/* Load and decrypt table's key */
		if (!GetKMSCipherKey(slot->tts_tableOid, &table_cipher_key))
			ereport(ERROR, (errmsg("tcle: could not get table's key")));

		if (!DecryptKMSCipherKey(table_cipher_key, master_key, &table_key))
			ereport(ERROR,
					(errmsg("tcle: could not decrypt table's cipher key")));

		pfree(table_cipher_key);

		/* Add table's key in shared memory */
		CacheAddRelationKey(shmkeycache, MyDatabaseId, slot->tts_tableOid,
							table_key);
	}

	/* Allocate memory for the attributes we'll have to encrypt / decrypt */
	replvals = (Datum *) palloc(sizeof(Datum) *natts_c_cryp);
	replnuls = (bool *) palloc(sizeof(bool) *natts_c_cryp);
	replcols = (int *) palloc(sizeof(int) *natts_c_cryp);

	/*
	 * Loop through tuple descriptor attributes looking for ENCRYPT_* types
	 * and apply encrypt/decrypt on attribute value if not null.
	 */
	for (int i=0; i < natts; i++)
	{
		bool				isNull;
		Datum				attVal;
		/* Attribute value copy used for decryption */
		Datum				attValCpy;
		/*
		 * plaintext / ciphertext length returned by AES decryption /
		 * encryption functions.
		 */
		int					crypt_len;
		/*
		 * Char buffer where encryption / decryption results will be stored.
		 * To avoid further extra memory allocation, this buffer will be
		 * "transformed" as a Datum. We also have to store AES IV in it when
		 * encrypting.
		 * We need then to allocate more memory than plaintex / ciphertext only
		 * really require.
		 *
		 * After plaintext been encrypted, crypt_buffer contains :
		 *
		 * Alloc.  | 4B  |  16B   | plaintext size + padding (16B max) |
		 * - - - - +-----+--------+------------------------------------+
		 * Content | HDR | AES IV | CIPHERTEXT                         |
		 * - - - - +-----+--------+------------------------------------+
		 *
		 * After ciphertext been decrypted:
		 *
		 * Alloc.  | 4B  |          ciphertext size
		 * - - - - +-----+-----------------------------------+
		 * Content | HDR | PLAINTEXT                         |
		 * - - - - +-----+-----------------------------------+
		 *
		 * After encryption / decryption, Datum size is set according to real
		 * ciphertext / plaintext size that AES encryption / decrytion function
		 * returns.
		 */
		char			   *crypt_buffer;
		/* Input plaintext / ciphertext length */
		int					buffer_len;
		/* AES initialization vector */
		unsigned char		iv[AES_IVLEN];
		/* Tuple attribute description */
		Form_pg_attribute	att = TupleDescAttr(slot->tts_tupleDescriptor,
												 i);
		unsigned char	   *att_buffer;

		if (att->atttypid != encrypt_text_oid
				&& att->atttypid != encrypt_numeric_oid
				&& att->atttypid != encrypt_timestamptz_oid)
			/* Not encrypt_text type */
			continue;

		attVal = heap_getattr(tuple, i+1, slot->tts_tupleDescriptor,
							  &isNull);

		if (isNull)
			/* No need to encrypt/decrypt null value */
			continue;

		if (flag == AES_ENCRYPT_FLAG)
		{
			/*
			 * Encryption part
			 */
			att_buffer = (unsigned char *) VARDATA_ANY(attVal);
			buffer_len = (int) VARSIZE_ANY_EXHDR(attVal);
			crypt_buffer = (char *) palloc(buffer_len + AES_BLOCKLEN
										   + AES_IVLEN + VARHDRSZ);

			/*
			 * Build random AES initialization vector and copy it into
			 * crypt_buffer
			 */
			if (!pg_strong_random(iv, AES_IVLEN))
				ereport(ERROR,
						(errmsg("tcle: could not generate random AES IV")));

			memcpy(VARDATA(crypt_buffer), iv, AES_IVLEN);

			/* AES encryption */
			crypt_len = AES_CBC_encrypt(att_buffer,
										buffer_len,
										table_key,
										iv,
										(unsigned char *) VARDATA(crypt_buffer)
										+ AES_IVLEN);
			if (crypt_len == -1)
				ereport(ERROR,(errmsg("tcle: could not encrypt data")));

			/* Set Datum size to the right size */
			SET_VARSIZE(crypt_buffer, crypt_len + VARHDRSZ + AES_IVLEN);

		}
		else if (flag == AES_DECRYPT_FLAG)
		{
			/*
			 * Decryption part
			 */

			/*
			 * No need to detoast, we work only with plain storage
			 */
			attValCpy = datumCopy(attVal, att->attbyval, att->attlen);
			att_buffer = (unsigned char *) VARDATA_ANY(attValCpy);

			/* Get AES IV */
			memcpy(iv, att_buffer, AES_IVLEN);

			buffer_len = (int) VARSIZE_ANY_EXHDR(attValCpy);
			crypt_buffer = (char *) palloc(buffer_len + VARHDRSZ - AES_IVLEN);

			/* AES decryption */
			crypt_len = AES_CBC_decrypt(att_buffer + AES_IVLEN,
										buffer_len - AES_IVLEN,
										table_key,
										iv,
										(unsigned char *) VARDATA(crypt_buffer));
			if (crypt_len == -1)
				ereport(ERROR,(errmsg("tcle: could not decrypt data")));

			SET_VARSIZE(crypt_buffer, crypt_len + VARHDRSZ);
		}

		replvals[pos] = PointerGetDatum(crypt_buffer);
		replnuls[pos] = isNull;
		replcols[pos] = i + 1;

		pos++;
		natts_r_cryp++;
	}

	/* Apply modifications on the tuple */
	new_tuple = heap_modify_tuple_by_cols(tuple, slot->tts_tupleDescriptor,
										  natts_r_cryp, replcols, replvals,
										  replnuls);

	/* Copy original tuple transaction informations */
	memcpy(&new_tuple->t_data->t_choice.t_heap,
		   &tuple->t_data->t_choice.t_heap,
		   sizeof(HeapTupleFields));

	/* If TTS is a buffer slot, let's conserve original Buffer. */
	if (BufferIsValid(hslot->buffer))
		ExecStoreBufferHeapTuple(new_tuple, slot, hslot->buffer);
	else
		ExecForceStoreHeapTuple(new_tuple, slot, false);

	pfree(replvals);
	pfree(replnuls);
	pfree(replcols);
}

/* ------------------------------------------------------------------------
 * Slot related callbacks
 * ------------------------------------------------------------------------
 */

static const TupleTableSlotOps *
tcleam_slot_callbacks(Relation relation)
{
	return GetHeapamTableAmRoutine()->slot_callbacks(relation);
}

/* ------------------------------------------------------------------------
 * Index Scan Callbacks
 * ------------------------------------------------------------------------
 */

static IndexFetchTableData *
tcleam_index_fetch_begin(Relation rel)
{
	return GetHeapamTableAmRoutine()->index_fetch_begin(rel);
}

static void
tcleam_index_fetch_reset(IndexFetchTableData *scan)
{
	GetHeapamTableAmRoutine()->index_fetch_reset(scan);
}

static void
tcleam_index_fetch_end(IndexFetchTableData *scan)
{
	GetHeapamTableAmRoutine()->index_fetch_end(scan);
}

static bool
tcleam_index_fetch_tuple(struct IndexFetchTableData *scan,
						 ItemPointer tid,
						 Snapshot snapshot,
						 TupleTableSlot *slot,
						 bool *call_again, bool *all_dead)
{
	MemoryContext	oldContext;
	bool			heapam_res;

	heapam_res = GetHeapamTableAmRoutine()->index_fetch_tuple(scan, tid,
															  snapshot, slot,
															  call_again,
															  all_dead);
	if (!heapam_res)
		return false;

	/* Move to TTS memory context */
	oldContext = MemoryContextSwitchTo(slot->tts_mcxt);

	/* Apply AES decryption on tuple attributes */
	EncryptDecryptTupleTableSlot(slot, AES_DECRYPT_FLAG);

	/* Back to AM routine memory context */
	MemoryContextSwitchTo(oldContext);

	return true;
}


/* ------------------------------------------------------------------------
 * Callbacks for non-modifying operations on individual tuples
 * ------------------------------------------------------------------------
 */

static bool
tcleam_fetch_row_version(Relation relation,
						 ItemPointer tid,
						 Snapshot snapshot,
						 TupleTableSlot *slot)
{
	return GetHeapamTableAmRoutine()->tuple_fetch_row_version(relation, tid,
															  snapshot, slot);
}

static bool
tcleam_tuple_tid_valid(TableScanDesc scan, ItemPointer tid)
{
	return GetHeapamTableAmRoutine()->tuple_tid_valid(scan, tid);
}

static bool
tcleam_tuple_satisfies_snapshot(Relation rel, TupleTableSlot *slot,
								Snapshot snapshot)
{
	return GetHeapamTableAmRoutine()->tuple_satisfies_snapshot(rel, slot,
															   snapshot);
}

static bool
tcleam_scan_getnextslot(TableScanDesc sscan, ScanDirection direction,
						 TupleTableSlot *slot)
{
	MemoryContext	oldContext;
	bool			heapam_res;

	heapam_res = GetHeapamTableAmRoutine()->scan_getnextslot(sscan, direction,
															 slot);
	if (!heapam_res)
		return false;

	/* Move to TTS memory context */
	oldContext = MemoryContextSwitchTo(slot->tts_mcxt);

	/* Apply AES decryption on tuple attributes */
	EncryptDecryptTupleTableSlot(slot, AES_DECRYPT_FLAG);

	/* Back to AM routine memory context */
	MemoryContextSwitchTo(oldContext);

	return true;
}


/* ----------------------------------------------------------------------------
 *  Functions for manipulations of physical tuples
 * ----------------------------------------------------------------------------
 */

static void
tcleam_tuple_insert(Relation relation, TupleTableSlot *slot, CommandId cid,
					int options, BulkInsertState bistate)
{
	/* Move to TTS memory context */
	MemoryContext oldContext = MemoryContextSwitchTo(slot->tts_mcxt);

	/* Apply AES encryption on tuple attributes */
	EncryptDecryptTupleTableSlot(slot, AES_ENCRYPT_FLAG);

	/* Back to AM routine memory context */
	MemoryContextSwitchTo(oldContext);

	GetHeapamTableAmRoutine()->tuple_insert(relation, slot, cid, options,
											bistate);
}

static void
tcleam_tuple_insert_speculative(Relation relation, TupleTableSlot *slot,
								CommandId cid, int options,
								BulkInsertState bistate, uint32 specToken)
{
	/* Move to TTS memory context */
	MemoryContext oldContext = MemoryContextSwitchTo(slot->tts_mcxt);

	/* Apply AES encryption on tuple attributes */
	EncryptDecryptTupleTableSlot(slot, AES_ENCRYPT_FLAG);

	/* Back to AM routine memory context */
	MemoryContextSwitchTo(oldContext);

	GetHeapamTableAmRoutine()->tuple_insert_speculative(relation, slot, cid,
														options, bistate,
														specToken);
}

static void
tcleam_tuple_complete_speculative(Relation relation, TupleTableSlot *slot,
								  uint32 specToken, bool succeeded)
{
	GetHeapamTableAmRoutine()->tuple_complete_speculative(relation, slot,
														  specToken,
														  succeeded);
}

static TM_Result
tcleam_tuple_delete(Relation relation, ItemPointer tid, CommandId cid,
					Snapshot snapshot, Snapshot crosscheck, bool wait,
					TM_FailureData *tmfd, bool changingPart)
{
	return GetHeapamTableAmRoutine()->tuple_delete(relation, tid, cid,
												   snapshot, crosscheck, wait,
												   tmfd, changingPart);
}

static TM_Result
tcleam_tuple_update(Relation relation, ItemPointer otid, TupleTableSlot *slot,
					CommandId cid, Snapshot snapshot, Snapshot crosscheck,
					bool wait, TM_FailureData *tmfd,
					LockTupleMode *lockmode, bool *update_indexes)
{
	/* Move to TTS memory context */
	MemoryContext oldContext = MemoryContextSwitchTo(slot->tts_mcxt);

	/* Apply AES encryption on tuple attributes */
	EncryptDecryptTupleTableSlot(slot, AES_ENCRYPT_FLAG);

	/* Back to AM routine memory context */
	MemoryContextSwitchTo(oldContext);

	return GetHeapamTableAmRoutine()->tuple_update(relation, otid, slot, cid,
												   snapshot, crosscheck, wait,
												   tmfd, lockmode,
												   update_indexes);
}

static TM_Result
tcleam_tuple_lock(Relation relation, ItemPointer tid, Snapshot snapshot,
				  TupleTableSlot *slot, CommandId cid, LockTupleMode mode,
				  LockWaitPolicy wait_policy, uint8 flags,
				  TM_FailureData *tmfd)
{
	return GetHeapamTableAmRoutine()->tuple_lock(relation, tid, snapshot, slot,
												 cid, mode, wait_policy, flags,
												 tmfd);
}


/* ------------------------------------------------------------------------
 * DDL related callbacks
 * ------------------------------------------------------------------------
 */

static void
tcleam_relation_set_new_filenode(Relation rel,
								 const RelFileNode *newrnode,
								 char persistence,
								 TransactionId *freezeXid,
								 MultiXactId *minmulti)
{
	GetHeapamTableAmRoutine()->relation_set_new_filenode(rel, newrnode,
														 persistence,
														 freezeXid, minmulti);
}

static void
tcleam_relation_nontransactional_truncate(Relation rel)
{
	GetHeapamTableAmRoutine()->relation_nontransactional_truncate(rel);
}

static void
tcleam_relation_copy_data(Relation rel, const RelFileNode *newrnode)
{
	GetHeapamTableAmRoutine()->relation_copy_data(rel, newrnode);
}

static void
tcleam_multi_insert(Relation relation, TupleTableSlot **slots, int ntuples,
					CommandId cid, int options, BulkInsertState bistate)
{
	for (int i=0; i < ntuples; i++)
	{
		/* Move to TTS memory context */
		MemoryContext oldContext = MemoryContextSwitchTo(slots[i]->tts_mcxt);

		/* Apply AES encryption on tuple attributes */
		EncryptDecryptTupleTableSlot(slots[i], AES_ENCRYPT_FLAG);

		/* Back to AM routine memory context */
		MemoryContextSwitchTo(oldContext);
	}

	heap_multi_insert(relation, slots, ntuples, cid, options, bistate);
}


/*
 * Duplicated from src/backend/access/heap/heapam_handler.c
 */
/*
 * This version has been tweaked to apply AES encryption before rewriting
 * tuples. In theory, we shouldn't have to decrypt / encrypt when rewriting
 * tuples in VACUUM FULL or CLUSTER context, we could just rewrite them "as
 * it", but heapam_relation_copy_for_cluster() relies on index_getnext_slot()
 * and table_scan_getnextslot() to fetch tuples and those 2 functions decrypt
 * tuples.
 */
static void
tcleam_relation_copy_for_cluster(Relation OldHeap, Relation NewHeap,
								 Relation OldIndex, bool use_sort,
								 TransactionId OldestXmin,
								 TransactionId *xid_cutoff,
								 MultiXactId *multi_cutoff,
								 double *num_tuples,
								 double *tups_vacuumed,
								 double *tups_recently_dead)
{
	RewriteState rwstate;
	IndexScanDesc indexScan;
	TableScanDesc tableScan;
	HeapScanDesc heapScan;
	bool		is_system_catalog;
	Tuplesortstate *tuplesort;
	TupleDesc	oldTupDesc = RelationGetDescr(OldHeap);
	TupleDesc	newTupDesc = RelationGetDescr(NewHeap);
	TupleTableSlot *slot;
	int			natts;
	Datum	   *values;
	bool	   *isnull;
	BufferHeapTupleTableSlot *hslot;

	/* Remember if it's a system catalog */
	is_system_catalog = IsSystemRelation(OldHeap);

	/*
	 * Valid smgr_targblock implies something already wrote to the relation.
	 * This may be harmless, but this function hasn't planned for it.
	 */
	Assert(RelationGetTargetBlock(NewHeap) == InvalidBlockNumber);

	/* Preallocate values/isnull arrays */
	natts = newTupDesc->natts;
	values = (Datum *) palloc(natts * sizeof(Datum));
	isnull = (bool *) palloc(natts * sizeof(bool));

	/* Initialize the rewrite operation */
	rwstate = begin_heap_rewrite(OldHeap, NewHeap, OldestXmin, *xid_cutoff,
								 *multi_cutoff);


	/* Set up sorting if wanted */
	if (use_sort)
		tuplesort = tuplesort_begin_cluster(oldTupDesc, OldIndex,
											maintenance_work_mem,
											NULL, false);
	else
		tuplesort = NULL;

	/*
	 * Prepare to scan the OldHeap.  To ensure we see recently-dead tuples
	 * that still need to be copied, we scan with SnapshotAny and use
	 * HeapTupleSatisfiesVacuum for the visibility test.
	 */
	if (OldIndex != NULL && !use_sort)
	{
		const int	ci_index[] = {
			PROGRESS_CLUSTER_PHASE,
			PROGRESS_CLUSTER_INDEX_RELID
		};
		int64		ci_val[2];

		/* Set phase and OIDOldIndex to columns */
		ci_val[0] = PROGRESS_CLUSTER_PHASE_INDEX_SCAN_HEAP;
		ci_val[1] = RelationGetRelid(OldIndex);
		pgstat_progress_update_multi_param(2, ci_index, ci_val);

		tableScan = NULL;
		heapScan = NULL;
		indexScan = index_beginscan(OldHeap, OldIndex, SnapshotAny, 0, 0);
		index_rescan(indexScan, NULL, 0, NULL, 0);
	}
	else
	{
		/* In scan-and-sort mode and also VACUUM FULL, set phase */
		pgstat_progress_update_param(PROGRESS_CLUSTER_PHASE,
									 PROGRESS_CLUSTER_PHASE_SEQ_SCAN_HEAP);

		tableScan = table_beginscan(OldHeap, SnapshotAny, 0, (ScanKey) NULL);
		heapScan = (HeapScanDesc) tableScan;
		indexScan = NULL;

		/* Set total heap blocks */
		pgstat_progress_update_param(PROGRESS_CLUSTER_TOTAL_HEAP_BLKS,
									 heapScan->rs_nblocks);
	}

	slot = table_slot_create(OldHeap, NULL);
	hslot = (BufferHeapTupleTableSlot *) slot;

	/*
	 * Scan through the OldHeap, either in OldIndex order or sequentially;
	 * copy each tuple into the NewHeap, or transiently to the tuplesort
	 * module.  Note that we don't bother sorting dead tuples (they won't get
	 * to the new table anyway).
	 */
	for (;;)
	{
		HeapTuple	tuple;
		Buffer		buf;
		bool		isdead;

		CHECK_FOR_INTERRUPTS();

		if (indexScan != NULL)
		{
			if (!index_getnext_slot(indexScan, ForwardScanDirection, slot))
				break;

			/* Since we used no scan keys, should never need to recheck */
			if (indexScan->xs_recheck)
				elog(ERROR, "CLUSTER does not support lossy index conditions");
		}
		else
		{
			if (!table_scan_getnextslot(tableScan, ForwardScanDirection, slot))
				break;

			/*
			 * In scan-and-sort mode and also VACUUM FULL, set heap blocks
			 * scanned
			 */
			pgstat_progress_update_param(PROGRESS_CLUSTER_HEAP_BLKS_SCANNED,
										 heapScan->rs_cblock + 1);
		}

		/* Apply AES encryption on tuple attributes */
		EncryptDecryptTupleTableSlot(slot, AES_ENCRYPT_FLAG);

		tuple = ExecFetchSlotHeapTuple(slot, false, NULL);
		buf = hslot->buffer;

		LockBuffer(buf, BUFFER_LOCK_SHARE);

		switch (HeapTupleSatisfiesVacuum(tuple, OldestXmin, buf))
		{
			case HEAPTUPLE_DEAD:
				/* Definitely dead */
				isdead = true;
				break;
			case HEAPTUPLE_RECENTLY_DEAD:
				*tups_recently_dead += 1;
				/* fall through */
			case HEAPTUPLE_LIVE:
				/* Live or recently dead, must copy it */
				isdead = false;
				break;
			case HEAPTUPLE_INSERT_IN_PROGRESS:

				/*
				 * Since we hold exclusive lock on the relation, normally the
				 * only way to see this is if it was inserted earlier in our
				 * own transaction.  However, it can happen in system
				 * catalogs, since we tend to release write lock before commit
				 * there.  Give a warning if neither case applies; but in any
				 * case we had better copy it.
				 */
				if (!is_system_catalog &&
					!TransactionIdIsCurrentTransactionId(HeapTupleHeaderGetXmin(tuple->t_data)))
					elog(WARNING, "concurrent insert in progress within table \"%s\"",
						 RelationGetRelationName(OldHeap));
				/* treat as live */
				isdead = false;
				break;
			case HEAPTUPLE_DELETE_IN_PROGRESS:

				/*
				 * Similar situation to INSERT_IN_PROGRESS case.
				 */
				if (!is_system_catalog &&
					!TransactionIdIsCurrentTransactionId(HeapTupleHeaderGetUpdateXid(tuple->t_data)))
					elog(WARNING, "concurrent delete in progress within table \"%s\"",
						 RelationGetRelationName(OldHeap));
				/* treat as recently dead */
				*tups_recently_dead += 1;
				isdead = false;
				break;
			default:
				elog(ERROR, "unexpected HeapTupleSatisfiesVacuum result");
				isdead = false; /* keep compiler quiet */
				break;
		}

		LockBuffer(buf, BUFFER_LOCK_UNLOCK);

		if (isdead)
		{
			*tups_vacuumed += 1;
			/* heap rewrite module still needs to see it... */
			if (rewrite_heap_dead_tuple(rwstate, tuple))
			{
				/* A previous recently-dead tuple is now known dead */
				*tups_vacuumed += 1;
				*tups_recently_dead -= 1;
			}
			continue;
		}

		*num_tuples += 1;
		if (tuplesort != NULL)
		{
			tuplesort_putheaptuple(tuplesort, tuple);

			/*
			 * In scan-and-sort mode, report increase in number of tuples
			 * scanned
			 */
			pgstat_progress_update_param(PROGRESS_CLUSTER_HEAP_TUPLES_SCANNED,
										 *num_tuples);
		}
		else
		{
			const int	ct_index[] = {
				PROGRESS_CLUSTER_HEAP_TUPLES_SCANNED,
				PROGRESS_CLUSTER_HEAP_TUPLES_WRITTEN
			};
			int64		ct_val[2];

			reform_and_rewrite_tuple(tuple, OldHeap, NewHeap,
									 values, isnull, rwstate);

			/*
			 * In indexscan mode and also VACUUM FULL, report increase in
			 * number of tuples scanned and written
			 */
			ct_val[0] = *num_tuples;
			ct_val[1] = *num_tuples;
			pgstat_progress_update_multi_param(2, ct_index, ct_val);
		}
	}

	if (indexScan != NULL)
		index_endscan(indexScan);
	if (tableScan != NULL)
		table_endscan(tableScan);
	if (slot)
		ExecDropSingleTupleTableSlot(slot);

	/*
	 * In scan-and-sort mode, complete the sort, then read out all live tuples
	 * from the tuplestore and write them to the new relation.
	 */
	if (tuplesort != NULL)
	{
		double		n_tuples = 0;

		/* Report that we are now sorting tuples */
		pgstat_progress_update_param(PROGRESS_CLUSTER_PHASE,
									 PROGRESS_CLUSTER_PHASE_SORT_TUPLES);

		tuplesort_performsort(tuplesort);

		/* Report that we are now writing new heap */
		pgstat_progress_update_param(PROGRESS_CLUSTER_PHASE,
									 PROGRESS_CLUSTER_PHASE_WRITE_NEW_HEAP);

		for (;;)
		{
			HeapTuple	tuple;

			CHECK_FOR_INTERRUPTS();

			tuple = tuplesort_getheaptuple(tuplesort, true);
			if (tuple == NULL)
				break;

			n_tuples += 1;
			reform_and_rewrite_tuple(tuple,
									 OldHeap, NewHeap,
									 values, isnull,
									 rwstate);
			/* Report n_tuples */
			pgstat_progress_update_param(PROGRESS_CLUSTER_HEAP_TUPLES_WRITTEN,
										 n_tuples);
		}

		tuplesort_end(tuplesort);
	}

	/* Write out any remaining tuples, and fsync if needed */
	end_heap_rewrite(rwstate);

	/* Clean up */
	pfree(values);
	pfree(isnull);
}

static bool
tcleam_scan_analyze_next_block(TableScanDesc scan, BlockNumber blockno,
							   BufferAccessStrategy bstrategy)
{
	return GetHeapamTableAmRoutine()->scan_analyze_next_block(scan, blockno,
															  bstrategy);
}

static bool
tcleam_scan_analyze_next_tuple(TableScanDesc scan, TransactionId OldestXmin,
							   double *liverows, double *deadrows,
							   TupleTableSlot *slot)
{
	return GetHeapamTableAmRoutine()->scan_analyze_next_tuple(scan, OldestXmin,
															  liverows,
															  deadrows, slot);
}


/* ------------------------------------------------------------------------
 * Miscellaneous callbacks
 * ------------------------------------------------------------------------
 */

static bool
tcleam_relation_needs_toast_table(Relation rel)
{
	return GetHeapamTableAmRoutine()->relation_needs_toast_table(rel);
}

static Oid
tcleam_relation_toast_am(Relation rel)
{
	return GetHeapamTableAmRoutine()->relation_toast_am(rel);
}


/* ------------------------------------------------------------------------
 * Planner related callbacks
 * ------------------------------------------------------------------------
 */

static void
tcleam_estimate_rel_size(Relation rel, int32 *attr_widths,
						 BlockNumber *pages, double *tuples,
						 double *allvisfrac)
{
	GetHeapamTableAmRoutine()->relation_estimate_size(rel, attr_widths, pages,
													  tuples, allvisfrac);
}


/* ------------------------------------------------------------------------
 * Executor related callbacks
 * ------------------------------------------------------------------------
 */

static bool
tcleam_scan_bitmap_next_block(TableScanDesc scan,
							  TBMIterateResult *tbmres)
{

	return GetHeapamTableAmRoutine()->scan_bitmap_next_block(scan, tbmres);
}

static bool
tcleam_scan_bitmap_next_tuple(TableScanDesc scan,
							  TBMIterateResult *tbmres,
							  TupleTableSlot *slot)
{
	return GetHeapamTableAmRoutine()->scan_bitmap_next_tuple(scan, tbmres,
															 slot);
}

static bool
tcleam_scan_sample_next_block(TableScanDesc scan, SampleScanState *scanstate)
{
	return GetHeapamTableAmRoutine()->scan_sample_next_block(scan, scanstate);
}

static bool
tcleam_scan_sample_next_tuple(TableScanDesc scan, SampleScanState *scanstate,
							  TupleTableSlot *slot)
{
	return GetHeapamTableAmRoutine()->scan_sample_next_tuple(scan, scanstate,
															 slot);
}

static void
tcleam_get_latest_tid(TableScanDesc scan, ItemPointer tid)
{
	ereport(LOG, (errmsg("tcle: tcleam_get_latest_tid")));
	heap_get_latest_tid(scan, tid);
}

static TableScanDesc
tcleam_beginscan(Relation rel, Snapshot snapshot, int nkeys,
				 struct ScanKeyData *key, ParallelTableScanDesc  parallel_scan,
				 uint32 flags)
{
	return heap_beginscan(rel, snapshot, nkeys, key, parallel_scan, flags);
}

static const TableAmRoutine tcleam_methods = {
	.type = T_TableAmRoutine,

	.slot_callbacks = tcleam_slot_callbacks,

	.scan_begin = tcleam_beginscan,
	.scan_end = heap_endscan,
	.scan_rescan = heap_rescan,
	.scan_getnextslot = tcleam_scan_getnextslot,

	.parallelscan_estimate = table_block_parallelscan_estimate,
	.parallelscan_initialize = table_block_parallelscan_initialize,
	.parallelscan_reinitialize = table_block_parallelscan_reinitialize,

	.index_fetch_begin = tcleam_index_fetch_begin,
	.index_fetch_reset = tcleam_index_fetch_reset,
	.index_fetch_end = tcleam_index_fetch_end,
	.index_fetch_tuple = tcleam_index_fetch_tuple,

	.tuple_insert = tcleam_tuple_insert,
	.tuple_insert_speculative = tcleam_tuple_insert_speculative,
	.tuple_complete_speculative = tcleam_tuple_complete_speculative,
	.multi_insert = tcleam_multi_insert,
	.tuple_delete = tcleam_tuple_delete,
	.tuple_update = tcleam_tuple_update,
	.tuple_lock = tcleam_tuple_lock,

	.tuple_fetch_row_version = tcleam_fetch_row_version,
	.tuple_get_latest_tid = tcleam_get_latest_tid,
	.tuple_tid_valid = tcleam_tuple_tid_valid,
	.tuple_satisfies_snapshot = tcleam_tuple_satisfies_snapshot,
	.compute_xid_horizon_for_tuples = heap_compute_xid_horizon_for_tuples,
	.relation_set_new_filenode = tcleam_relation_set_new_filenode,
	.relation_nontransactional_truncate = tcleam_relation_nontransactional_truncate,
	.relation_copy_data = tcleam_relation_copy_data,
	.relation_copy_for_cluster = tcleam_relation_copy_for_cluster,
	.relation_vacuum = heap_vacuum_rel,
	.scan_analyze_next_block = tcleam_scan_analyze_next_block,
	.scan_analyze_next_tuple = tcleam_scan_analyze_next_tuple,
	.index_build_range_scan = tcleam_index_build_range_scan,
	.index_validate_scan = tcleam_index_validate_scan,

	.relation_size = table_block_relation_size,
	.relation_needs_toast_table = tcleam_relation_needs_toast_table,
	.relation_toast_am = tcleam_relation_toast_am,
	.relation_fetch_toast_slice = heap_fetch_toast_slice,

	.relation_estimate_size = tcleam_estimate_rel_size,

	.scan_bitmap_next_block = tcleam_scan_bitmap_next_block,
	.scan_bitmap_next_tuple = tcleam_scan_bitmap_next_tuple,
	.scan_sample_next_block = tcleam_scan_sample_next_block,
	.scan_sample_next_tuple = tcleam_scan_sample_next_tuple
};


Datum
tcleam_handler(PG_FUNCTION_ARGS)
{
	PG_RETURN_POINTER(&tcleam_methods);
}
