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
#if (PG_VERSION_NUM >= 130000)
#include "access/heaptoast.h"
#endif
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
#include "commands/extension.h"
#include "commands/progress.h"
#include "libpq/pqformat.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/lmgr.h"
#include "storage/bufmgr.h"
#include "storage/smgr.h"
#include "storage/proc.h"
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/datum.h"
#include "utils/fmgrprotos.h"
#include "utils/memutils.h"
#include "utils/numeric.h"
#include "utils/syscache.h"

#include "tcleheap.h"
#include "aes.h"
#include "kms.h"
#include "utils.h"

PG_MODULE_MAGIC;

/* Number of encryptable data types */
#define N_ENCRYPT_TYPES		3
#define IS_ENCRYPTABLE_TYPE(OID, ARRAY) \
	(OID == ARRAY[0] || OID == ARRAY[1] || OID == ARRAY[2])

/*
 * CommandCryptState* struct are used to store in a htab (local to backend) a
 * flag or transient key related to current command. The flag will be use to
 * disable encryption / decryption for some utility statements like VACUUM FULL
 * or CLUSTER.
 */
typedef struct CommandCryptStateKey {
	LocalTransactionId	lxid; /* Local Transaction ID */
} CommandCryptStateKey;

typedef struct CommandCryptStateEntry {
	CommandCryptStateKey key;
	int8			flag;
	unsigned char  *transient_key;
} CommandCryptStateEntry;

/* Array of encryptable data type names currently implemented */
static const char *encrypt_types[N_ENCRYPT_TYPES] = {"encrypt_text",
													 "encrypt_numeric",
													 "encrypt_timestamptz"};

/* Saved hook values in case of unload */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

/* Link to shared memory and globals variables */
static ShmemKMSMasterKeysLock *shmmasterkeyslock = NULL;
static ShmemKMSKeyCache *shmkeycache = NULL;
static HTAB *shmmasterkeys = NULL;
static HTAB *command_crypt_state = NULL;

extern Datum encrypt_text_in(PG_FUNCTION_ARGS);
extern Datum encrypt_text_out(PG_FUNCTION_ARGS);
extern Datum tcle_set_passphrase(PG_FUNCTION_ARGS);
extern Datum tcle_change_passphrase(PG_FUNCTION_ARGS);

static bool RelationAMIsTcleam(Oid relid);
static HeapTuple EncryptDecryptHeapTuple(HeapTuple tuple, TupleDesc tupleDesc,
										 Oid tableId, int8 flag,
										 unsigned char *table_key,
										 Oid *type_oids);
static void LoadTableKey(Oid databaseId, Oid tableId,
						 unsigned char **table_keyPtr);
static void get_encrypt_type_oids(Oid **oidsPtr);
static void command_crypt_state_init(void);
static void command_crypt_state_set(LocalTransactionId lxid, int8 flag,
									unsigned char *tkey);
static void command_crypt_state_rm(LocalTransactionId lxid);
static void command_crypt_state_mcb(void *arg);
static bool ShouldEncryptDecryptTTS(void);
static void SetNotEncryptDecryptTTS(void);
static void RemoveCommandCryptState(void);
static void BuildCommandTransientKey(void);
static bool GetCommandTransientKey(unsigned char **tkeyPtr);

void _PG_init(void);
void _PG_fini(void);

/* Hook function */
static void tcle_shmem_startup(void);
#if (PG_VERSION_NUM >= 130000)
static void tcle_ProcessUtility(PlannedStmt *pstmt,
								const char *queryString,
								ProcessUtilityContext context,
								ParamListInfo params,
								QueryEnvironment *queryEnv,
								DestReceiver *dest,
								QueryCompletion *qc);
#elif (PG_VERSION_NUM >= 120000)
static void tcle_ProcessUtility(PlannedStmt *pstmt,
								const char *queryString,
								ProcessUtilityContext context,
								ParamListInfo params,
								QueryEnvironment *queryEnv,
								DestReceiver *dest,
								char *qc);
#endif

PG_FUNCTION_INFO_V1(tcleam_handler);
PG_FUNCTION_INFO_V1(encrypt_text_in);
PG_FUNCTION_INFO_V1(encrypt_text_recv);
PG_FUNCTION_INFO_V1(encrypt_timestamptz_in);
PG_FUNCTION_INFO_V1(encrypt_timestamptz_out);
PG_FUNCTION_INFO_V1(encrypt_timestamptz_recv);
PG_FUNCTION_INFO_V1(encrypt_timestamptz_send);
PG_FUNCTION_INFO_V1(tcle_set_passphrase);
PG_FUNCTION_INFO_V1(tcle_change_passphrase);

void
_PG_init(void)
{
	/*
	 * Ensures TCLE library has been loaded via shared_preload_libraries.
	 */
	if (!process_shared_preload_libraries_in_progress)
		ereport(ERROR,
				(errmsg("tcle must be loaded via shared_preload_libraries")));

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
#if (PG_VERSION_NUM >= 130000)
tcle_ProcessUtility(PlannedStmt *pstmt,
					const char *queryString,
					ProcessUtilityContext context,
					ParamListInfo params,
					QueryEnvironment *queryEnv,
					DestReceiver *dest,
					QueryCompletion *qc)
#elif (PG_VERSION_NUM >= 120000)
tcle_ProcessUtility(PlannedStmt *pstmt,
					const char *queryString,
					ProcessUtilityContext context,
					ParamListInfo params,
					QueryEnvironment *queryEnv,
					DestReceiver *dest,
					char *qc)
#endif
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
			 * and store in memory a transient AES key right before the DDL is
			 * executed by standard_ProcessUtility().
			 */
			CreateTableAsStmt  *stmt;

			stmt = (CreateTableAsStmt *) parsetree;

			if (stmt->into->accessMethod
					&& strcmp(stmt->into->accessMethod, "tcleam") == 0)
				BuildCommandTransientKey();

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

		case T_CreateTableAsStmt:
		{
			/*
			 * End of CREATE TABLE .. AS special case: we have now to build a
			 * new KMSKeyAction and push the action to further add the
			 * transient key in KMS table.
			 */
			CreateTableAsStmt  *stmt;
			KMSKeyAction	   *kkact;

			stmt = (CreateTableAsStmt *) parsetree;

			if (!stmt->into->accessMethod
					|| strcmp(stmt->into->accessMethod, "tcleam") != 0)
				break;

			kkact = RelationGetKMSKeyAction(stmt->into->rel);

			kkact->action_tag = AT_ADD_CTAS_KEY;
			kkact->ctas_key = (unsigned char *) palloc(AES_KEYLEN);

			if (!GetCommandTransientKey(&(kkact->ctas_key)))
			{
				/*
				 * CTAS but no transient key found ?
				 * This case should not happen but we handle it just in case.
				 */

				pfree(kkact->ctas_key);
				pfree(kkact);

				ereport(ERROR, (errmsg("tcle: transient key not found")));
			}

			RemoveCommandCryptState();

			actions = lappend(actions, kkact);
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

		list_free(actions);
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
	char		   *passphrase = PG_GETARG_CSTRING(0);
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

	if (strlen(passphrase) == 0)
		ereport(ERROR, (errmsg("tcle: passphrase should not be empty")));

	/* Compute sha256 hash of the passphrase */
	pg_sha256_init(&ctx);
	pg_sha256_update(&ctx, (unsigned char *) VARDATA_ANY(passphrase),
					 VARSIZE_ANY_EXHDR(passphrase));
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
				(errmsg("tcle: wrong passphrase")));

	/*
	 * Remove previous master key from shmem if any. This can ben done safely
	 * because we're sure at this point that this key is not really in use.
	 */
	RemoveDatabaseMasterKey(shmmasterkeyslock, shmmasterkeys, MyDatabaseId);
	/* Add the brand new master key in shmem */
	AddDatabaseMasterKey(shmmasterkeyslock, shmmasterkeys, MyDatabaseId,
						 master_key);

	PG_RETURN_BOOL(true);
}

/*
 * Unsecure (the passphrase could leak in logs) and temporary user function to
 * change a master key using a passphrase.
 */
Datum
tcle_change_passphrase(PG_FUNCTION_ARGS)
{
	char		   *passphrase = PG_GETARG_CSTRING(0);
	char		   *new_passphrase = PG_GETARG_CSTRING(1);
	pg_sha256_ctx	ctx;
	unsigned char	buf[PG_SHA256_DIGEST_LENGTH];
	unsigned char	master_key[AES_KEYLEN],
					new_master_key[AES_KEYLEN];
	unsigned char	*shmem_master_key;
	shmem_master_key = (unsigned char *) palloc(AES_KEYLEN);

	/*
	 * Master key rotation could not run in a transaction block because the
	 * shmem update part is not atomic and cannot be rollback'd.
	 */
	PreventInTransactionBlock(true, "tcle: master key rotation");

	/*
	 * ACL check against database: only the owner or a superuser can change a
	 * database master key.
	 */
	if (!pg_database_ownercheck(MyDatabaseId, GetUserId()))
		ereport(ERROR,
				(errmsg("tcle: only database owner and superusers are allowed "
						"to change the master key")));

	if (strlen(passphrase) == 0)
		ereport(ERROR, (errmsg("tcle: passphrase should not be empty")));
	if (strlen(new_passphrase) == 0)
		ereport(ERROR, (errmsg("tcle: new passphrase should not be empty")));

	/*
	 * Derivate master key from the passphrase by computing passphrase sha256
	 * sum.
	 */
	pg_sha256_init(&ctx);
	pg_sha256_update(&ctx, (unsigned char *) VARDATA_ANY(passphrase),
					 VARSIZE_ANY_EXHDR(passphrase));
	pg_sha256_final(&ctx, buf);
	memcpy(&master_key, buf, sizeof(buf));

	/*
	 * We have to check if the given passphrase corresponds to the current
	 * master key.
	 */
	if (GetDatabaseMasterKey(shmmasterkeyslock, shmmasterkeys, MyDatabaseId,
							 &shmem_master_key))
	{
		if (memcmp(shmem_master_key, master_key, AES_KEYLEN) != 0)
			ereport(ERROR,
					(errmsg("tcle: wrong passphrase")));
	}
	if (!CheckKMSMasterKey(master_key))
		ereport(ERROR,
				(errmsg("tcle: wrong passphrase")));

	/* Key derivation for the new passphrase this time */
	memset(buf, 0, PG_SHA256_DIGEST_LENGTH);
	pg_sha256_init(&ctx);
	pg_sha256_update(&ctx, (unsigned char *) VARDATA_ANY(new_passphrase),
					 VARSIZE_ANY_EXHDR(new_passphrase));
	pg_sha256_final(&ctx, buf);
	memcpy(&new_master_key, buf, sizeof(buf));

	/*
	 * Let's continue with master key rotation. We need to first hold an
	 * exclusive lock on the master key residing in shmem, then apply table key
	 * reencryption with the new master key, update the master key residing in
	 * shmem, finally, release master key LWLock.
	 */
	LWLockAcquire(shmmasterkeyslock->lock, LW_EXCLUSIVE);
	/* Apply table keys reencryption */
	ChangeKMSMasterKey(master_key, new_master_key);
	/* Update master key in shmem */
	UpdateDatabaseMasterKey(shmmasterkeys, MyDatabaseId, new_master_key);
	LWLockRelease(shmmasterkeyslock->lock);

	pfree(shmem_master_key);

	PG_RETURN_BOOL(true);
}

/*
 * Load encryptable types Oids into input array.
 */
static void
get_encrypt_type_oids(Oid ** oidsPtr)
{
	Oid		namespaceId;
	Oid		extensionId;

	extensionId = get_extension_oid("tcle", false);
	namespaceId = get_extension_schema(extensionId);

	for (int i = 0; i < N_ENCRYPT_TYPES; i++)
	{
		(*oidsPtr)[i] = GetSysCacheOid2(TYPENAMENSP, Anum_pg_type_oid,
									  PointerGetDatum(encrypt_types[i]),
									  ObjectIdGetDatum(namespaceId));
	}
}

/*
 * Encrypt / decrypt tuple attributes from a TupleTableSlot.
 */
static void
EncryptDecryptTupleTableSlot(TupleTableSlot *slot, int8 flag, Oid tableId)
{
	/* Number of attributes (columns) */
	int				natts;
	bool			found_encrypt_type = false;
	/* Variables for tuple manipulation */
	HeapTuple		tuple, new_tuple;
	bool			shouldFreeTuple;
	unsigned char  *table_key;
	Oid			   *type_oids;
	BufferHeapTupleTableSlot *bslot;
	MemoryContext	oldContext;
	bool			materialize;

	if (!ShouldEncryptDecryptTTS())
		return;

	/* Get encryptable data types Oids */
	type_oids = (Oid *) palloc(N_ENCRYPT_TYPES * sizeof(Oid));
	get_encrypt_type_oids(&type_oids);

	natts = slot->tts_tupleDescriptor->natts;

	/*
	 * Quick attributes list lookup to see if any value should be encrypted /
	 * decrypted later. We need to know maximum number of attributes we will
	 * later update in heap to allocate memory for replvals, replnuls and
	 * replcols.
	 */
	for (int i=0; i < natts; i++)
	{
		Form_pg_attribute att = TupleDescAttr(slot->tts_tupleDescriptor, i);

		if (IS_ENCRYPTABLE_TYPE(att->atttypid, type_oids))
		{
			found_encrypt_type = true;
			break;
		}
	}

	if (!found_encrypt_type)
	{
		/* No encryptable data ? Just exit. */
		pfree(type_oids);
		return;
	}

	/*
	 * If tableId argument is not a valid Oid, let's consider that TTS contains
	 * the right table id.
	 */
	if (!OidIsValid(tableId))
		tableId = slot->tts_tableOid;

	/* Load table's key */
	table_key = (unsigned char *) palloc(AES_KEYLEN);
	LoadTableKey(MyDatabaseId, tableId, &table_key);

	/* Do not materialize if we're dealing with virtual tuple */
	materialize = (slot->tts_ops != &TTSOpsVirtual);

	/* Fetch tuple from the slot */
	bslot = (BufferHeapTupleTableSlot *) slot;
	tuple = ExecFetchSlotHeapTuple(slot, materialize, &shouldFreeTuple);

	/* Tuple encryption / decryption */
	new_tuple = EncryptDecryptHeapTuple(tuple, slot->tts_tupleDescriptor,
										tableId, flag, table_key, type_oids);

	if (slot->tts_ops == &TTSOpsVirtual)
	{
		/*
		 * Virtual tuples (coming from CTAS) should not be materialized and can
		 * be stored with ExecForceStoreHeapTuple() as is.
		 */
		ExecForceStoreHeapTuple(new_tuple, slot, true);
	}
	else if (slot->tts_ops == &TTSOpsBufferHeapTuple)
	{
		/* The Slot has been materialized, so we can free the buffer tuple */
		heap_freetuple(bslot->base.tuple);

		/* Tuple duplication into TTS memory context */
		oldContext = MemoryContextSwitchTo(slot->tts_mcxt);
		bslot->base.tuple = heap_copytuple(new_tuple);
		MemoryContextSwitchTo(oldContext);

		/* Copy ctid, and flag the TTS */
		slot->tts_tid = new_tuple->t_self;
		slot->tts_flags |= TTS_FLAG_SHOULDFREE;

		heap_freetuple(new_tuple);
	}
	else
		ereport(ERROR, (errmsg("tcle: unsupported type of TTS")));

	if (shouldFreeTuple)
		heap_freetuple(tuple);
	pfree(table_key);
	pfree(type_oids);
}

/*
 * Shared memory lookup for table's key. If not found then we have to load
 * the master key and fetch table's cipher key from KMS table and finally
 * push the table's key in shared memory.
 */
static void
LoadTableKey(Oid databaseId, Oid tableId, unsigned char **table_keyPtr)
{
	unsigned char  *master_key;
	bytea		   *table_cipher_key;

	/* Cache lookup first */
	if (CacheGetRelationKey(shmkeycache, databaseId, tableId, table_keyPtr))
		return;

	/* Try to get table's key from KMS table */
	table_cipher_key = (bytea *) palloc(AES_IVLEN + AES_KEYLEN + AES_BLOCKLEN);
	if (!GetKMSCipherKey(tableId, &table_cipher_key))
	{
		pfree(table_cipher_key);

		/* If not found in KMS, maybe we have a transient key ? */
		if (GetCommandTransientKey(table_keyPtr))
		{
			/* If found, we put it into the cache */
			CacheAddRelationKey(shmkeycache, databaseId, tableId,
								*table_keyPtr);
			return;
		}
		else
			ereport(ERROR, (errmsg("tcle: could not find table's key")));
	}

	/*
	 * At this point we've found table's cipher key in KMS table, now we have
	 * to decrypt it with the master key and put it in cache.
	 */
	master_key = (unsigned char *) palloc(AES_KEYLEN);

	/* Get master key from shared memory */
	if (!GetDatabaseMasterKey(shmmasterkeyslock, shmmasterkeys, databaseId,
							  &master_key))
	{
		pfree(table_cipher_key);
		pfree(master_key);
		ereport(ERROR,
				(errmsg("tcle: master key not found for this database")));
	}

	/* Decrypt table's cipher key */
	if (!DecryptKMSCipherKey(table_cipher_key, master_key, table_keyPtr))
	{
		pfree(table_cipher_key);
		pfree(master_key);
		ereport(ERROR, (errmsg("tcle: could not decrypt table's cipher key")));
	}

	pfree(table_cipher_key);
	pfree(master_key);

	/* Add table's key in shared memory */
	CacheAddRelationKey(shmkeycache, databaseId, tableId, *table_keyPtr);
}

static HeapTuple
EncryptDecryptHeapTuple(HeapTuple tuple, TupleDesc tupleDesc, Oid tableId,
						int8 flag, unsigned char *table_key, Oid *type_oids)
{
	/* Variables for tuple manipulation */
	HeapTuple		new_tuple;

	Datum		   *values, *new_values;
	bool		   *isnull;
	MemoryContext	oldcontext, tmpcontext;

	/* Let's do encryption / decryption in a dedicated memory context */
	tmpcontext = AllocSetContextCreate(CurrentMemoryContext,
									   "TCLE crypt tuple",
									   ALLOCSET_DEFAULT_SIZES);
	oldcontext = MemoryContextSwitchTo(tmpcontext);

	values = (Datum *) palloc(sizeof(Datum) * tupleDesc->natts);
	isnull = (bool *) palloc(sizeof(bool) * tupleDesc->natts);
	new_values = (Datum *) palloc(sizeof(Datum) * tupleDesc->natts);

	/* Extract tuple values and nulls */
	heap_deform_tuple(tuple, tupleDesc, values, isnull);

	/*
	 * Loop through tuple descriptor attributes looking for ENCRYPT_* types
	 * and apply encrypt/decrypt on attribute value if not null.
	 */
	for (int i=0; i < tupleDesc->natts; i++)
	{
		/*
		 * plaintext / ciphertext length returned by AES decryption /
		 * encryption functions.
		 */
		int				crypt_len;
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
		char		   *crypt_buffer = NULL;
		/* Input plaintext / ciphertext length */
		int				buffer_len;
		/* AES initialization vector */
		unsigned char	iv[AES_IVLEN];
		unsigned char  *att_buffer;
		/* Tuple attribute description */
		Form_pg_attribute att = TupleDescAttr(tupleDesc, i);

		if (!IS_ENCRYPTABLE_TYPE(att->atttypid, type_oids) || isnull[i])
		{
			/* Not encryptable type or null value*/
			new_values[i] = values[i];
			continue;
		}

		att_buffer = (unsigned char *) VARDATA_ANY(values[i]);
		buffer_len = (int) VARSIZE_ANY_EXHDR(values[i]);

		if (flag == AES_ENCRYPT_FLAG)
		{
			/*
			 * Encryption part
			 */
			crypt_buffer = (char *) palloc(buffer_len + AES_BLOCKLEN
										   + AES_IVLEN + VARHDRSZ);

			/*
			 * Build random AES initialization vector and copy it into
			 * crypt_buffer
			 */
			if (!pg_strong_random(iv, AES_IVLEN))
				goto error_rng;

			/* Store AES IV */
			memcpy(VARDATA(crypt_buffer), iv, AES_IVLEN);

			/* AES encryption */
			crypt_len = AES_CBC_encrypt(att_buffer,
										buffer_len,
										table_key,
										iv,
										(unsigned char *) VARDATA(crypt_buffer)
										+ AES_IVLEN);
			if (crypt_len == -1)
				goto error_encrypt;

			/* Set Datum size to the right size */
			SET_VARSIZE(crypt_buffer, crypt_len + VARHDRSZ + AES_IVLEN);
		}
		else if (flag == AES_DECRYPT_FLAG)
		{
			/*
			 * Decryption part
			 */
			crypt_buffer = (char *) palloc(buffer_len + VARHDRSZ - AES_IVLEN);

			/* Get AES IV */
			memcpy(iv, att_buffer, AES_IVLEN);

			/* AES decryption */
			crypt_len = AES_CBC_decrypt(att_buffer + AES_IVLEN,
										buffer_len - AES_IVLEN,
										table_key,
										iv,
										(unsigned char *) VARDATA(crypt_buffer));
			if (crypt_len == -1)
				goto error_decrypt;

			SET_VARSIZE(crypt_buffer, crypt_len + VARHDRSZ);
		}

		new_values[i] = PointerGetDatum(crypt_buffer);
	}

	MemoryContextSwitchTo(oldcontext);

	/* Build a new tuple with updated (encrypted / decrypted) fields */
	new_tuple = heap_form_tuple(tupleDesc, new_values, isnull);

	/* Copy original tuple transaction informations */
	memcpy(&new_tuple->t_data->t_choice.t_heap,
		   &tuple->t_data->t_choice.t_heap,
		   sizeof(HeapTupleFields));
	memcpy(&new_tuple->t_data->t_choice.t_datum,
		   &tuple->t_data->t_choice.t_datum,
		   sizeof(DatumTupleFields));
	new_tuple->t_data->t_infomask2 = tuple->t_data->t_infomask2;
	new_tuple->t_data->t_infomask = tuple->t_data->t_infomask;
	new_tuple->t_data->t_hoff = tuple->t_data->t_hoff;
	new_tuple->t_data->t_ctid = tuple->t_data->t_ctid;
	memcpy(new_tuple->t_data->t_bits,
		   tuple->t_data->t_bits,
		   BITMAPLEN(HeapTupleHeaderGetNatts(tuple->t_data)));
	new_tuple->t_self = tuple->t_self;
	new_tuple->t_tableOid = tuple->t_tableOid;

	MemoryContextDelete(tmpcontext);

	return new_tuple;

error_rng:
	MemoryContextSwitchTo(oldcontext);
	MemoryContextDelete(tmpcontext);
	ereport(ERROR, (errmsg("tcle: could not generate random AES IV")));

error_encrypt:
	MemoryContextSwitchTo(oldcontext);
	MemoryContextDelete(tmpcontext);
	ereport(ERROR, (errmsg("tcle: could not encrypt data")));

error_decrypt:
	MemoryContextSwitchTo(oldcontext);
	MemoryContextDelete(tmpcontext);
	ereport(ERROR, (errmsg("tcle: could not decrypt data")));
}

/*
 * Initializes command_crypt_state HTAB into TopTransaction memory context. The
 * main goal here is to destroy and free the htab whatever is going on at the
 * end of the transaction. Even if the htab is automatically freed when the
 * memory context is destroyed, we still have to reset command_crypt_state to
 * NULL if we want to reuse it and create a new htab for the next transaction
 * (within the same backend). That's why we add a memory context reset
 * callback in charge of reseting command_crypt_state to NULL.
 */
static void
command_crypt_state_init(void)
{
	HASHCTL		ctl;
	MemoryContextCallback *mcb;
	MemoryContext oldContext;

	MemSet(&ctl, 0, sizeof(ctl));
	ctl.keysize = sizeof(CommandCryptStateKey);
	ctl.entrysize = sizeof(CommandCryptStateEntry);
	ctl.hcxt = TopTransactionContext;

	/*
	 * Create the htab with only 1 element. This is not a shared-memory
	 * htab, so it can be resized if needed.
	 */
	command_crypt_state = hash_create("command_crypt_state", 1, &ctl,
									  HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

	/* Callback struct must be allocated into target memory context */
	oldContext = MemoryContextSwitchTo(TopTransactionContext);

	mcb = (MemoryContextCallback *) palloc(sizeof(MemoryContextCallback));
	mcb->func = command_crypt_state_mcb;
	mcb->arg = NULL;

	MemoryContextSwitchTo(oldContext);
	MemoryContextRegisterResetCallback(TopTransactionContext, mcb);
}

/*
 * Memory context reset callback to reset command_crypt_state.
 */
static void
command_crypt_state_mcb(void *arg)
{
	if (command_crypt_state != NULL)
		command_crypt_state = NULL;
}

/*
 * Add a new entry into command_crypt_state htab. This routine initializes the
 * htab if needed.
 */
static void
command_crypt_state_set(LocalTransactionId lxid, int8 flag,
						unsigned char *tkey)
{
	CommandCryptStateKey *hkey;
	CommandCryptStateEntry *entry;
	bool		found;

	if (command_crypt_state == NULL)
		command_crypt_state_init();

	hkey = (CommandCryptStateKey *) palloc(sizeof(CommandCryptStateKey));
	hkey->lxid = lxid;

	entry = (CommandCryptStateEntry *) hash_search(command_crypt_state, hkey,
												   HASH_ENTER, &found);
	if (!found)
	{
		entry->flag = AES_INVALID_FLAG;
		entry->transient_key = NULL;
	}

	if (flag != AES_INVALID_FLAG)
		entry->flag = flag;

	if (tkey != NULL)
	{
		entry->transient_key = (unsigned char *) palloc(AES_KEYLEN);
		memcpy(entry->transient_key, tkey, AES_KEYLEN);
	}

	pfree(hkey);
}

/*
 * Remove an entry from command_crypt_state htab.
 */
static void
command_crypt_state_rm(LocalTransactionId lxid)
{
	CommandCryptStateKey *hkey;

	hkey = (CommandCryptStateKey *) palloc(sizeof(CommandCryptStateKey));
	hkey->lxid = lxid;

	hash_search(command_crypt_state, hkey, HASH_REMOVE, NULL);

	pfree(hkey);
}

/*
 * Is current command inside current transaction been flagged with
 * AES_NOCRYPT_FLAG ?
 */
static bool
ShouldEncryptDecryptTTS(void)
{
	LocalTransactionId lxid;
	bool			found;
	bool			shouldCrypt = true;
	CommandCryptStateKey *hkey;
	CommandCryptStateEntry *entry;

	lxid = MyProc->lxid;

	if (command_crypt_state == NULL)
		return true;

	hkey = (CommandCryptStateKey *) palloc(sizeof(CommandCryptStateKey));
	hkey->lxid = lxid;

	entry = (CommandCryptStateEntry *) hash_search(command_crypt_state, hkey,
												   HASH_FIND, &found);

	if (found && entry->flag == AES_NOCRYPT_FLAG)
		shouldCrypt = false;

	pfree(hkey);

	return shouldCrypt;
}

/*
 * Flags current command inside current transaction with AES_NOCRYPT_FLAG.
 */
static void
SetNotEncryptDecryptTTS(void)
{
	LocalTransactionId lxid;

	lxid = MyProc->lxid;

	command_crypt_state_set(lxid, AES_NOCRYPT_FLAG, NULL);
}

/*
 * Remove entry from command_crypt_state HTAB.
 */
static void
RemoveCommandCryptState(void)
{
	LocalTransactionId lxid;

	lxid = MyProc->lxid;

	command_crypt_state_rm(lxid);
}

/*
 * Generate a random transient AES key and store it into command_crypt_state
 * HTAB. This is necessary to handle CREATE TABLE .. AS statements because we
 * need an encryption key before standard_ProcessUtility() is executed, and
 * then store this key into KMS table at the end.
 */
static void
BuildCommandTransientKey(void)
{
	unsigned char  *tkey;
	LocalTransactionId lxid;

	lxid = MyProc->lxid;
	tkey = (unsigned char *) palloc(AES_KEYLEN);

	if (!pg_strong_random(tkey, AES_KEYLEN))
		ereport(ERROR,
				(errmsg("tcle: could not generate transient CTAS key")));

	command_crypt_state_set(lxid, AES_INVALID_FLAG, tkey);

	pfree(tkey);
}

/*
 * Get command's transient encryption key if any.
 */
static bool
GetCommandTransientKey(unsigned char **tkeyPtr)
{
	LocalTransactionId lxid;
	bool			found;
	CommandCryptStateKey *hkey;
	CommandCryptStateEntry *entry;

	lxid = MyProc->lxid;

	if (command_crypt_state == NULL)
		return false;

	hkey = (CommandCryptStateKey *) palloc(sizeof(CommandCryptStateKey));
	hkey->lxid = lxid;

	entry = (CommandCryptStateEntry *) hash_search(command_crypt_state, hkey,
												   HASH_FIND, &found);

	if (found && entry->transient_key != NULL)
		memcpy(*tkeyPtr, entry->transient_key, AES_KEYLEN);

	pfree(hkey);

	return found;
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
	EncryptDecryptTupleTableSlot(slot, AES_DECRYPT_FLAG, scan->rel->rd_id);

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
	EncryptDecryptTupleTableSlot(slot, AES_DECRYPT_FLAG, sscan->rs_rd->rd_id);

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
	EncryptDecryptTupleTableSlot(slot, AES_ENCRYPT_FLAG, relation->rd_id);

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
	EncryptDecryptTupleTableSlot(slot, AES_ENCRYPT_FLAG, relation->rd_id);

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
	EncryptDecryptTupleTableSlot(slot, AES_ENCRYPT_FLAG, relation->rd_id);

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
		EncryptDecryptTupleTableSlot(slots[i], AES_ENCRYPT_FLAG,
									 relation->rd_id);

		/* Back to AM routine memory context */
		MemoryContextSwitchTo(oldContext);
	}

	heap_multi_insert(relation, slots, ntuples, cid, options, bistate);
}


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
	/* Flags current command to not encrypt / decrypt tuples */
	SetNotEncryptDecryptTTS();

	GetHeapamTableAmRoutine()->relation_copy_for_cluster(OldHeap, NewHeap,
														 OldIndex, use_sort,
														 OldestXmin,
														 xid_cutoff,
														 multi_cutoff,
														 num_tuples,
														 tups_vacuumed,
														 tups_recently_dead);

	/* Remove command crypt state entry */
	RemoveCommandCryptState();
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

#if (PG_VERSION_NUM >= 130000)
static Oid
tcleam_relation_toast_am(Relation rel)
{
	return GetHeapamTableAmRoutine()->relation_toast_am(rel);
}
#endif

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

static uint64
tcleam_relation_size(Relation rel, ForkNumber forkNumber)
{
	return GetHeapamTableAmRoutine()->relation_size(rel, forkNumber);
}

#if (PG_VERSION_NUM >= 120000 && PG_VERSION_NUM < 130000)
static void
tcleam_finish_bulk_insert(Relation rel, int options)
{
	GetHeapamTableAmRoutine()->finish_bulk_insert(rel, options);
}
#endif

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
#if (PG_VERSION_NUM >= 120000 && PG_VERSION_NUM < 130000)
	.finish_bulk_insert = tcleam_finish_bulk_insert,
#endif

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

	.relation_size = tcleam_relation_size,
	.relation_needs_toast_table = tcleam_relation_needs_toast_table,
#if (PG_VERSION_NUM >= 130000)
	.relation_toast_am = tcleam_relation_toast_am,
	.relation_fetch_toast_slice = heap_fetch_toast_slice,
#endif

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
