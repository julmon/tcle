#ifndef _KMS_H_
#define _KMS_H_

/* Action tags */
#define AT_ADD_KEY		1
#define AT_DEL_KEY		2
#define AT_MOV_KEY		3
#define AT_DEL_NSP_KEY  4
#define AT_MOV_NSP_KEY  5
#define AT_ADD_CTAS_KEY 6

/* Shared memory lock for master keys hash table */
typedef struct ShmemKMSMasterKeysLock {
	LWLock		   *lock;
} ShmemKMSMasterKeysLock;

/* Hash key for master keys, this is the database Oid */
typedef Oid KMSMasterKeysHashKey;

/* Hash entry for master keys */
typedef struct KMSMasterKeysEntry {
	KMSMasterKeysHashKey key;
	unsigned char	master_key[AES_KEYLEN];
} KMSMasterKeysEntry;

typedef struct KMSKeyAction {
	Oid				relid;
	Oid				nspid;
	char		   *relname;
	char		   *nspname;
	char		   *new_relname;
	char		   *new_nspname;
	int				action_tag;
	unsigned char  *ctas_key;
} KMSKeyAction;

typedef struct KMSKeyCacheEntry {
	Oid				relid;
	Oid				datid;
	unsigned char	key[AES_KEYLEN];
} KMSKeyCacheEntry;

#define KMS_CACHE_SIZE		1000
#define KMS_MAX_DATABASES	1000

typedef struct ShmemKMSKeyCache {
	KMSKeyCacheEntry buffer[KMS_CACHE_SIZE]; /* Ring buffer of 1000 entries */
	LWLock		   *lock;
	int				position;
	int				n_entries;
} ShmemKMSKeyCache;

extern KMSKeyAction * new_kkact(void);
extern KMSKeyAction * RelationGetKMSKeyAction(RangeVar *rel);
extern void ApplyKMSKeyActions(List *actions, unsigned char *master_key);
extern bool AddKMSCipherKey(char *nspname, char *relname, bytea *cipher_key);
extern bool DeleteKMSKey(char *nspname, char *relname);
extern bool MoveKMSKey(char *nspname, char *relname, char *new_relname);
extern bool MoveNamespaceKMSKey(char *nspname,
								char *relname,
								char *new_nspname);
extern bool MoveNamespaceKMSKeys(char *nspname, char *new_nspname);
extern bool DeleteNamespaceKMSKeys(char *nspname);
extern bool GetKMSCipherKey(Oid relid, bytea **cipher_keyPtr);
extern bool DecryptKMSCipherKey(bytea *cipher_key,
								unsigned char *master_key,
								unsigned char **plain_keyPtr);
extern bool CacheGetRelationKey(ShmemKMSKeyCache *shmkeycache,
								Oid datid,
								Oid relid,
								unsigned char **keyPtr);
extern void CacheAddRelationKey(ShmemKMSKeyCache *shmkeycache,
								Oid datid,
								Oid relid,
								unsigned char *key);
extern bool GetDatabaseMasterKey(ShmemKMSMasterKeysLock *shmmasterkeyslock,
								 HTAB *shmmasterkeys,
								 Oid datid,
								 unsigned char **keyPtr);
extern void AddDatabaseMasterKey(ShmemKMSMasterKeysLock *shmmasterkeyslock,
								 HTAB *shmmasterkeys,
								 Oid datid,
								 unsigned char key[AES_KEYLEN]);
extern void RemoveDatabaseMasterKey(ShmemKMSMasterKeysLock *shmmasterkeyslock,
									HTAB *shmmasterkeys,
									Oid datid);
extern bool CheckKMSMasterKey(unsigned char *master_key);

#endif
