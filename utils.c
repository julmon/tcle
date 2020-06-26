/*----------------------------------------------------------------------------
 *
 *                          TCLE utilities
 *
 * Portions Copyright (c) 2020, Julien Tachoires
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
  *
 * IDENTIFICATION
 *	  utils.c
 *
 * Utilities and functions from core source code that are not public in it.
 *
 *----------------------------------------------------------------------------
 */

#include "postgres.h"
#include "access/genam.h"
#include "access/htup_details.h"
#include "access/table.h"
#include "catalog/pg_extension.h"
#include "catalog/pg_extension_d.h"
#include "catalog/indexing.h"
#include "commands/extension.h"
#include "utils/fmgroids.h"

#include "utils.h"

/*
 * get_extension_schema - given an extension OID, fetch its extnamespace
 *
 * Returns InvalidOid if no such extension.
 */
extern Oid
get_extension_schema(Oid ext_oid)
{
	Oid			result;
	Relation	rel;
	SysScanDesc scandesc;
	HeapTuple	tuple;
	ScanKeyData entry[1];

	rel = table_open(ExtensionRelationId, AccessShareLock);

	ScanKeyInit(&entry[0],
				Anum_pg_extension_oid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(ext_oid));

	scandesc = systable_beginscan(rel, ExtensionOidIndexId, true,
								  NULL, 1, entry);

	tuple = systable_getnext(scandesc);

	/* We assume that there can be at most one matching tuple */
	if (HeapTupleIsValid(tuple))
		result = ((Form_pg_extension) GETSTRUCT(tuple))->extnamespace;
	else
		result = InvalidOid;

	systable_endscan(scandesc);

	table_close(rel, AccessShareLock);

	return result;
}
