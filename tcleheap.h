#ifndef _TCLEHEAP_H_
#define _TCLEHEAP_H_

extern void tcleam_index_validate_scan(Relation heapRelation,
									   Relation indexRelation,
									   IndexInfo *indexInfo,
									   Snapshot snapshot,
									   ValidateIndexState *state);
extern double tcleam_index_build_range_scan(Relation heapRelation,
											Relation indexRelation,
											IndexInfo *indexInfo,
											bool allow_sync,
											bool anyvisible,
											bool progress,
											BlockNumber start_blockno,
											BlockNumber numblocks,
											IndexBuildCallback callback,
											void *callback_state,
											TableScanDesc scan);
extern void
reform_and_rewrite_tuple(HeapTuple tuple,
						 Relation OldHeap, Relation NewHeap,
						 Datum *values, bool *isnull, RewriteState rwstate);

#endif
