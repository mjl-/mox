package bstore

// StatsKV represent operations on the underlying BoltDB key/value store.
type StatsKV struct {
	Get    uint
	Put    uint // For Stats.Bucket, this counts calls of CreateBucket.
	Delete uint
	Cursor uint // Any cursor operation: Seek/First/Last/Next/Prev.
}

// Stats tracks DB/Tx/Query statistics, mostly counters.
type Stats struct {
	// Number of read-only or writable transactions. Set for DB only.
	Reads  uint
	Writes uint

	Bucket  StatsKV // Use of buckets.
	Records StatsKV // Use of records bucket for types.
	Index   StatsKV // Use of index buckets for types.

	// Operations that modify the database. Each record is counted, e.g.
	// for a query that updates/deletes multiple records.
	Get    uint
	Insert uint
	Update uint
	Delete uint

	Queries       uint   // Total queries executed.
	PlanTableScan uint   // Full table scans.
	PlanPK        uint   // Primary key get.
	PlanUnique    uint   // Full key Unique index get.
	PlanPKScan    uint   // Scan over primary keys.
	PlanIndexScan uint   // Scan over index.
	Sort          uint   // In-memory collect and sort.
	LastType      string // Last type queried.
	LastIndex     string // Last index for LastType used for a query, or empty.
	LastOrdered   bool   // Whether last scan (PK or index) use was ordered, e.g. for sorting or because of a comparison filter.
	LastAsc       bool   // If ordered, whether last index scan was ascending.
	Reseek        uint   // Number of cursor reseeks due to updates during queries.
}

func (skv *StatsKV) add(n StatsKV) {
	skv.Get += n.Get
	skv.Put += n.Put
	skv.Delete += n.Delete
	skv.Cursor += n.Cursor
}

func (skv *StatsKV) sub(n StatsKV) {
	skv.Get -= n.Get
	skv.Put -= n.Put
	skv.Delete -= n.Delete
	skv.Cursor -= n.Cursor
}

func (st *Stats) add(n Stats) {
	st.Reads += n.Reads
	st.Writes += n.Writes

	st.Bucket.add(n.Bucket)
	st.Records.add(n.Records)
	st.Index.add(n.Index)

	st.Get += n.Get
	st.Insert += n.Insert
	st.Update += n.Update
	st.Delete += n.Delete

	st.Queries += n.Queries
	st.PlanTableScan += n.PlanTableScan
	st.PlanPK += n.PlanPK
	st.PlanUnique += n.PlanUnique
	st.PlanPKScan += n.PlanPKScan
	st.PlanIndexScan += n.PlanIndexScan
	st.Sort += n.Sort

	st.LastType = n.LastType
	st.LastIndex = n.LastIndex
	st.LastOrdered = n.LastOrdered
	st.LastAsc = n.LastAsc
	st.Reseek += n.Reseek
}

// Sub returns st with the counters from o subtracted.
func (st Stats) Sub(o Stats) Stats {
	st.Reads -= o.Reads
	st.Writes -= o.Writes

	st.Bucket.sub(o.Bucket)
	st.Records.sub(o.Records)
	st.Index.sub(o.Index)

	st.Get -= o.Get
	st.Insert -= o.Insert
	st.Update -= o.Update
	st.Delete -= o.Delete

	st.Queries -= o.Queries
	st.PlanTableScan -= o.PlanTableScan
	st.PlanPK -= o.PlanPK
	st.PlanUnique -= o.PlanUnique
	st.PlanPKScan -= o.PlanPKScan
	st.PlanIndexScan -= o.PlanIndexScan
	st.Sort -= o.Sort
	st.Reseek -= o.Reseek

	return st
}
