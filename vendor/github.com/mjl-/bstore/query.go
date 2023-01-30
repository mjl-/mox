package bstore

import (
	"fmt"
	"reflect"
)

// The convention for handling a errors on a Query: methods that return a bool
// will have set q.err using q.error(), which does cleanup. If a method returns
// an error, q.error was not yet called, but usually will be called immediately
// after with the returned err, possibly first adding context.

// Query selects data for Go struct T based on filters, sorting, limits. The
// query is completed by calling an operation, such as Count, Get, List,
// Update, Delete, etc.
//
// Record selection functions like FilterEqual and Limit return the (modified)
// query itself, allowing chaining of calls.
//
// Queries are automatically closed after their operation, with two exceptions:
// After using Next and NextID on a query that did not yet return a non-nil
// error, you must call Close.
//
// A Query is not safe for concurrent use.
type Query[T any] struct {
	st         storeType     // Of T.
	pkType     reflect.Type  // Shortcut for st.Current.Fields[0].
	xtx        *Tx           // If nil, a new transaction is automatically created from db. Using a tx goes through tx() one exists.
	xdb        *DB           // If not nil, xtx was created to execute the operation and is when the operation finishes (also on error).
	err        error         // If set, returned by operations. For indicating failed filters, or that an operation has finished.
	xfilterIDs *filterIDs[T] // Kept separately from filters because these filters make us use the PK without further index planning.
	xfilters   []filter[T]
	xorders    []order

	// If 0, no limit has been set. Otherwise the number of IDs or records to
	// read. Set by limit calls, and set to 1 for an Exists.
	xlimit int

	// Set when Next/NextID is called. We prevent non-Next calls after that moment.
	// Should prevent unexpected results for users.
	nextOnly bool

	gatherIDs reflect.Value // Pointer to slice to pktype, for PKs of updated/deleted records.
	gathers   *[]T          // For full records of updated/deleted records.

	exec *exec[T]

	stats Stats
}

// sentinel interface to for sanity checking.
type filter[T any] interface {
	filter()
}

// filter by one or more IDs.
type filterIDs[T any] struct {
	ids map[any]struct{} // Regular values.
	pks [][]byte         // Packed values.
}

func (filterIDs[T]) filter() {}

type filterFn[T any] struct {
	fn func(value T) bool // Function to call for each record, returning true if the record is selected.
}

func (filterFn[T]) filter() {}

// Filter on field equality.
type filterEqual[T any] struct {
	field  field
	rvalue reflect.Value
}

func (filterEqual[T]) filter() {}

// Filter on field non-equality.
type filterNotEqual[T any] struct {
	field  field
	rvalue reflect.Value
}

func (filterNotEqual[T]) filter() {}

// Like filterEqual, but for one or more values.
type filterIn[T any] struct {
	field   field
	rvalues []reflect.Value
}

func (filterIn[T]) filter() {}

// Like filterNonEqual, but for one or more values.
type filterNotIn[T any] struct {
	field   field
	rvalues []reflect.Value
}

func (filterNotIn[T]) filter() {}

type compareOp byte

const (
	opGreater compareOp = iota
	opGreaterEqual
	opLess
	opLessEqual
)

// filter by comparison.
type filterCompare[T any] struct {
	field field
	op    compareOp
	value reflect.Value
}

func (filterCompare[T]) filter() {}

// ordering of result.
type order struct {
	field field
	asc   bool
}

// Pair represents a primary key with lazily loaded record data. When user only
// cares about IDs we don't have to parse the full record. And if we go through
// in index we don't have to fetch the full record either.
type pair[T any] struct {
	bk    []byte
	bv    []byte // If nil, data must be loaded.
	value *T     // If not nil, the parsed form of bv.
}

// Value returns a fully parsed record. It first fetches the record data if not
// yet present.
func (p *pair[T]) Value(e *exec[T]) (T, error) {
	var zero T
	if p.value != nil {
		return *p.value, nil
	}
	if p.bv == nil {
		e.q.stats.Records.Get++
		p.bv = e.rb.Get(p.bk)
		if p.bv == nil {
			return zero, fmt.Errorf("%w: no data for key", ErrStore)
		}
	}
	var v T
	err := e.q.st.parseFull(reflect.ValueOf(&v).Elem(), p.bk, p.bv)
	if err != nil {
		return zero, err
	}
	p.value = &v
	return v, nil
}

// QueryDB returns a new Query for type T. When an operation on the query is
// executed, a read-only/writable transaction is created as appropriate for the
// operation.
func QueryDB[T any](db *DB) *Query[T] {
	// We lock db for storeTypes. We keep it locked until Query is done.
	db.typesMutex.RLock()
	q := &Query[T]{xdb: db}
	q.init(db)
	return q
}

// Query returns a new Query that operates on type T using transaction tx.
func QueryTx[T any](tx *Tx) *Query[T] {
	// note: Since we are in a transaction, we already hold an rlock on the
	// db types.
	q := &Query[T]{xtx: tx}
	q.init(tx.db)
	return q
}

// Stats returns the current statistics for this query. When a query finishes,
// its stats are added to those of its transaction. When a transaction
// finishes, its stats are added to those of its database.
func (q *Query[T]) Stats() Stats {
	return q.stats
}

func (q *Query[T]) init(db *DB) {
	var v T
	t := reflect.TypeOf(v)
	if t.Kind() != reflect.Struct {
		q.errorf("%w: type must be struct, not pointer or other type", ErrType)
		return
	}
	q.st, q.err = db.storeType(t)
	if q.err == nil {
		q.stats.LastType = q.st.Name
		q.pkType = q.st.Current.Fields[0].structField.Type
	}
}

func (q *Query[T]) tx(write bool) (*Tx, error) {
	if q.xtx == nil {
		if q.xdb == nil {
			q.errorf("%w: missing db and tx: use QueryDB or QueryTx to make a new Query", ErrParam)
			return nil, q.err
		}
		tx, err := q.xdb.bdb.Begin(write)
		if err != nil {
			q.error(err)
			return nil, q.err
		}
		q.xtx = &Tx{db: q.xdb, btx: tx}
		if write {
			q.stats.Writes++
		} else {
			q.stats.Reads++
		}
	}
	return q.xtx, nil
}

// error sets an error for the query, to be returned when next operations are executed.
// All Query instances go through this function for proper rollback and/or runlock
// as needed. If a query finished successfully, ErrFinished is set.
func (q *Query[T]) error(err error) {
	if q.xtx != nil && q.xdb != nil {
		txerr := q.xtx.btx.Rollback()
		if sanityChecks && txerr != nil {
			panic(fmt.Sprintf("xtx rollback: %v", txerr))
		}
		q.dbAddStats()
		q.xtx = nil
	}
	if q.xdb != nil {
		q.xdb.typesMutex.RUnlock()
		q.xdb = nil
	}
	if q.xtx != nil {
		q.txAddStats()
	}
	// This is the only place besides init that sets an error on query.
	q.err = err
}

// errorf calls error with a formatted error.
func (q *Query[T]) errorf(format string, args ...any) {
	q.error(fmt.Errorf(format, args...))
}

// Close closes a Query. Must always be called for Queries on which Next or
// NextID was called. Other operations call Close themselves.
func (q *Query[T]) Close() error {
	var err error
	if q.xtx != nil && q.xdb != nil {
		err = q.xtx.btx.Rollback()
		q.dbAddStats()
		q.xtx = nil
	}
	q.error(ErrFinished)
	return err
}

// txAddStats adds stats to a transaction that Query did not create.
func (q *Query[T]) txAddStats() {
	q.xtx.stats.add(q.stats)
	q.stats = Stats{}
}

// dbAddStats adds stats to the database directly, because Query created the
// transaction and the tx is never exposed, so no need to go through it.
func (q *Query[T]) dbAddStats() {
	q.xdb.statsMutex.Lock()
	q.xdb.stats.add(q.stats)
	q.xdb.statsMutex.Unlock()
	q.stats = Stats{}
}

// Operations that will do database operations get a defer call to this finish
// function, to ensure we also close transactions that we made.
func (q *Query[T]) finish(rerr *error) {
	if q.xtx != nil && q.xdb != nil {
		if *rerr == nil && q.xtx.btx.Writable() {
			if err := q.xtx.btx.Commit(); err != nil {
				*rerr = err
			}
		} else if err := q.xtx.btx.Rollback(); err != nil && sanityChecks {
			panic(fmt.Errorf("rolling back: %v", err))
		}
		q.dbAddStats()
		q.xtx = nil
	}
	x := recover()
	if x != nil {
		q.errorf("%v", x)
		panic(x)
	}
	q.error(ErrFinished)
}

// checkNotNext is called by all operations except Next and NextID to ensure
// that the user does not mix Next/NextID with regular operations.
func (q *Query[T]) checkNotNext() {
	if q.err == nil && q.nextOnly {
		q.errorf("%w: can only use further Next calls", ErrParam)
	}
}

func (q *Query[T]) checkErr() bool {
	if q.err == nil && q.xtx == nil && q.xdb == nil {
		// Probably the result of using a Query zero value.
		q.errorf("%w: invalid query, use QueryDB or QueryTx to make a query", ErrParam)
	}
	return q.err == nil
}

func (q *Query[T]) addFilter(f filter[T]) {
	q.xfilters = append(q.xfilters, f)
}

// nextKey returns the key and optionally value for the next matching record.
// If there is no more matching record, ErrAbsent is returned and the query
// finished. ErrAbsent should be set on the query by the calling operation if
// appropriate (but not for Update/Delete, because it would prevent further
// operations on the query and its transaction).
//
// The actual work is handled by executing a query plan. One is created on the
// first call, and the nextKey is forwarded to the plan execution thereafter.
//
// write indicates if a writable tx needs to be created (if any) for the
// operation that is initiating this data selection.
//
// value indicates if a full record should be parsed and returned, as opposed
// to only the PK. Some callers only care about the IDs of records, which can
// be handled more efficiently when going through an index.
func (q *Query[T]) nextKey(write, value bool) ([]byte, T, error) {
	if q.exec == nil {
		p, err := q.selectPlan()
		if err != nil {
			q.error(err)
			var zero T
			return nil, zero, err
		}
		// log.Printf("plan %#v", p)
		q.exec = p.exec(q)
	}
	return q.exec.nextKey(write, value)
}

// fetch the PK of the next selected record, and parse into pkv.
func (q *Query[T]) nextID(write bool, pkv reflect.Value) error {
	bk, _, err := q.nextKey(write, false)
	if err != nil {
		return err
	}
	return parsePK(pkv, bk)
}

// foreachKey calls fn on each selected record. If value is set, fn's v is set,
// otherwise the zero value.
func (q *Query[T]) foreachKey(write, value bool, fn func(bk []byte, v T) error) error {
	if q.err != nil {
		return q.err
	}
	for {
		bk, v, err := q.nextKey(write, value)
		if err == ErrAbsent {
			return nil
		} else if err != nil {
			return err
		} else if err := fn(bk, v); err != nil {
			q.error(err)
			return err
		}
	}
}

// foreachID calls fn with the primary key value for each selected record.
func (q *Query[T]) foreachID(write bool, fn func(pkv any) error) error {
	if q.err != nil {
		return q.err
	}
	v := reflect.New(q.pkType).Elem()
	for {
		err := q.nextID(write, v)
		if err == ErrAbsent {
			return nil
		} else if err != nil {
			return err
		} else if err := fn(v.Interface()); err != nil {
			q.error(err)
			return err
		}
	}
}

// lookup field name in the current typeVersion.
func (q *Query[T]) lookupField(name string) (field, bool) {
	for _, ff := range q.st.Current.Fields {
		if ff.Name == name {
			return ff, true
		}
	}
	q.errorf("%w: unknown field %q", ErrParam, name)
	return field{}, false
}

// Kinds that can be converted without loss of precision, identity is not in here.
type convertKinds struct{ from, to kind }

var convertFieldKinds = map[convertKinds]struct{}{
	{kindInt8, kindInt16}:  {},
	{kindInt8, kindInt32}:  {},
	{kindInt8, kindInt64}:  {},
	{kindInt8, kindInt}:    {},
	{kindInt16, kindInt32}: {},
	{kindInt16, kindInt64}: {},
	{kindInt16, kindInt}:   {},
	{kindInt32, kindInt}:   {},
	{kindInt32, kindInt64}: {},
	{kindInt, kindInt32}:   {},
	{kindInt, kindInt64}:   {},

	{kindUint8, kindUint16}:  {},
	{kindUint8, kindUint32}:  {},
	{kindUint8, kindUint64}:  {},
	{kindUint8, kindUint}:    {},
	{kindUint16, kindUint32}: {},
	{kindUint16, kindUint64}: {},
	{kindUint16, kindUint}:   {},
	{kindUint32, kindUint}:   {},
	{kindUint32, kindUint64}: {},
	{kindUint, kindUint32}:   {},
	{kindUint, kindUint64}:   {},

	{kindFloat32, kindFloat64}: {},
}

// Check type of value for field and return a reflect value that can directly be set on the field.
// If the field is a pointer, we allow non-pointers and convert them.
// We require value to be of a type that can be converted without loss of precision to the type of field.
func (q *Query[T]) prepareValue(fname string, ft fieldType, sf reflect.StructField, rv reflect.Value) (reflect.Value, bool) {
	if !rv.IsValid() {
		q.errorf("%w: invalid value", ErrParam)
		return rv, false
	}
	// Quick check first.
	t := rv.Type()
	if t == sf.Type {
		return rv, true
	}
	if !ft.Ptr && rv.Kind() == reflect.Ptr {
		q.errorf("%w: cannot set ptr value to nonptr field", ErrParam)
		return rv, false
	}

	k, err := typeKind(t)
	if err != nil {
		q.errorf("%w: type of field: %s", ErrParam, err)
		return reflect.Value{}, false
	}
	if _, ok := convertFieldKinds[convertKinds{k, ft.Kind}]; !ok && k != ft.Kind {
		q.errorf("%w: got %v for field %q, need %v", ErrParam, rv.Type(), fname, ft.Kind)
		return reflect.Value{}, false
	}
	if k != ft.Kind {
		dt := sf.Type
		if ft.Ptr {
			dt = dt.Elem()
		}
		rv = rv.Convert(dt)
	}
	if ft.Ptr && rv.Kind() != reflect.Ptr {
		nv := reflect.New(sf.Type.Elem())
		nv.Elem().Set(rv)
		rv = nv
	}
	return rv, true
}

// checkPK checks if t is the type of the current typeVersion's PK, and returns
// a userfriendly error message otherwise.
func (q *Query[T]) checkPK(t reflect.Type) bool {
	if t != q.pkType {
		q.errorf("%w: id type was %s, must be %s", ErrParam, t, q.pkType)
		return false
	}
	return true
}

// FilterID selects the records with primary key id, which must be of the type
// of T's primary key.
func (q *Query[T]) FilterID(id any) *Query[T] {
	if !q.checkErr() {
		return q
	}
	kv := reflect.ValueOf(id)
	if !q.checkPK(kv.Type()) {
		return q
	}
	pk, err := packPK(kv)
	if err != nil {
		q.error(err)
		return q
	}

	if q.xfilterIDs != nil {
		// Intersection of this ID with the previous IDs. Either it is this single ID or the list becomes empty.
		if _, ok := q.xfilterIDs.ids[id]; !ok {
			q.xfilterIDs = &filterIDs[T]{map[any]struct{}{}, [][]byte{}}
			return q
		}
	}
	q.xfilterIDs = &filterIDs[T]{map[any]struct{}{id: {}}, [][]byte{pk}}
	return q
}

// FilterIDs selects the records with a primary key that is in ids. Ids must be
// a slice of T's primary key type.
func (q *Query[T]) FilterIDs(ids any) *Query[T] {
	if !q.checkErr() {
		return q
	}
	kv := reflect.ValueOf(ids)
	if kv.Kind() != reflect.Slice {
		q.errorf("%w: ids must be slice of %v, not %T", ErrParam, q.pkType, ids)
		return q
	}
	if !q.checkPK(kv.Type().Elem()) {
		return q
	}

	n := kv.Len()
	pks := make([][]byte, 0, n)
	var prevIDs map[any]struct{}
	if q.xfilterIDs != nil {
		prevIDs = q.xfilterIDs.ids // We use this to check intersection.
	}
	// todo: should we fail for a zero PK?
	nids := map[any]struct{}{}
	for i := 0; i < n; i++ {
		rev := kv.Index(i)
		ev := rev.Interface()
		if _, ok := prevIDs[ev]; !ok && prevIDs != nil {
			continue
		}
		nids[ev] = struct{}{}
		pk, err := packPK(rev)
		if err != nil {
			q.error(err)
			return q
		}
		pks = append(pks, pk)
	}
	q.xfilterIDs = &filterIDs[T]{nids, pks}
	return q
}

// FilterFn calls fn for each record selected so far. If fn returns true, the
// record is kept for further filters and finally the operation.
func (q *Query[T]) FilterFn(fn func(value T) bool) *Query[T] {
	if !q.checkErr() {
		return q
	}
	if fn == nil {
		q.errorf("%w: nil fn", ErrParam)
		return q
	}
	q.addFilter(filterFn[T]{fn})
	return q
}

// gatherNonzeroFields returns fields and values that are non-zero. Used for
// Update and FilterNonzero.
//
// allowID indicates if the primary key is allowed to be nonzero (not for
// Updates).
//
// At least one field must be nonzero.
func gatherNonzeroFields(tv *typeVersion, rv reflect.Value, allowID bool) ([]field, []reflect.Value, error) {
	var fields []field
	var values []reflect.Value

	for i, f := range tv.Fields {
		fv := rv.FieldByIndex(f.structField.Index)
		if f.Type.isZero(fv) {
			continue
		}
		if i == 0 && !allowID {
			return nil, nil, fmt.Errorf("%w: primary key must be zero", ErrParam)
		}
		fields = append(fields, f)
		values = append(values, fv)
	}
	if len(fields) == 0 {
		return nil, nil, fmt.Errorf("%w: must have at least one nonzero field", ErrParam)
	}
	return fields, values, nil
}

// FilterNonzero gathers the nonzero fields from value, and selects records that
// have equal values for those fields. At least one value must be nonzero. If a
// value comes from an external source, e.g. user input, make sure it is not
// the zero value.
//
// Keep in mind that filtering on an embed/anonymous field looks at individual
// fields in the embedded field for non-zeroness, not at the embed field as a whole.
func (q *Query[T]) FilterNonzero(value T) *Query[T] {
	if !q.checkErr() {
		return q
	}
	fields, values, err := gatherNonzeroFields(q.st.Current, reflect.ValueOf(value), true)
	if err != nil {
		q.error(err)
		return q
	}
	for i, f := range fields {
		if f.Name == q.st.Current.Fields[0].Name {
			q.FilterID(values[i].Interface())
		} else {
			q.addFilter(filterEqual[T]{f, values[i]})
		}
	}
	return q
}

// FilterEqual selects records that have one of values for fieldName.
//
// Note: Value must be a compatible type for comparison with fieldName. Go
// constant numbers become ints, which are not compatible with uint or float
// types.
func (q *Query[T]) FilterEqual(fieldName string, values ...any) *Query[T] {
	q.filterEqual(fieldName, values, false)
	return q
}

// FilterNotEqual selects records that do not have any of values for fieldName.
func (q *Query[T]) FilterNotEqual(fieldName string, values ...any) *Query[T] {
	q.filterEqual(fieldName, values, true)
	return q
}

func (q *Query[T]) filterEqual(fieldName string, values []any, not bool) {
	if !q.checkErr() {
		return
	}
	ff, ok := q.lookupField(fieldName)
	if !ok {
		return
	}
	if len(values) == 0 {
		q.errorf("%w: need at least one value for (not) equal", ErrParam)
		return
	}
	if ff.Type.Ptr {
		q.errorf("%w: cannot compare pointer values", ErrParam)
		return
	}
	if len(values) == 1 {
		rv, ok := q.prepareValue(ff.Name, ff.Type, ff.structField, reflect.ValueOf(values[0]))
		if !ok {
			return
		}
		if not {
			q.addFilter(filterNotEqual[T]{ff, rv})
		} else {
			q.addFilter(filterEqual[T]{ff, rv})
		}
		return
	}
	rvs := make([]reflect.Value, len(values))
	for i, value := range values {
		rv, ok := q.prepareValue(ff.Name, ff.Type, ff.structField, reflect.ValueOf(value))
		if !ok {
			return
		}
		rvs[i] = rv
	}
	if not {
		q.addFilter(filterNotIn[T]{ff, rvs})
	} else {
		q.addFilter(filterIn[T]{ff, rvs})
	}
}

// FilterGreater selects records that have fieldName > value.
//
// Note: Value must be a compatible type for comparison with fieldName. Go
// constant numbers become ints, which are not compatible with uint or float
// types.
func (q *Query[T]) FilterGreater(fieldName string, value any) *Query[T] {
	return q.filterCompare(fieldName, opGreater, reflect.ValueOf(value))
}

// FilterGreaterEqual selects records that have fieldName >= value.
func (q *Query[T]) FilterGreaterEqual(fieldName string, value any) *Query[T] {
	return q.filterCompare(fieldName, opGreaterEqual, reflect.ValueOf(value))
}

// FilterLess selects records that have fieldName < value.
func (q *Query[T]) FilterLess(fieldName string, value any) *Query[T] {
	return q.filterCompare(fieldName, opLess, reflect.ValueOf(value))
}

// FilterLessEqual selects records that have fieldName <= value.
func (q *Query[T]) FilterLessEqual(fieldName string, value any) *Query[T] {
	return q.filterCompare(fieldName, opLessEqual, reflect.ValueOf(value))
}

func (q *Query[T]) filterCompare(fieldName string, op compareOp, value reflect.Value) *Query[T] {
	if !q.checkErr() {
		return q
	}
	ff, ok := q.lookupField(fieldName)
	if !ok {
		return q
	}
	if !comparable(ff.Type) {
		q.errorf("%w: cannot compare %s", ErrParam, ff.Type.Kind)
		return q
	}
	rv, ok := q.prepareValue(ff.Name, ff.Type, ff.structField, value)
	if !ok {
		return q
	}
	q.addFilter(filterCompare[T]{ff, op, rv})
	return q
}

// Limit stops selecting records after the first n records.
// Can only be called once. n must be > 1.
func (q *Query[T]) Limit(n int) *Query[T] {
	if !q.checkErr() {
		return q
	}
	if n <= 0 {
		q.errorf("%w: limit must be >= 1", ErrParam)
		return q
	}
	if q.xlimit > 0 {
		q.errorf("%w: already have a limit", ErrParam)
		return q
	}
	q.xlimit = n
	return q
}

// SortAsc sorts the selected records by fieldNames in ascending order.
// Additional orderings can be added by more calls to SortAsc or SortDesc.
func (q *Query[T]) SortAsc(fieldNames ...string) *Query[T] {
	return q.order(fieldNames, true)
}

// SortDesc sorts the selected records by fieldNames in descending order.
// Additional orderings can be added by more calls to SortAsc or SortDesc.
func (q *Query[T]) SortDesc(fieldNames ...string) *Query[T] {
	return q.order(fieldNames, false)
}

func (q *Query[T]) order(fieldNames []string, asc bool) *Query[T] {
	if !q.checkErr() {
		return q
	}
	if len(fieldNames) == 0 {
		q.errorf("%w: sort fieldNames must be non-empty", ErrParam)
		return q
	}
	for _, name := range fieldNames {
		ff, ok := q.lookupField(name)
		if !ok {
			return q
		}
		if !comparable(ff.Type) {
			q.errorf("%w: cannot sort by unorderable %q", ErrParam, name)
			return q
		}
		q.xorders = append(q.xorders, order{ff, asc})
	}
	return q
}

// Gather causes an Update or Delete operation to return the values of the
// affect records into l. For Update, the updated records are returned.
func (q *Query[T]) Gather(l *[]T) *Query[T] {
	if !q.checkErr() {
		return q
	}
	if l == nil {
		q.errorf("%w: l must be non-nil", ErrParam)
		return q
	}
	if q.gathers != nil {
		q.errorf("%w: can only have one Gather", ErrParam)
		return q
	}
	q.gathers = l
	return q
}

// GatherIDs causes an Update or Delete operation to return the primary keys of
// affected records into ids, which must be a pointer to a slice of T's
// primary key.
func (q *Query[T]) GatherIDs(ids any) *Query[T] {
	if !q.checkErr() {
		return q
	}
	if ids == nil {
		q.errorf("%w: ids must be non-nil", ErrParam)
		return q
	}
	rv := reflect.ValueOf(ids)
	t := rv.Type()
	if t.Kind() != reflect.Ptr || t.Elem().Kind() != reflect.Slice || t.Elem().Elem() != q.pkType {
		q.errorf("%w: ids must be pointer to slice of %v, not %T", ErrParam, q.pkType, ids)
		return q
	}
	if q.gatherIDs.IsValid() {
		q.errorf("%w: can only have one GatherIDs", ErrParam)
		return q
	}
	q.gatherIDs = rv
	return q
}

func (q *Query[T]) gather(v T, rv reflect.Value) {
	if q.gathers != nil {
		*q.gathers = append(*q.gathers, v)
	}
	if q.gatherIDs.IsValid() {
		ridv := rv.FieldByIndex(q.st.Current.Fields[0].structField.Index)
		l := q.gatherIDs.Elem()
		nl := reflect.Append(l, ridv)
		l.Set(nl)
	}
}

// Err returns if an error is set on the query. Can happen for invalid filters.
// Finished queries return ErrFinished.
func (q *Query[T]) Err() error {
	q.checkErr()
	return q.err
}

// Delete removes the selected records, returning how many were deleted.
//
// See Gather and GatherIDs for collecting the deleted records or IDs.
func (q *Query[T]) Delete() (deleted int, rerr error) {
	defer q.finish(&rerr)
	q.checkNotNext()
	if !q.checkErr() {
		return 0, q.err
	}

	n := 0
	err := q.foreachKey(true, true, func(bk []byte, ov T) error {
		n++
		rov := reflect.ValueOf(ov)
		q.gather(ov, rov)
		q.stats.Delete++
		return q.xtx.delete(q.exec.rb, q.st, bk, rov)
	})
	return n, err
}

// Get returns the single selected record.
//
// ErrMultiple is returned if multiple records were selected.
// ErrAbsent is returned if no record was selected.
func (q *Query[T]) Get() (value T, rerr error) {
	defer q.finish(&rerr)
	q.checkNotNext()
	if !q.checkErr() {
		var zero T
		return zero, q.err
	}

	if _, v, err := q.nextKey(false, true); err != nil {
		return v, err
	} else if _, _, err := q.nextKey(false, false); err == nil {
		return v, ErrMultiple
	} else {
		return v, nil
	}
}

// Count returns the number of selected records.
func (q *Query[T]) Count() (n int, rerr error) {
	defer q.finish(&rerr)
	q.checkNotNext()
	if !q.checkErr() {
		return 0, q.err
	}

	err := q.foreachKey(false, false, func(kb []byte, unused T) error {
		n++
		return nil
	})
	return n, err
}

// List returns all selected records.
// On success with zero selected records, List returns the empty list.
func (q *Query[T]) List() (list []T, rerr error) {
	defer q.finish(&rerr)
	q.checkNotNext()
	if !q.checkErr() {
		return nil, q.err
	}

	l := []T{}
	err := q.foreachKey(false, true, func(unused []byte, v T) error {
		l = append(l, v)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

// UpdateNonzero updates all selected records with the non-zero fields from
// value, returning the number of records updated.
//
// Recall that false, 0, "" are all zero values. Use UpdateField or
// UpdateFields to set fields to zero their value. This is especially relevant
// if the field value comes from an external source, e.g. user input.
//
// See Gather and GatherIDs for collecting the updated records or IDs.
//
// Keep in mind that updating on an embed/anonymous field looks at individual
// fields in the embedded field for non-zeroness, not at the embed field as a whole.
func (q *Query[T]) UpdateNonzero(value T) (updated int, rerr error) {
	defer q.finish(&rerr)
	q.checkNotNext()
	if !q.checkErr() {
		return 0, q.err
	}

	fields, values, err := gatherNonzeroFields(q.st.Current, reflect.ValueOf(value), false)
	if err != nil {
		return 0, err
	}
	sfl := make([]reflect.StructField, len(fields))
	for i, f := range fields {
		sfl[i] = f.structField
	}
	return q.update(sfl, values)
}

// UpdateField calls UpdateFields for fieldName and value.
func (q *Query[T]) UpdateField(fieldName string, value any) (updated int, rerr error) {
	return q.UpdateFields(map[string]any{fieldName: value})
}

// UpdateFields updates all selected records, setting fields named by the map
// keys of fieldValues to the corresponding map value and returning the number
// of records updated.
//
// See Gather and GatherIDs for collecting the updated records or IDs.
//
// Entire embed fields can be updated, as well as their individual embedded
// fields.
func (q *Query[T]) UpdateFields(fieldValues map[string]any) (updated int, rerr error) {
	defer q.finish(&rerr)
	q.checkNotNext()
	if !q.checkErr() {
		return 0, q.err
	}

	if len(fieldValues) == 0 {
		return 0, fmt.Errorf("%w: must update at least one field", ErrParam)
	}

	fields := make([]reflect.StructField, 0, len(fieldValues))
	values := make([]reflect.Value, 0, len(fieldValues))
next:
	for name, value := range fieldValues {
		for i, f := range q.st.Current.Fields {
			if f.Name != name {
				continue
			}
			if i == 0 {
				return 0, fmt.Errorf("%w: cannot update primary key", ErrParam)
			}
			rv, ok := q.prepareValue(f.Name, f.Type, f.structField, reflect.ValueOf(value))
			if !ok {
				return 0, q.err
			}
			fields = append(fields, f.structField)
			values = append(values, rv)
			continue next
		}
		for _, ef := range q.st.Current.embedFields {
			if ef.Name != name {
				continue
			}
			rv, ok := q.prepareValue(ef.Name, ef.Type, ef.structField, reflect.ValueOf(value))
			if !ok {
				return 0, q.err
			}
			fields = append(fields, ef.structField)
			values = append(values, rv)
			continue next
		}
		return 0, fmt.Errorf("%w: unknown field %q", ErrParam, name)
	}
	return q.update(fields, values)
}

func (q *Query[T]) update(fields []reflect.StructField, values []reflect.Value) (int, error) {
	n := 0
	ov := reflect.New(q.st.Type).Elem()
	err := q.foreachKey(true, true, func(bk []byte, v T) error {
		n++
		rv := reflect.ValueOf(&v).Elem()
		ov.Set(rv)
		for i, sf := range fields {
			frv := rv.FieldByIndex(sf.Index)
			frv.Set(values[i])
		}
		q.gather(v, rv)
		q.stats.Update++
		return q.xtx.update(q.exec.rb, q.st, rv, ov, bk)
	})
	return n, err
}

// IDs sets idsptr to the primary keys of selected records. Idptrs must be a
// slice of T's primary key type.
func (q *Query[T]) IDs(idsptr any) (rerr error) {
	defer q.finish(&rerr)
	q.checkNotNext()
	if !q.checkErr() {
		return q.err
	}

	if idsptr == nil {
		return fmt.Errorf("%w: idsptr must not be nil", ErrParam)
	}
	rv := reflect.ValueOf(idsptr)
	if rv.Type().Kind() != reflect.Ptr || rv.Type().Elem().Kind() != reflect.Slice || rv.Type().Elem().Elem() != q.pkType {
		return fmt.Errorf("%w: idsptr must be a ptr to slice of %v, not %T", ErrParam, q.pkType, idsptr)
	}

	s := reflect.MakeSlice(rv.Type().Elem(), 0, 0)
	err := q.foreachID(false, func(pkv any) error {
		s = reflect.Append(s, reflect.ValueOf(pkv))
		return nil
	})
	if err != nil {
		return err
	}
	rv.Elem().Set(s)
	return nil
}

// Next fetches the next record, moving the cursor forward.
//
// ErrAbsent is returned if no more records match.
//
// Automatically created transactions are read-only.
//
// Close must be called on a Query on which Next or NextID was called and that
// is not yet finished, i.e. has not yet returned an error (including
// ErrAbsent).
func (q *Query[T]) Next() (value T, rerr error) {
	// note: no q.finish preamble because caller iterates over result themselves.
	if !q.checkErr() {
		var zero T
		return zero, q.err
	}

	q.nextOnly = true
	_, v, err := q.nextKey(false, true)
	if err == ErrAbsent {
		q.error(err)
	}
	return v, err
}

// NextID is like Next, but only fetches the primary key of the next matching
// record, storing it in idptr.
func (q *Query[T]) NextID(idptr any) (rerr error) {
	// note: no q.finish preamble because caller iterates over result themselves.
	if !q.checkErr() {
		return q.err
	}

	q.nextOnly = true
	rpkv := reflect.ValueOf(idptr)
	if idptr == nil {
		q.errorf("%w: idptr must be non-nil", ErrParam)
		return q.err
	}
	t := rpkv.Type()
	if t.Kind() != reflect.Ptr || t.Elem() != q.pkType {
		return fmt.Errorf("%w: value must be ptr to %v, not %v", ErrParam, q.pkType, t)
	}
	err := q.nextID(false, rpkv.Elem())
	if err == ErrAbsent {
		q.error(err)
	}
	return err
}

// Exists returns whether any record was selected.
func (q *Query[T]) Exists() (exists bool, rerr error) {
	defer q.finish(&rerr)
	q.checkNotNext()
	if !q.checkErr() {
		return false, q.err
	}

	q.xlimit = 1
	_, _, err := q.nextKey(false, false)
	if err == ErrAbsent {
		return false, nil
	}
	return err == nil, err
}

// ForEach calls fn on each selected record.
func (q *Query[T]) ForEach(fn func(value T) error) (rerr error) {
	defer q.finish(&rerr)
	q.checkNotNext()
	if !q.checkErr() {
		return q.err
	}

	return q.foreachKey(false, true, func(bk []byte, v T) error {
		return fn(v)
	})
}
