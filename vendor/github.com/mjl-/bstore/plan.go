package bstore

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
)

// todo: cache query plans? perhaps explicitly through something like a prepared statement. the current plan includes values in keys,start,stop, which would need to be calculated for each execution. should benchmark time spent in planning first.
// todo optimize: combine multiple filter (not)in/equals calls for same field
// todo optimize: efficiently pack booleans in an index (eg for Message.Flags), and use it to query.
// todo optimize: do multiple range scans if necessary when we can use an index for an equal check with multiple values.

// Plan represents a plan to execute a query, possibly using a simple/quick
// bucket "get" or cursor scan (forward/backward) on either the records or an
// index.
type plan[T any] struct {
	// The index for this plan. If nil, we are using pk's, in which case
	// "keys" below can be nil for a range scan with start/stop (possibly empty
	// for full scan), or non-nil for looking up specific keys.
	idx *index

	// Use full unique index to get specific values from keys. idx above can be
	// a unique index that we only use partially. In that case, this field is
	// false.
	unique bool

	// If not nil, used to fetch explicit keys when using pk or unique
	// index. Required non-nil for unique.
	keys [][]byte

	desc bool // Direction of the range scan.
	// First key to scan. Filters below may still apply. If desc, this value is > than
	// stop (if it is set). If nil, we begin ranging at the first or last (for desc)
	// key.
	start []byte
	// Last key to scan. Can be nil independently of start.
	stop []byte
	// If the start and stop values are inclusive or exclusive.
	startInclusive bool
	stopInclusive  bool

	// Filter we need to apply after retrieving the record. If all original filters
	// from a query were handled by "keys" above, or by a range scan, this field is
	// empty.
	filters []filter[T]

	// Number of fields from index used to group results before applying in-memory
	// ordering with "orders" below.
	norderidxuse int

	// Orders we need to apply after first retrieving all records with equal values for
	// first norderidxuse fields. As with filters, if a range scan takes care of all
	// orderings from the query, this field is empty.
	orders []order
}

// selectPlan selects the best plan for this query.
func (q *Query[T]) selectPlan() (*plan[T], error) {
	// Simple case first: List of known IDs. We can just fetch them from
	// the records bucket by their primary keys. This is common for a
	// "Get" query.
	if q.xfilterIDs != nil {
		orders := q.xorders
		keys := q.xfilterIDs.pks
		// If there is an ordering on the PK field, we do the ordering here.
		if len(orders) > 0 && orders[0].field.Name == q.st.Current.Fields[0].Name {
			asc := orders[0].asc
			sort.Slice(keys, func(i, j int) bool {
				cmp := bytes.Compare(keys[i], keys[j])
				return asc && cmp < 0 || !asc && cmp > 0
			})
			orders = orders[1:]
		}
		p := &plan[T]{
			keys:    keys,
			filters: q.xfilters,
			orders:  orders,
		}
		return p, nil
	}

	// Try using a fully matched unique index. We build a map with all
	// fields that have an equal or in filter. So we can easily look
	// through our unique indices and get a match. We only look at a single
	// filter per field. If there are multiple, we would use the last one.
	// That's okay, we'll filter records out when we execute the leftover
	// filters. Probably not common.
	// This is common for filterEqual and filterIn on fields that have a unique index.
	equalsIn := map[string]*filter[T]{}
	for i := range q.xfilters {
		ff := &q.xfilters[i]
		switch f := (*ff).(type) {
		case filterEqual[T]:
			equalsIn[f.field.Name] = ff
		case filterIn[T]:
			equalsIn[f.field.Name] = ff
		}
	}
indices:
	for _, idx := range q.st.Current.Indices {
		// Direct fetches only for unique indices.
		if !idx.Unique {
			continue
		}
		for _, f := range idx.Fields {
			if _, ok := equalsIn[f.Name]; !ok {
				// At least one index field does not have a filter.
				continue indices
			}
		}
		// Calculate all keys that we need to retrieve from the index.
		// todo optimize: if there is a sort involving these fields, we could do the sorting before fetching data.
		// todo optimize: we can generate the keys on demand, will help when limit is in use: we are not generating all keys.
		var keys [][]byte
		var skipFilters []*filter[T] // Filters to remove from the full list because they are handled by quering the index.
		for i, f := range idx.Fields {
			var rvalues []reflect.Value
			ff := equalsIn[f.Name]
			skipFilters = append(skipFilters, ff)
			switch fi := (*ff).(type) {
			case filterEqual[T]:
				rvalues = []reflect.Value{fi.rvalue}
			case filterIn[T]:
				rvalues = fi.rvalues
			default:
				return nil, fmt.Errorf("internal error: bad filter %T", equalsIn[f.Name])
			}
			fekeys := make([][]byte, len(rvalues))
			for j, fv := range rvalues {
				ikl, err := packIndexKeys([]reflect.Value{fv}, nil)
				if err != nil {
					q.error(err)
					return nil, err
				}
				if len(ikl) != 1 {
					return nil, fmt.Errorf("internal error: multiple index keys for unique index (%d)", len(ikl))
				}
				fekeys[j] = ikl[0].pre
			}
			if i == 0 {
				keys = fekeys
				continue
			}
			// Multiply current keys with the new values.
			nkeys := make([][]byte, 0, len(keys)*len(fekeys))
			for _, k := range keys {
				for _, fk := range fekeys {
					nk := append(append([]byte{}, k...), fk...)
					nkeys = append(nkeys, nk)
				}
			}
			keys = nkeys
		}
		p := &plan[T]{
			idx:     idx,
			unique:  true,
			keys:    keys,
			filters: dropFilters(q.xfilters, skipFilters),
			orders:  q.xorders,
		}
		return p, nil
	}

	// Try all other indices. We treat them all as non-unique indices now.
	// We want to use the one with as many "equal" or "inslice" field filters as
	// possible. Then we hope to use a scan on the remaining, either because of a
	// filterCompare, or for an ordering. If there is a limit, orderings are preferred
	// over compares.
	equals := map[string]*filter[T]{}
	inslices := map[string]*filter[T]{}
	for i := range q.xfilters {
		ff := &q.xfilters[i]
		switch f := (*ff).(type) {
		case filterEqual[T]:
			equals[f.field.Name] = ff
		case filterInSlice[T]:
			inslices[f.field.Name] = ff
		}
	}

	// We are going to generate new plans, and keep the new one if it is better than
	// what we have so far.
	var p *plan[T]
	var nexact int
	var nrange int
	var norder int

	evaluatePKOrIndex := func(idx *index) error {
		var isPK bool
		var packKeys func([]reflect.Value) ([]byte, error)
		if idx == nil {
			// Make pretend index.
			isPK = true
			idx = &index{
				Fields: []field{q.st.Current.Fields[0]},
			}
			packKeys = func(l []reflect.Value) ([]byte, error) {
				return packPK(l[0])
			}
		} else {
			packKeys = func(l []reflect.Value) ([]byte, error) {
				ikl, err := packIndexKeys(l, nil)
				if err != nil {
					return nil, err
				}
				if err == nil && len(ikl) != 1 {
					return nil, fmt.Errorf("internal error: multiple index keys for exact filters, %v", ikl)
				}
				return ikl[0].pre, nil
			}
		}

		var nex = 0
		// log.Printf("evaluating idx %#v", idx)
		var skipFilters []*filter[T]
		for _, f := range idx.Fields {
			if equals[f.Name] != nil && f.Type.Kind != kindSlice {
				skipFilters = append(skipFilters, equals[f.Name])
			} else if inslices[f.Name] != nil && f.Type.Kind == kindSlice {
				skipFilters = append(skipFilters, inslices[f.Name])
			} else {
				break
			}
			nex++
		}

		// For ordering, skip leading filters we already match on exactly.
		orders := q.xorders
		trim := 0
	TrimOrders:
		for _, o := range orders {
			for _, f := range idx.Fields[:nex] {
				if o.field.Name == f.Name {
					trim++
					continue TrimOrders
				}
			}
			break
		}
		orders = orders[trim:]

		// Fields from the index that we use for grouping before in-memory sorting.
		var norderidxuse int

		// See if the next index field can be used for compare and ordering.
		var gx, lx *filterCompare[T]
		var nrng int // for nrange
		if nex < len(idx.Fields) {
			nf := idx.Fields[nex]
			for i := range q.xfilters {
				ff := &q.xfilters[i]
				switch f := (*ff).(type) {
				case filterCompare[T]:
					if f.field.Name != nf.Name {
						continue
					}
					switch f.op {
					case opGreater, opGreaterEqual:
						if gx == nil {
							gx = &f
							skipFilters = append(skipFilters, ff)
							nrng++
						}
					case opLess, opLessEqual:
						if lx == nil {
							lx = &f
							skipFilters = append(skipFilters, ff)
							nrng++
						}
					}
				}
			}

			// We can use multiple orderings as long as the asc/desc direction stays the same.
			nord := 0
			for i, o := range orders {
				if nex+i < len(idx.Fields) && o.field.Name == idx.Fields[nex+i].Name && (nord == 0 || o.asc == orders[0].asc) {
					nord++
					continue
				}
				break
			}
			norderidxuse = nex + nord
			prevorders := orders
			orders = orders[nord:]

			// The stored index key ends with the primary key, so if we're there, and the next
			// ordering key is the primary key, we use the index for it too.
			if norderidxuse == len(idx.Fields) && len(orders) > 0 && orders[0].field.Name == q.st.Current.Fields[0].Name && (nord == 0 || orders[0].asc == prevorders[nord-1].asc) {
				orders = orders[1:]
				norderidxuse++
			}
		} else if len(orders) > 0 && orders[0].field.Name == q.st.Current.Fields[0].Name {
			// We only had equals filters that used all of the index, but we're also sorting by
			// the primary key, so use the index for that too.
			orders = orders[1:]
			norderidxuse++
		}

		// Orders handled by the index, excluding exact match filters.
		idxorders := q.xorders[trim : len(q.xorders)-len(orders)]

		// log.Printf("index fields to match for index order: %d, orders for index %d, in-memory ordering %d, total orders %d", norderidxuse, len(idxorders), len(orders), len(q.xorders))

		// See if this is better than what we had.
		if !(nex > nexact || (nex == nexact && (nrng > nrange || len(idxorders) > norder && (q.xlimit > 0 || nrng == nrange)))) {
			// log.Printf("plan not better, nex %d, nrng %d, limit %d, nidxorders %v ordered %v", nex, nrng, q.xlimit, len(idxorders), norder)
			return nil
		}
		nexact = nex
		nrange = nrng
		norder = len(idxorders)

		// Calculate the prefix key.
		var kvalues []reflect.Value
		for i := 0; i < nex; i++ {
			f := idx.Fields[i]
			var v reflect.Value
			if f.Type.Kind != kindSlice {
				v = (*equals[f.Name]).(filterEqual[T]).rvalue
			} else {
				v = (*inslices[f.Name]).(filterInSlice[T]).rvalue
			}
			kvalues = append(kvalues, v)
		}
		var key []byte
		var err error
		if nex > 0 {
			key, err = packKeys(kvalues)
			if err != nil {
				return err
			}
		}

		start := key
		stop := key
		if gx != nil {
			k, err := packKeys([]reflect.Value{gx.value})
			if err != nil {
				return err
			}
			start = append(append([]byte{}, start...), k...)
		}
		if lx != nil {
			k, err := packKeys([]reflect.Value{lx.value})
			if err != nil {
				return err
			}
			stop = append(append([]byte{}, stop...), k...)
		}

		startInclusive := gx == nil || gx.op != opGreater
		stopInclusive := lx == nil || lx.op != opLess
		desc := len(idxorders) > 0 && !idxorders[0].asc
		if desc {
			start, stop = stop, start
			startInclusive, stopInclusive = stopInclusive, startInclusive
		}

		if isPK {
			idx = nil // Clear our fake index for PK.
		}

		p = &plan[T]{
			idx:            idx,
			desc:           desc,
			start:          start,
			stop:           stop,
			startInclusive: startInclusive,
			stopInclusive:  stopInclusive,
			filters:        dropFilters(q.xfilters, skipFilters),
			norderidxuse:   norderidxuse,
			orders:         orders,
		}
		return nil
	}

	if err := evaluatePKOrIndex(nil); err != nil {
		q.error(err)
		return nil, q.err
	}
	for _, idx := range q.st.Current.Indices {
		if err := evaluatePKOrIndex(idx); err != nil {
			q.error(err)
			return nil, q.err
		}

	}
	if p != nil {
		// log.Printf("using index plan %v", p)
		return p, nil
	}

	// We'll just do a scan over all data.
	p = &plan[T]{
		filters: q.xfilters,
		orders:  q.xorders,
	}
	return p, nil
}

func dropFilters[T any](filters []T, skip []*T) []T {
	n := make([]T, 0, len(filters)-len(skip))
next:
	for i := range filters {
		f := &filters[i]
		for _, s := range skip {
			if f == s {
				continue next
			}
		}
		n = append(n, *f)
	}
	return n
}
