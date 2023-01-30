package bstore

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
)

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

	desc           bool   // Direction of the range scan.
	start          []byte // First key to scan. Filters below may still apply. If desc, this value is > than stop (if it is set). If nil, we begin ranging at the first or last (for desc) key.
	stop           []byte // Last key to scan. Can be nil independently of start.
	startInclusive bool   // If the start and stop values are inclusive or exclusive.
	stopInclusive  bool

	// Filter we need to apply on after retrieving the record. If all
	// original filters from a query were handled by "keys" above, or by a
	// range scan, this field is empty.
	filters []filter[T]

	// Orders we need to apply after first retrieving all records. As with
	// filters, if a range scan takes care of an ordering from the query,
	// this field is empty.
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
	// This is common for filterEqual and filterIn on
	// fields that have a unique index.
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
		// todo optimization: if there is a sort involving these fields, we could do the sorting before fetching data.
		// todo optimization: we can generate the keys on demand, will help when limit is in use: we are not generating all keys.
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
				key, _, err := packIndexKeys([]reflect.Value{fv}, nil)
				if err != nil {
					q.error(err)
					return nil, err
				}
				fekeys[j] = key
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
	// We want to use the one with as many "equal" prefix fields as
	// possible. Then we hope to use a scan on the remaining, either
	// because of a filterCompare, or for an ordering. If there is a limit,
	// orderings are preferred over compares.
	equals := map[string]*filter[T]{}
	for i := range q.xfilters {
		ff := &q.xfilters[i]
		switch f := (*ff).(type) {
		case filterEqual[T]:
			equals[f.field.Name] = ff
		}
	}

	// We are going to generate new plans, and keep the new one if it is better than what we have.
	var p *plan[T]
	var nequals int
	var nrange int
	var ordered bool

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
				key, _, err := packIndexKeys(l, nil)
				return key, err
			}
		}

		var neq = 0
		// log.Printf("idx %v", idx)
		var skipFilters []*filter[T]
		for _, f := range idx.Fields {
			if ff, ok := equals[f.Name]; ok {
				skipFilters = append(skipFilters, ff)
				neq++
			} else {
				break
			}
		}

		// See if the next field can be used for compare.
		var gx, lx *filterCompare[T]
		var nrng int
		var order *order
		orders := q.xorders
		if neq < len(idx.Fields) {
			nf := idx.Fields[neq]
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

			// See if it can be used for ordering.
			// todo optimization: we could use multiple orders
			if len(orders) > 0 && orders[0].field.Name == nf.Name {
				order = &orders[0]
				orders = orders[1:]
			}
		}

		// See if this is better than what we had.
		if !(neq > nequals || (neq == nequals && (nrng > nrange || order != nil && !ordered && (q.xlimit > 0 || nrng == nrange)))) {
			// log.Printf("plan not better, neq %d, nrng %d, limit %d, order %v ordered %v", neq, nrng, q.limit, order, ordered)
			return nil
		}
		nequals = neq
		nrange = nrng
		ordered = order != nil

		// Calculate the prefix key.
		var kvalues []reflect.Value
		for i := 0; i < neq; i++ {
			f := idx.Fields[i]
			kvalues = append(kvalues, (*equals[f.Name]).(filterEqual[T]).rvalue)
		}
		var key []byte
		var err error
		if neq > 0 {
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
		if order != nil && !order.asc {
			start, stop = stop, start
			startInclusive, stopInclusive = stopInclusive, startInclusive
		}

		if isPK {
			idx = nil // Clear our fake index for PK.
		}

		p = &plan[T]{
			idx:            idx,
			desc:           order != nil && !order.asc,
			start:          start,
			stop:           stop,
			startInclusive: startInclusive,
			stopInclusive:  stopInclusive,
			filters:        dropFilters(q.xfilters, skipFilters),
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
