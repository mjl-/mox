package bstore

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// todo optimize: do not fetch full record if we can apply the filters with just the values we glean from the index key.

// exec represents the execution of a query plan.
type exec[T any] struct {
	q    *Query[T]
	plan *plan[T]

	// For queries with explicit PKs filtered on.
	// See plan.keys. We remove items from the list when we looked one up, but we keep the slice non-nil.
	keys [][]byte

	// If -1, no limit is set. This is different from Query where 0 means
	// no limit. We count back and 0 means the end.
	limit int

	data    []pair[T] // If not nil (even if empty), serve nextKey requests from here.
	ib      *bolt.Bucket
	rb      *bolt.Bucket
	forward func() (bk, bv []byte) // Once we start scanning, we prepare forward to next/prev to the following value.
}

// exec creates a new execution for the plan, registering statistics.
func (p *plan[T]) exec(q *Query[T]) *exec[T] {
	q.stats.Queries++
	if p.idx == nil {
		if p.keys != nil {
			q.stats.PlanPK++
		} else if p.start != nil || p.stop != nil {
			q.stats.PlanPKScan++
		} else {
			q.stats.PlanTableScan++
		}
		q.stats.LastIndex = ""
	} else {
		if p.keys != nil {
			q.stats.PlanUnique++
		} else {
			q.stats.PlanIndexScan++
		}
		q.stats.LastIndex = p.idx.Name
	}
	if len(p.orders) > 0 {
		q.stats.Sort++
	}
	q.stats.LastOrdered = p.start != nil || p.stop != nil
	q.stats.LastAsc = !p.desc

	limit := -1
	if q.xlimit > 0 {
		limit = q.xlimit
	}
	return &exec[T]{q: q, plan: p, keys: p.keys, limit: limit}
}

// incr treats buf as a bigendian number, increasing it by one. used for reverse
// scans, where we must start beyond the key prefix we are looking for.
func incr(buf []byte) bool {
	for i := len(buf) - 1; i >= 0; i-- {
		if buf[i] < 255 {
			buf[i]++
			return true
		}
		buf[i] = 0
	}
	return false
}

func cutoff(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// nextKey returns the key and optionally value for the next selected record.
//
// ErrAbsent is returned if there is no more record.
//
// If an error occurs, an error is set on query, except in the case of
// ErrAbsent. ErrAbsent does not finish the query because a Delete or Update
// could follow.
func (e *exec[T]) nextKey(write, value bool) ([]byte, T, error) {
	var zero T

	q := e.q

	if q.err == nil {
		select {
		case <-q.ctxDone:
			q.error(q.ctx.Err())
		default:
		}
	}
	if q.err != nil {
		return nil, zero, q.err
	}

	// We collected & sorted data previously. Return from it until done.
	// Limit was already applied.
	if e.data != nil {
		if len(e.data) == 0 {
			return nil, zero, ErrAbsent
		}
		p := e.data[0]
		e.data = e.data[1:]
		var v T
		if value {
			var err error
			v, err = p.Value(e)
			if err != nil {
				q.error(err)
				return nil, zero, err
			}
		}
		return p.bk, v, nil
	}

	if e.limit == 0 {
		return nil, zero, ErrAbsent
	}

	// First time we are going to need buckets.
	if e.rb == nil {
		tx, err := q.tx(write)
		if err != nil {
			q.error(err)
			return nil, zero, err
		}
		e.rb, err = tx.recordsBucket(q.st.Name, q.st.Current.fillPercent)
		if err != nil {
			return nil, zero, err
		}
		if e.plan.idx != nil {
			e.ib, err = tx.indexBucket(e.plan.idx)
			if err != nil {
				return nil, zero, err
			}
		}
	}

	// List of IDs (records) or full unique index equality match.
	// We can get the records/index value by a simple "get" on the key.
	if e.keys != nil {
		collect := len(e.plan.orders) > 0
		if collect {
			e.data = []pair[T]{} // Must be non-nil to get into e.data branch!
		}
		for i, xk := range e.keys {
			var bk, bv []byte

			// For indices, we need look up the PK through the index.
			if e.plan.idx != nil {
				c := e.ib.Cursor()
				q.stats.Index.Cursor++
				bki, _ := c.Seek(xk)
				if !bytes.HasPrefix(bki, xk) {
					continue
				}
				// log.Printf("seek %x, bki %x", xk, bki)
				bk = bki[len(xk):]
			} else {
				bk = xk
			}

			// We don't need to fetch the full record now if it isn't needed by
			// caller. It may be fetch below for more filters.
			if value || e.plan.idx == nil {
				q.stats.Records.Get++
				bv = e.rb.Get(bk)
				if bv == nil {
					if e.plan.idx != nil {
						return nil, zero, fmt.Errorf("%w: record with pk %x referenced through index %q not found", ErrStore, bk, e.plan.idx.Name)
					}
					continue
				}
			}
			p := pair[T]{bk, bv, nil}
			if ok, err := e.checkFilter(&p); err != nil {
				return nil, zero, err
			} else if !ok {
				continue
			}

			if collect {
				e.data = append(e.data, p)
				continue
			}

			// Again, only fetch value if needed.
			var v T
			if value {
				var err error
				v, err = p.Value(e)
				if err != nil {
					q.error(err)
					return nil, zero, err
				}
			}

			if e.limit > 0 {
				e.limit--
			}

			e.keys = e.keys[i+1:]
			return bk, v, nil
		}
		if !collect {
			return nil, zero, ErrAbsent
		}
		// Restart, now with data.
		e.keys = [][]byte{}
		e.sort()
		if e.limit > 0 && len(e.data) > e.limit {
			e.data = e.data[:e.limit]
		}
		return q.nextKey(write, value)
	}

	// We are going to do a scan, either over the records or an index. We may have a start and stop key.
	collect := len(e.plan.orders) > 0
	if collect {
		e.data = []pair[T]{} // Must be non-nil to get into e.data branch on function restart.
	}
	for {
		var xk, xv []byte
		if e.forward == nil {
			// First time we are in this loop, we set up a cursor and e.forward.

			var c *bolt.Cursor
			var statsKV *StatsKV
			if e.plan.idx == nil {
				c = e.rb.Cursor()
				statsKV = &q.stats.Records
			} else {
				c = e.ib.Cursor()
				statsKV = &q.stats.Index
			}
			if !e.plan.desc {
				e.forward = c.Next
				if e.plan.start != nil {
					statsKV.Cursor++
					// If e.plan.start does not exist, seek will skip to the
					// next value after. Fine because this is ascending order.
					xk, xv = c.Seek(e.plan.start)
				} else {
					statsKV.Cursor++
					xk, xv = c.First()
				}
			} else {
				e.forward = c.Prev
				if e.plan.start == nil {
					statsKV.Cursor++
					xk, xv = c.Last()
				} else {
					start := make([]byte, len(e.plan.start))
					copy(start, e.plan.start)
					ok := incr(start)
					if !ok {
						statsKV.Cursor++
						// We were at the last representable value. So we simply start at the end.
						xk, xv = c.Last()
					} else {
						statsKV.Cursor++
						xk, xv = c.Seek(start)
						if xk == nil {
							statsKV.Cursor++
							xk, xv = c.Last()
						}
						// We started at the value after where we were requested to start, so we have to
						// move until we find a matching key.
						// todo: we could take e.plan.stop into account (if set). right now we may be
						// seeking all the way to the front without ever seeing a match to stop.
						for xk != nil && bytes.Compare(cutoff(xk, len(e.plan.start)), e.plan.start) > 0 {
							statsKV.Cursor++
							xk, xv = e.forward()
						}
					}
				}
			}
		} else {
			if e.plan.idx == nil {
				q.stats.Records.Cursor++
			} else {
				q.stats.Index.Cursor++
			}
			xk, xv = e.forward()
			// log.Printf("forwarded, %x %x", xk, xv)
		}

		if xk == nil {
			break
		}

		if e.plan.start != nil && !e.plan.startInclusive && bytes.HasPrefix(xk, e.plan.start) {
			continue
		}
		if e.plan.stop != nil {
			cmp := bytes.Compare(cutoff(xk, len(e.plan.stop)), e.plan.stop)
			if !e.plan.desc && (e.plan.stopInclusive && cmp > 0 || !e.plan.stopInclusive && cmp >= 0) {
				break
			} else if e.plan.desc && (e.plan.stopInclusive && cmp < 0 || !e.plan.stopInclusive && cmp <= 0) {
				break
			}
		}

		var pk, bv []byte
		if e.plan.idx == nil {
			pk = xk
			bv = xv
		} else {
			var err error
			pk, _, err = e.plan.idx.parseKey(xk, false)
			if err != nil {
				q.error(err)
				return nil, zero, err
			}
		}

		p := pair[T]{pk, bv, nil}
		if ok, err := e.checkFilter(&p); err != nil {
			return nil, zero, err
		} else if !ok {
			continue
		}
		//log.Printf("have kv, %x %x", p.bk, p.bv)
		var v T
		var err error
		if value {
			v, err = p.Value(e)
			if err != nil {
				q.error(err)
				return nil, zero, err
			}
		}
		if collect {
			e.data = append(e.data, p)
			continue
		}
		if e.limit > 0 {
			e.limit--
		}
		return p.bk, v, nil
	}
	if !collect {
		return nil, zero, ErrAbsent
	}
	// Restart, now with data.
	e.sort()
	if e.limit > 0 && len(e.data) > e.limit {
		e.data = e.data[:e.limit]
	}
	return e.nextKey(write, value)
}

// checkFilter checks against the filters for the plan.
func (e *exec[T]) checkFilter(p *pair[T]) (rok bool, rerr error) {
	q := e.q

	for _, ff := range e.plan.filters {
		switch f := ff.(type) {
		// note: filterIDs is not here, it is handled earlier to fetch records.
		case filterFn[T]:
			v, err := p.Value(e)
			if err != nil {
				q.error(err)
				return false, err
			}
			if !f.fn(v) {
				return
			}
		case filterEqual[T]:
			v, err := p.Value(e)
			if err != nil {
				q.error(err)
				return false, err
			}
			rv := reflect.ValueOf(v)
			frv := rv.FieldByIndex(f.field.structField.Index)
			if !f.field.Type.equal(frv, f.rvalue) {
				return
			}
		case filterNotEqual[T]:
			v, err := p.Value(e)
			if err != nil {
				q.error(err)
				return false, err
			}
			rv := reflect.ValueOf(v)
			frv := rv.FieldByIndex(f.field.structField.Index)
			if f.field.Type.equal(frv, f.rvalue) {
				return
			}
		case filterIn[T]:
			v, err := p.Value(e)
			if err != nil {
				q.error(err)
				return false, err
			}
			rv := reflect.ValueOf(v)
			frv := rv.FieldByIndex(f.field.structField.Index)
			var have bool
			for _, xrv := range f.rvalues {
				if f.field.Type.equal(frv, xrv) {
					have = true
					break
				}
			}
			if !have {
				return
			}
		case filterNotIn[T]:
			v, err := p.Value(e)
			if err != nil {
				q.error(err)
				return false, err
			}
			rv := reflect.ValueOf(v)
			frv := rv.FieldByIndex(f.field.structField.Index)
			for _, xrv := range f.rvalues {
				if f.field.Type.equal(frv, xrv) {
					return
				}
			}
		case filterInSlice[T]:
			v, err := p.Value(e)
			if err != nil {
				q.error(err)
				return false, err
			}
			rv := reflect.ValueOf(v)
			frv := rv.FieldByIndex(f.field.structField.Index)
			n := frv.Len()
			var have bool
			for i := 0; i < n; i++ {
				if f.field.Type.ListElem.equal(frv.Index(i), f.rvalue) {
					have = true
					break
				}
			}
			if !have {
				return
			}
		case filterCompare[T]:
			v, err := p.Value(e)
			if err != nil {
				q.error(err)
				return false, err
			}
			rv := reflect.ValueOf(v)
			fv := rv.FieldByIndex(f.field.structField.Index)
			cmp := compare(f.field.Type.Kind, fv, f.value)
			switch {
			case cmp == 0 && (f.op == opGreaterEqual || f.op == opLessEqual):
			case cmp < 0 && (f.op == opLess || f.op == opLessEqual):
			case cmp > 0 && (f.op == opGreater || f.op == opGreaterEqual):
			default:
				return
			}
		default:
			q.errorf("internal error: missing case for filter %T", ff)
			return false, q.err
		}
	}
	return true, nil
}

// if type can be compared for filterCompare, eg for greater/less comparison.
func comparable(ft fieldType) bool {
	if ft.Ptr {
		return false
	}
	switch ft.Kind {
	case kindBytes, kindString, kindBool, kindInt8, kindInt16, kindInt32, kindInt64, kindInt, kindUint8, kindUint16, kindUint32, kindUint64, kindUint, kindFloat32, kindFloat64, kindTime:
		return true
	default:
		return false
	}
}

func compare(k kind, a, b reflect.Value) int {
	switch k {
	case kindBytes:
		return bytes.Compare(a.Bytes(), b.Bytes())

	case kindString:
		sa := a.String()
		sb := b.String()
		if sa < sb {
			return -1
		} else if sa > sb {
			return 1
		}
		return 0

	case kindBool:
		ba := a.Bool()
		bb := b.Bool()
		if !ba && bb {
			return -1
		} else if ba && !bb {
			return 1
		}
		return 0

	case kindInt8, kindInt16, kindInt32, kindInt64, kindInt:
		ia := a.Int()
		ib := b.Int()
		if ia < ib {
			return -1
		} else if ia > ib {
			return 1
		}
		return 0

	case kindUint8, kindUint16, kindUint32, kindUint64, kindUint:
		ia := a.Uint()
		ib := b.Uint()
		if ia < ib {
			return -1
		} else if ia > ib {
			return 1
		}
		return 0

	case kindFloat32, kindFloat64:
		fa := a.Float()
		fb := b.Float()
		if fa < fb {
			return -1
		} else if fa > fb {
			return 1
		}
		return 0

	case kindTime:
		ta := a.Interface().(time.Time)
		tb := b.Interface().(time.Time)
		if ta.Before(tb) {
			return -1
		} else if ta.After(tb) {
			return 1
		}
		return 0
	}
	// todo: internal error, cannot happen
	return 0
}

func (e *exec[T]) sort() {
	// todo: We should check whether we actually need to load values. We're
	// always loading it for the time being because SortStableFunc isn't
	// going to give us a *pair (even though it could because of the slice)
	// so we couldn't set/cache the value T during sorting.
	q := e.q

	for i := range e.data {
		p := &e.data[i]
		if p.value != nil {
			continue
		}
		_, err := p.Value(e)
		if err != nil {
			q.error(err)
			return
		}
	}

	sort.SliceStable(e.data, func(i, j int) bool {
		a := e.data[i]
		b := e.data[j]
		for _, o := range e.plan.orders {
			ra := reflect.ValueOf(*a.value)
			rb := reflect.ValueOf(*b.value)
			rva := ra.FieldByIndex(o.field.structField.Index)
			rvb := rb.FieldByIndex(o.field.structField.Index)
			cmp := compare(o.field.Type.Kind, rva, rvb)
			if cmp == 0 {
				continue
			}
			return cmp < 0 && o.asc || cmp > 0 && !o.asc
		}
		return false
	})
}
