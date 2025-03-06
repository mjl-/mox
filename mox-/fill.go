package mox

import (
	"reflect"
)

// FillNil returns a modified value with nil maps/slices replaced with empty
// maps/slices.
func FillNil(rv reflect.Value) (nv reflect.Value, changed bool) {
	switch rv.Kind() {
	case reflect.Struct:
		for i := range rv.NumField() {
			if !rv.Type().Field(i).IsExported() {
				continue
			}
			vv := rv.Field(i)
			nvv, ch := FillNil(vv)
			if ch && !rv.CanSet() {
				// Make struct settable.
				nrv := reflect.New(rv.Type()).Elem()
				for j := range rv.NumField() {
					nrv.Field(j).Set(rv.Field(j))
				}
				rv = nrv
				vv = rv.Field(i)
			}
			if ch {
				changed = true
				vv.Set(nvv)
			}
		}
	case reflect.Slice:
		if rv.IsNil() {
			return reflect.MakeSlice(rv.Type(), 0, 0), true
		}
		n := rv.Len()
		for i := range n {
			rve := rv.Index(i)
			nrv, ch := FillNil(rve)
			if ch {
				changed = true
				rve.Set(nrv)
			}
		}
	case reflect.Map:
		if rv.IsNil() {
			return reflect.MakeMap(rv.Type()), true
		}
		i := rv.MapRange()
		for i.Next() {
			erv, ch := FillNil(i.Value())
			if ch {
				changed = true
				rv.SetMapIndex(i.Key(), erv)
			}
		}
	case reflect.Pointer:
		if !rv.IsNil() {
			FillNil(rv.Elem())
		}
	}
	return rv, changed
}

// FillExample returns a modified value with nil/empty maps/slices/pointers values
// replaced with non-empty versions, for more helpful examples of types. Useful for
// documenting JSON representations of types.
func FillExample(seen []reflect.Type, rv reflect.Value) reflect.Value {
	if seen == nil {
		seen = make([]reflect.Type, 100)
	}

	// Prevent recursive filling.
	rvt := rv.Type()
	index := -1
	for i, t := range seen {
		if t == rvt {
			return rv
		} else if t == nil {
			index = i
		}
	}
	if index < 0 {
		return rv
	}
	seen[index] = rvt
	defer func() {
		seen[index] = nil
	}()

	switch rv.Kind() {
	case reflect.Struct:
		for i := range rv.NumField() {
			if !rvt.Field(i).IsExported() {
				continue
			}
			vv := rv.Field(i)
			vv.Set(FillExample(seen, vv))
		}
	case reflect.Slice:
		ev := FillExample(seen, reflect.New(rvt.Elem()).Elem())
		return reflect.Append(rv, ev)
	case reflect.Map:
		vv := FillExample(seen, reflect.New(rvt.Elem()).Elem())
		nv := reflect.MakeMap(rvt)
		nv.SetMapIndex(reflect.ValueOf("example"), vv)
		return nv
	case reflect.Pointer:
		nv := reflect.New(rvt.Elem())
		return FillExample(seen, nv.Elem()).Addr()
	}
	return rv
}
