package bstore

import (
	"bytes"
	"encoding"
	"reflect"
	"time"
)

// equal checks if ov and v are the same as far as storage is concerned. i.e.
// this only takes stored fields into account. reflect.DeepEqual cannot be used,
// it would take all fields into account, including unexported.
func (tv *typeVersion) equal(ov, v reflect.Value) (r bool) {
	if !ov.IsValid() || !v.IsValid() {
		return false
	}
	for _, f := range tv.Fields {
		fov := ov.FieldByIndex(f.structField.Index)
		fv := v.FieldByIndex(f.structField.Index)
		if !f.Type.equal(fov, fv) {
			return false
		}
	}
	return true
}

func (ft fieldType) equal(ov, v reflect.Value) (r bool) {
	if ov == v {
		return true
	} else if !ov.IsValid() || !v.IsValid() {
		return false
	}
	if ft.Ptr {
		ov = ov.Elem()
		v = v.Elem()
	}
	if ov == v {
		return true
	} else if !ov.IsValid() || !v.IsValid() {
		return false
	}
	switch ft.Kind {
	case kindBytes:
		return bytes.Equal(ov.Bytes(), v.Bytes())
	case kindMap:
		on := ov.Len()
		n := v.Len()
		if on != n {
			return false
		}
		r := ov.MapRange()
		for r.Next() {
			vv := v.MapIndex(r.Key())
			if !vv.IsValid() || !ft.MapValue.equal(r.Value(), vv) {
				return false
			}
		}
		return true
	case kindSlice:
		on := ov.Len()
		n := v.Len()
		if on != n {
			return false
		}
		for i := 0; i < n; i++ {
			if !ft.List.equal(ov.Index(i), v.Index(i)) {
				return false
			}
		}
		return true
	case kindTime:
		return ov.Interface().(time.Time).Equal(v.Interface().(time.Time))
	case kindBinaryMarshal:
		obuf, oerr := ov.Interface().(encoding.BinaryMarshaler).MarshalBinary()
		buf, err := v.Interface().(encoding.BinaryMarshaler).MarshalBinary()
		if oerr != nil || err != nil {
			return false // todo: should propagate error?
		}
		return bytes.Equal(obuf, buf)
	case kindStruct:
		for _, f := range ft.Fields {
			fov := ov.FieldByIndex(f.structField.Index)
			fv := v.FieldByIndex(f.structField.Index)
			if !f.Type.equal(fov, fv) {
				return false
			}
		}
		return true
	}
	return ov.Interface() == v.Interface()
}
