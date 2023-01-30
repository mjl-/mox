package bstore

import (
	"fmt"
	"reflect"
	"time"
)

var zerotime = time.Time{}

// applyDefault replaces zero values for fields that have a Default value configured.
func (tv *typeVersion) applyDefault(rv reflect.Value) error {
	for _, f := range tv.Fields[1:] {
		fv := rv.FieldByIndex(f.structField.Index)
		if err := f.applyDefault(fv); err != nil {
			return err
		}
	}
	return nil
}

func (f field) applyDefault(rv reflect.Value) error {
	switch f.Type.Kind {
	case kindBytes, kindBinaryMarshal, kindMap:
		return nil

	case kindSlice, kindStruct:
		return f.Type.applyDefault(rv)

	case kindBool, kindInt, kindInt8, kindInt16, kindInt32, kindInt64, kindUint, kindUint8, kindUint16, kindUint32, kindUint64, kindFloat32, kindFloat64, kindString, kindTime:
		if !f.defaultValue.IsValid() || !rv.IsZero() {
			return nil
		}
		fv := f.defaultValue
		// Time is special. "now" is encoded as the zero value of time.Time.
		if f.Type.Kind == kindTime && fv.Interface() == zerotime {
			now := time.Now().Round(0)
			if f.Type.Ptr {
				fv = reflect.ValueOf(&now)
			} else {
				fv = reflect.ValueOf(now)
			}
		} else if f.Type.Ptr {
			fv = reflect.New(f.structField.Type.Elem())
			fv.Elem().Set(f.defaultValue)
		}
		rv.Set(fv)
		return nil

	default:
		return fmt.Errorf("internal error: missing case for %v", f.Type.Kind)
	}
}

// only for recursing. we do not support recursing into maps because it would
// involve more work making values settable. and how sensible it it anyway?
func (ft fieldType) applyDefault(rv reflect.Value) error {
	if ft.Ptr && (rv.IsZero() || rv.IsNil()) {
		return nil
	} else if ft.Ptr {
		rv = rv.Elem()
	}
	switch ft.Kind {
	case kindSlice:
		n := rv.Len()
		for i := 0; i < n; i++ {
			if err := ft.List.applyDefault(rv.Index(i)); err != nil {
				return err
			}
		}
	case kindStruct:
		for _, nf := range ft.Fields {
			nfv := rv.FieldByIndex(nf.structField.Index)
			if err := nf.applyDefault(nfv); err != nil {
				return err
			}
		}
	}
	return nil
}
