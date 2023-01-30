package bstore

import (
	"fmt"
	"reflect"
)

// isZero returns whether v is the zero value for the fields that we store.
// reflect.IsZero cannot be used on structs because it checks private fields as well.
func (ft fieldType) isZero(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	if ft.Ptr {
		return v.IsNil()
	}
	switch ft.Kind {
	case kindStruct:
		for _, f := range ft.Fields {
			if !f.Type.isZero(v.FieldByIndex(f.structField.Index)) {
				return false
			}
		}
		return true
	}
	// Use standard IsZero otherwise, also for kindBinaryMarshal.
	return v.IsZero()
}

// checkNonzero compare ofields and nfields (from previous type schema vs newly
// created type schema) for nonzero struct tag. If an existing field got a
// nonzero struct tag added, we verify that there are indeed no nonzero values
// in the database. If there are, we return ErrZero.
func (tx *Tx) checkNonzero(st storeType, tv *typeVersion, ofields, nfields []field) error {
	// First we gather paths that we need to check, so we can later simply
	// execute those steps on all data we need to read.
	paths := &follows{}
next:
	for _, f := range nfields {
		for _, of := range ofields {
			if f.Name == of.Name {
				err := f.checkNonzeroGather(&of, paths)
				if err != nil {
					return err
				}
				continue next
			}
		}
		if err := f.checkNonzeroGather(nil, paths); err != nil {
			return err
		}
	}

	if len(paths.paths) == 0 {
		// Common case, not reading all data.
		return nil
	}

	// Finally actually do the checks.
	// todo: if there are only top-level fields to check, and we have an index, we can use the index check this without reading all data.
	return tx.checkNonzeroPaths(st, tv, paths.paths)
}

type follow struct {
	mapKey, mapValue bool
	field            field
}

type follows struct {
	current []follow
	paths   [][]follow
}

func (f *follows) push(ff follow) {
	f.current = append(f.current, ff)
}

func (f *follows) pop() {
	f.current = f.current[:len(f.current)-1]
}

func (f *follows) add() {
	f.paths = append(f.paths, append([]follow{}, f.current...))
}

func (f field) checkNonzeroGather(of *field, paths *follows) error {
	paths.push(follow{field: f})
	defer paths.pop()
	if f.Nonzero && (of == nil || !of.Nonzero) {
		paths.add()
	}
	if of != nil {
		return f.Type.checkNonzeroGather(of.Type, paths)
	}
	return nil
}

func (ft fieldType) checkNonzeroGather(oft fieldType, paths *follows) error {
	switch ft.Kind {
	case kindMap:
		paths.push(follow{mapKey: true})
		if err := ft.MapKey.checkNonzeroGather(*oft.MapKey, paths); err != nil {
			return err
		}
		paths.pop()

		paths.push(follow{mapValue: true})
		if err := ft.MapValue.checkNonzeroGather(*oft.MapValue, paths); err != nil {
			return err
		}
		paths.pop()

	case kindSlice:
		err := ft.List.checkNonzeroGather(*oft.List, paths)
		if err != nil {
			return err
		}
	case kindStruct:
	next:
		for _, ff := range ft.Fields {
			for _, off := range oft.Fields {
				if ff.Name == off.Name {
					err := ff.checkNonzeroGather(&off, paths)
					if err != nil {
						return err
					}
					continue next
				}
			}
			err := ff.checkNonzeroGather(nil, paths)
			if err != nil {
				return err
			}
		}

	}
	return nil
}

// checkNonzero reads through all records of a type, and checks that the fields
// indicated by paths are nonzero. If not, ErrZero is returned.
func (tx *Tx) checkNonzeroPaths(st storeType, tv *typeVersion, paths [][]follow) error {
	rb, err := tx.recordsBucket(st.Current.name, st.Current.fillPercent)
	if err != nil {
		return err
	}
	return rb.ForEach(func(bk, bv []byte) error {
		tx.stats.Records.Cursor++

		rv, err := st.parseNew(bk, bv)
		if err != nil {
			return err
		}
		// todo optimization: instead of parsing the full record, use the fieldmap to see if the value is nonzero.
		for _, path := range paths {
			frv := rv.FieldByIndex(path[0].field.structField.Index)
			if err := path[0].field.checkNonzero(frv, path[1:]); err != nil {
				return err
			}
		}
		return nil
	})
}

func (f field) checkNonzero(rv reflect.Value, path []follow) error {
	if len(path) == 0 {
		if !f.Nonzero {
			return fmt.Errorf("internal error: checkNonzero: expected field to have Nonzero set")
		}
		if f.Type.isZero(rv) {
			return fmt.Errorf("%w: field %q", ErrZero, f.Name)
		}
		return nil
	}
	return f.Type.checkNonzero(rv, path)
}

func (ft fieldType) checkNonzero(rv reflect.Value, path []follow) error {
	switch ft.Kind {
	case kindMap:
		follow := path[0]
		path = path[1:]
		key := follow.mapKey
		if !key && !follow.mapValue {
			return fmt.Errorf("internal error: following map, expected mapKey or mapValue, got %#v", follow)
		}

		iter := rv.MapRange()
		for iter.Next() {
			var err error
			if key {
				err = ft.MapKey.checkNonzero(iter.Key(), path)
			} else {
				err = ft.MapValue.checkNonzero(iter.Value(), path)
			}
			if err != nil {
				return err
			}
		}
	case kindSlice:
		n := rv.Len()
		for i := 0; i < n; i++ {
			if err := ft.List.checkNonzero(rv.Index(i), path); err != nil {
				return err
			}
		}
	case kindStruct:
		follow := path[0]
		path = path[1:]
		frv := rv.FieldByIndex(follow.field.structField.Index)
		if err := follow.field.checkNonzero(frv, path); err != nil {
			return err
		}
	default:
		return fmt.Errorf("internal error: checkNonzero with non-empty path, but kind %v", ft.Kind)
	}
	return nil
}
