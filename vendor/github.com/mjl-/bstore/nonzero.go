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
		return v.IsZero()
	}
	switch ft.Kind {
	case kindStruct:
		for _, f := range ft.structFields {
			if !f.Type.isZero(v.FieldByIndex(f.structField.Index)) {
				return false
			}
		}
		return true
	}

	// Use standard IsZero otherwise, also for kindBinaryMarshal.
	return v.IsZero()
}

// We ensure nonzero constraints when opening a database. An updated schema, with
// added nonzero constraints, can mean all records have to be checked. With cyclic
// types, we have to take care not to recurse, and for efficiency we want to only
// check fields/types that are affected. Steps:
//
// - Go through each field of the struct, and recurse into the field types,
//   gathering the types and newly nonzero fields.
// - Propagate the need for nonzero checks to types that reference the changed
//   types.
// - By now, if there was a new nonzero constraint, the top-level type will be
//   marked as needing a check, so we'll read through all records and check all the
//   immediate newly nonzero fields of a type, and recurse into fields of types that
//   are marked as needing a check.

// nonzeroCheckType is tracked per reflect.Type that has been analysed (always the
// non-pointer type, i.e. a pointer is dereferenced). These types can be cyclic. We
// gather them for all types involved, including map and slice types and basic
// types, but "newlyNonzero" and "fields" will only be set for structs.
type nonzeroCheckType struct {
	needsCheck bool

	newlyNonzero []field // Fields in this type that have a new nonzero constraint themselves.
	fields       []field // All fields in a struct type.

	// Types that reference this type. Used to propagate needsCheck to the top.
	referencedBy map[reflect.Type]struct{}
}

func (ct *nonzeroCheckType) markRefBy(t reflect.Type) {
	if t != nil {
		ct.referencedBy[t] = struct{}{}
	}
}

// checkNonzero compares ofields (optional previous type schema) and nfields (new
// type schema) for nonzero struct tags. If an existing field has a new nonzero
// constraint, we verify that there are indeed no nonzero values in the existing
// records. If there are, we return ErrZero. checkNonzero looks at (potentially
// cyclic) types referenced by fields.
func (tx *Tx) checkNonzero(st storeType, tv *typeVersion, ofields, nfields []field) error {
	// Gather all new nonzero constraints on fields.
	m := map[reflect.Type]*nonzeroCheckType{}
	nonzeroCheckGather(m, st.Type, nil, ofields, nfields)

	// Propagate the need for a check on all types due to a referenced type having a
	// new nonzero constraint.
	// todo: this can probably be done more elegantly, with fewer graph walks...
	for t, ct := range m {
		if ct.needsCheck {
			nonzeroCheckPropagate(m, t, t, ct)
		}
	}

	// If needsCheck wasn't propagated to the top-level, there was no new nonzero
	// constraint, and we're not going to read all the data.  This is the common case
	// when opening a database.
	if !m[st.Type].needsCheck {
		return nil
	}

	// Read through all data, and check the new nonzero constraint.
	// todo optimize: if there are only top-level fields to check, and we have indices on those fields, we can use the index to check this without reading all data.
	return checkNonzeroRecords(tx, st, tv, m)
}

// Walk down fields, gathering their types (including those they reference), and
// marking needsCheck if any of a type's immediate field has a new nonzero
// constraint. The need for a check is not propagated to referencing types by this
// function.
func nonzeroCheckGather(m map[reflect.Type]*nonzeroCheckType, t, refBy reflect.Type, ofields, nfields []field) {
	ct := m[t]
	if ct != nil {
		// Already gathered, don't recurse, for cyclic types.
		ct.markRefBy(refBy)
		return
	}
	ct = &nonzeroCheckType{
		fields:       nfields,
		referencedBy: map[reflect.Type]struct{}{},
	}
	ct.markRefBy(refBy)
	m[t] = ct

	for _, f := range nfields {
		// Check if this field is newly nonzero.
		var of *field
		for i := range ofields {
			if f.Name == ofields[i].Name {
				of = &ofields[i]
				// Compare with existing field.
				if f.Nonzero && !of.Nonzero {
					ct.newlyNonzero = append(ct.newlyNonzero, f)
					ct.needsCheck = true
				}
				break
			}
		}
		// Check if this is a new field entirely, with nonzero constraint.
		if of == nil && f.Nonzero {
			ct.newlyNonzero = append(ct.newlyNonzero, f)
			ct.needsCheck = true
		}

		// Descend into referenced types, adding references back to this type.
		var oft *fieldType
		if of != nil {
			oft = &of.Type
		}
		ft := f.structField.Type
		nonzeroCheckGatherFieldType(m, ft, t, oft, f.Type)
	}
}

// gather new nonzero constraints for type "t", which is referenced by "refBy" (and
// will be marked as such). type "t" is described by "nft" and optionally
// previously by "oft".
func nonzeroCheckGatherFieldType(m map[reflect.Type]*nonzeroCheckType, t, refBy reflect.Type, oft *fieldType, nft fieldType) {
	// If this is a pointer type, dereference the reflect type.
	if nft.Ptr {
		t = t.Elem()
	}

	if nft.Kind == kindStruct {
		var fofields []field
		if oft != nil {
			fofields = oft.structFields
		}
		nonzeroCheckGather(m, t, refBy, fofields, nft.structFields)
	}

	// Mark this type as gathered, so we don't process it again if we recurse.
	ct := m[t]
	if ct != nil {
		ct.markRefBy(refBy)
		return
	}
	ct = &nonzeroCheckType{
		fields:       nft.structFields,
		referencedBy: map[reflect.Type]struct{}{},
	}
	ct.markRefBy(refBy)
	m[t] = ct

	switch nft.Kind {
	case kindMap:
		var koft, voft *fieldType
		if oft != nil {
			koft = oft.MapKey
			voft = oft.MapValue
		}
		nonzeroCheckGatherFieldType(m, t.Key(), t, koft, *nft.MapKey)
		nonzeroCheckGatherFieldType(m, t.Elem(), t, voft, *nft.MapValue)
	case kindSlice:
		var loft *fieldType
		if oft != nil {
			loft = oft.ListElem
		}
		nonzeroCheckGatherFieldType(m, t.Elem(), t, loft, *nft.ListElem)
	case kindArray:
		var loft *fieldType
		if oft != nil {
			loft = oft.ListElem
		}
		nonzeroCheckGatherFieldType(m, t.Elem(), t, loft, *nft.ListElem)
	}
}

// Propagate that type "t" is affected by a new nonzero constrained and needs to be
// checked. The types referencing "t" are in ct.referencedBy. "origt" is the
// starting type for this propagation.
func nonzeroCheckPropagate(m map[reflect.Type]*nonzeroCheckType, origt, t reflect.Type, ct *nonzeroCheckType) {
	for rt := range ct.referencedBy {
		if rt == origt {
			continue // End recursion.
		}
		m[rt].needsCheck = true
		nonzeroCheckPropagate(m, origt, rt, m[rt])
	}
}

// checkNonzeroPaths reads through all records of a type, and checks that the fields
// indicated by paths are nonzero. If not, ErrZero is returned.
func checkNonzeroRecords(tx *Tx, st storeType, tv *typeVersion, m map[reflect.Type]*nonzeroCheckType) error {
	rb, err := tx.recordsBucket(st.Current.name, st.Current.fillPercent)
	if err != nil {
		return err
	}

	ctxDone := tx.ctx.Done()

	return rb.ForEach(func(bk, bv []byte) error {
		tx.stats.Records.Cursor++

		select {
		case <-ctxDone:
			return tx.ctx.Err()
		default:
		}

		// todo optimize: instead of parsing the full record, use the fieldmap to see if the value is nonzero.
		rv, err := st.parseNew(bk, bv)
		if err != nil {
			return err
		}
		ct := m[st.Type]
		return checkNonzeroFields(m, st.Type, ct.newlyNonzero, ct.fields, rv)
	})
}

// checkNonzeroFields checks that the newly nonzero fields of a struct value are
// indeed nonzero, and walks down referenced types, checking the constraint.
func checkNonzeroFields(m map[reflect.Type]*nonzeroCheckType, t reflect.Type, newlyNonzero, fields []field, rv reflect.Value) error {
	// Check the newly nonzero fields.
	for _, f := range newlyNonzero {
		frv := rv.FieldByIndex(f.structField.Index)
		if f.Type.isZero(frv) {
			return fmt.Errorf("%w: field %q", ErrZero, f.Name)
		}
	}

	// Descend into referenced types.
	for _, f := range fields {
		switch f.Type.Kind {
		case kindMap, kindSlice, kindStruct, kindArray:
			ft := f.structField.Type
			if err := checkNonzeroFieldType(m, f.Type, ft, rv.FieldByIndex(f.structField.Index)); err != nil {
				return err
			}
		}
	}

	return nil
}

// checkNonzeroFieldType walks down a value, and checks that its (struct) types
// don't violate nonzero constraints.
// Does not check whether the value itself is nonzero. If required, that has
// already been checked.
func checkNonzeroFieldType(m map[reflect.Type]*nonzeroCheckType, ft fieldType, t reflect.Type, rv reflect.Value) error {
	if ft.Ptr {
		t = t.Elem()
	}
	if !m[t].needsCheck {
		return nil
	}

	if ft.Ptr && rv.IsZero() {
		return nil
	}

	if ft.Ptr {
		rv = rv.Elem()
	}

	unptr := func(t reflect.Type, ptr bool) reflect.Type {
		if ptr {
			return t.Elem()
		}
		return t
	}

	switch ft.Kind {
	case kindMap:
		kt := t.Key()
		vt := t.Elem()
		checkKey := m[unptr(kt, ft.MapKey.Ptr)].needsCheck
		checkValue := m[unptr(vt, ft.MapValue.Ptr)].needsCheck
		iter := rv.MapRange()
		for iter.Next() {
			if checkKey {
				if err := checkNonzeroFieldType(m, *ft.MapKey, kt, iter.Key()); err != nil {
					return err
				}
			}
			if checkValue {
				if err := checkNonzeroFieldType(m, *ft.MapValue, vt, iter.Value()); err != nil {
					return err
				}
			}
		}

	case kindSlice:
		et := t.Elem()
		n := rv.Len()
		for i := 0; i < n; i++ {
			if err := checkNonzeroFieldType(m, *ft.ListElem, et, rv.Index(i)); err != nil {
				return err
			}
		}
	case kindArray:
		et := t.Elem()
		n := ft.ArrayLength
		for i := 0; i < n; i++ {
			if err := checkNonzeroFieldType(m, *ft.ListElem, et, rv.Index(i)); err != nil {
				return err
			}
		}
	case kindStruct:
		ct := m[t]
		if err := checkNonzeroFields(m, t, ct.newlyNonzero, ct.fields, rv); err != nil {
			return err
		}
	}
	return nil
}
