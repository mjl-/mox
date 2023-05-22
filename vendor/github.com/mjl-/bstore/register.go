package bstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// todo: implement changing PK type, eg to wider int. requires rewriting all values, and removing old typeVersions.
// todo: allow schema change between []byte and string?
// todo: allow more schema changes, eg int to string, bool to int or string, int to bool, perhaps even string to int/bool. and between structs and maps. would require rewriting the records.

const (
	// First version.
	ondiskVersion1 = 1

	// With support for cyclic types, adding typeField.FieldsTypeSeq to
	// define/reference types. Only used when a type has a field that references another
	// struct type.
	ondiskVersion2 = 2
)

var errSchemaCheck = errors.New("schema check")

// Register registers the Go types of each value in typeValues for use with the
// database. Each value must be a struct, not a pointer.
//
// Type definition versions (schema versions) are added to the database if they
// don't already exist or have changed. Existing type definitions are checked
// for compatibility. Unique indexes are created if they don't already exist.
// Creating a new unique index fails with ErrUnique on duplicate values.  If a
// nonzero constraint is added, all records are verified to be nonzero. If a zero
// value is found, ErrZero is returned.
//
// Register can be called multiple times, with different types. But types that
// reference each other must be registered in the same call to Registers.
//
// To help during development, if environment variable "bstore_schema_check" is set
// to "changed", an error is returned if there is no schema change. If it is set to
// "unchanged", an error is returned if there was a schema change.
func (db *DB) Register(ctx context.Context, typeValues ...any) error {
	// We will drop/create new indices as needed. For changed indices, we drop
	// and recreate. E.g. if an index becomes a unique index, or if a field in
	// an index changes.  These values map type and index name to their index.
	oindices := map[string]map[string]*index{} // Existing in previous typeVersion.
	nindices := map[string]map[string]*index{} // Existing in new typeVersion.

	otypeversions := map[string]*typeVersion{} // Replaced typeVersions.
	ntypeversions := map[string]*typeVersion{} // New typeversions, through new types or updated versions of existing types.
	registered := map[string]*storeType{}      // Registered in this call.

	checkSchemaChanged := os.Getenv("bstore_schema_check") == "changed"
	checkSchemaUnchanged := os.Getenv("bstore_schema_check") == "unchanged"

	return db.Write(ctx, func(tx *Tx) error {
		for _, t := range typeValues {
			rt := reflect.TypeOf(t)
			if rt.Kind() != reflect.Struct {
				return fmt.Errorf("%w: type value %T is not a struct", ErrParam, t)
			}

			tv, err := gatherTypeVersion(rt)
			if err != nil {
				return fmt.Errorf("%w: generating schema for type %q", err, rt.Name())
			}

			// Ensure buckets exist.
			tx.stats.Bucket.Get++
			b := tx.btx.Bucket([]byte(tv.name))
			var rb, tb *bolt.Bucket
			if b == nil {
				var err error
				tx.stats.Bucket.Put++
				b, err = tx.btx.CreateBucket([]byte(tv.name))
				if err != nil {
					return fmt.Errorf("creating bucket for type %q: %w", tv.name, err)
				}
				tx.stats.Bucket.Put++
				rb, err = b.CreateBucket([]byte("records"))
				if err != nil {
					return fmt.Errorf("creating records bucket for type %q: %w", tv.name, err)
				}
				tx.stats.Bucket.Put++
				tb, err = b.CreateBucket([]byte("types"))
				if err != nil {
					return fmt.Errorf("creating types bucket for type %q: %w", tv.name, err)
				}
			} else {
				rb, err = tx.recordsBucket(tv.name, tv.fillPercent)
				if err != nil {
					return err
				}
				tb, err = tx.bucket(bucketKey{tv.name, "types"})
				if err != nil {
					return err
				}
			}

			st, ok := db.typeNames[tv.name]
			if ok {
				return fmt.Errorf("%w: type %q already registered", ErrParam, tv.name)
			}
			st = storeType{
				Name:     tv.name,
				Type:     rt,
				Versions: map[uint32]*typeVersion{},
			}

			// We read all type definitions.
			err = tb.ForEach(func(bk, bv []byte) error {
				// note: we don't track stats for types operations.

				otv, err := parseSchema(bk, bv)
				if err != nil {
					return err
				}
				if _, ok := st.Versions[otv.Version]; ok {
					return fmt.Errorf("%w: duplicate schema version %d", ErrStore, otv.Version)
				}
				st.Versions[otv.Version] = otv
				if st.Current == nil || otv.Version > st.Current.Version {
					st.Current = otv
				}
				return nil
			})
			if err != nil {
				return err
			}

			// Decide if we need to add a new typeVersion to the database. I.e. a new type schema.
			if st.Current == nil || !st.Current.typeEqual(*tv) {
				if checkSchemaUnchanged {
					return fmt.Errorf("%w: schema changed but bstore_schema_check=unchanged is set (type %v)", errSchemaCheck, st.Name)
				}
				checkSchemaChanged = false // After registering types, we check that it is false.

				tv.Version = 1
				if st.Current != nil {
					tv.Version = st.Current.Version + 1
				}
				k, v, err := packSchema(tv)
				if err != nil {
					return fmt.Errorf("internal error: packing schema for type %q", tv.name)
				}

				// Sanity check: parse the typeVersion again, and check that we think it is equal to the typeVersion just written.
				if xtv, err := parseSchema(k, v); err != nil {
					return fmt.Errorf("%w: parsing generated typeVersion: %v", ErrStore, err)
				} else if !xtv.typeEqual(*tv) {
					return fmt.Errorf("%w: generated typeVersion not equal to itself after pack and parse", ErrStore)
				}

				// note: we don't track types bucket operations in stats.
				if err := tb.Put(k, v); err != nil {
					return fmt.Errorf("storing new schema: %w", err)
				}

				if st.Current != nil {
					// Copy current ReferencedBy, updated later and check for consistency.
					tv.ReferencedBy = map[string]struct{}{}
					for name := range st.Current.ReferencedBy {
						tv.ReferencedBy[name] = struct{}{}
					}

					// Indices can change: between index and unique, or fields.
					// We recreate them for such changes.
					recreateIndices := map[string]struct{}{}
					if err := tx.checkTypes(st.Current, tv, recreateIndices); err != nil {
						return fmt.Errorf("checking compatibility of types: %w", err)
					}
					for iname := range recreateIndices {
						ibname := fmt.Sprintf("index.%s", iname)
						tx.stats.Bucket.Delete++
						if err := b.DeleteBucket([]byte(ibname)); err != nil {
							return fmt.Errorf("%w: deleting bucket %q for incompatible index that would be recreated: %v", ErrStore, ibname, err)
						}
						delete(st.Current.Indices, iname)
					}

					oindices[st.Name] = st.Current.Indices
					otypeversions[st.Name] = st.Current

					// If the current latest (old) primary key has "noauto", but
					// the new version does not, we will ensure the records
					// bucket sequence (that we use for autoincrement) is set to
					// the highest value stored so far.
					if st.Current.Noauto && !tv.Noauto {
						tx.stats.Records.Cursor++
						bk, _ := rb.Cursor().Last()
						if bk != nil {
							rv := reflect.New(tv.Fields[0].structField.Type).Elem()
							if err := parsePK(rv, bk); err != nil {
								return fmt.Errorf("parsing pk of last record to update autoincrement sequence: %w", err)
							}
							var seq uint64
							switch tv.Fields[0].Type.Kind {
							case kindInt8, kindInt16, kindInt32, kindInt64, kindInt:
								seq = uint64(rv.Int())
							case kindUint8, kindUint16, kindUint32, kindUint64, kindUint:
								seq = rv.Uint()
							default:
								return fmt.Errorf("internal error: noauto on non-int primary key: %v", err)
							}
							if err := rb.SetSequence(seq); err != nil {
								return fmt.Errorf("%w: updating autoincrement sequence after schema change: %s", ErrStore, err)
							}
						}
					}
				}
				nindices[st.Name] = tv.Indices
				ntypeversions[st.Name] = tv
			} else {
				tv.Version = st.Current.Version
				// Start out with the previous ReferencedBy. May be updated later.
				tv.ReferencedBy = st.Current.ReferencedBy
			}

			// Prepare types for parsing into the registered reflect.Type.
			st.prepare(tv)

			st.Current = tv
			st.Versions[tv.Version] = tv
			db.typeNames[st.Name] = st
			db.types[st.Type] = st
			registered[st.Name] = &st
		}

		if checkSchemaChanged {
			return fmt.Errorf("%w: schema did not change while bstore_schema_check=changed is set", errSchemaCheck)
		}

		// Check that referenced types exist, and make links in the referenced types.
		for _, st := range registered {
			tv := st.Current
			for name := range tv.references {
				_, ok := registered[name]
				if !ok {
					return fmt.Errorf("%w: type %q referenced by type %q not registered; you must register them in the same call to Open/Register", ErrType, name, tv.name)
				}
			}

			// Link fields that are referenced.
			for _, f := range tv.Fields {
				for _, ref := range f.References {
					rtv := db.typeNames[ref].Current
					k := f.Type.Kind
					refk := rtv.Fields[0].Type.Kind
					if k != refk {
						return fmt.Errorf("%w: %s.%s references %s.%s but fields have different types %s and %s", ErrType, tv.name, f.Name, rtv.name, rtv.Fields[0].Name, k, refk)
					}
					// todo: should check if an index on this field exists, regardless of name. safes us an index.
					idx, ok := tv.Indices[f.Name+":"+ref]
					if !ok {
						return fmt.Errorf("internal error: missing index for ref")
					}
					rtv.referencedBy = append(rtv.referencedBy, idx)
				}
			}
		}

		// Ensure that for all registered storeTypes, their Current.ReferencedBy are up to
		// date by adding/removing. We mark those that need updating. We only have to check
		// ntypeversions: If a reference by a type changed, a new typeversion is created.
		// We cannot just recalculate the ReferencedBy, because the whole point is to
		// detect types that are missing in this Register.
		updateReferencedBy := map[string]struct{}{}
		for ntname, ntv := range ntypeversions {
			otv := otypeversions[ntv.name] // Can be nil, on first register.

			// Look for references that were added.
			for name := range ntv.references {
				if otv != nil {
					if _, ok := otv.references[name]; ok {
						// Reference was present in previous typeVersion, nothing to do.
						continue
					}
				}
				if _, ok := registered[name].Current.ReferencedBy[ntv.name]; ok {
					return fmt.Errorf("%w: type %q introduces reference to %q but is already marked as ReferencedBy in that type", ErrStore, ntv.name, name)
				}

				// Verify that the new reference does not violate the foreign key constraint.
				var foundField bool
				for _, f := range ntv.Fields {
					for _, rname := range f.References {
						if rname != name {
							continue
						}

						foundField = true

						// For newly added references, check they are valid.
						b, err := tx.recordsBucket(ntname, ntv.fillPercent)
						if err != nil {
							return fmt.Errorf("%w: bucket for type %s with field with new reference: %v", ErrStore, ntname, err)
						}

						rb, err := tx.recordsBucket(name, registered[name].Current.fillPercent)
						if err != nil {
							return fmt.Errorf("%w: bucket for referenced type %s: %v", ErrStore, name, err)
						}

						nst := registered[ntname]
						rv := reflect.New(nst.Type).Elem()
						ctxDone := ctx.Done()
						err = b.ForEach(func(bk, bv []byte) error {
							tx.stats.Records.Cursor++

							select {
							case <-ctxDone:
								return tx.ctx.Err()
							default:
							}

							if err := nst.parse(rv, bv); err != nil {
								return fmt.Errorf("parsing record for %s: %w", ntname, err)
							}
							frv := rv.FieldByIndex(f.structField.Index)
							if frv.IsZero() {
								return nil
							}
							rpk, err := packPK(frv)
							if err != nil {
								return fmt.Errorf("packing pk for referenced type %s: %w", name, err)
							}
							tx.stats.Records.Cursor++
							if rb.Get(rpk) == nil {
								return fmt.Errorf("%w: value %v not in %s", ErrReference, frv.Interface(), name)
							}
							return nil
						})
						if err != nil {
							return fmt.Errorf("%w: ensuring referential integrity for newly added reference of %s.%s", err, ntname, f.Name)
						}
					}
				}
				if !foundField {
					return fmt.Errorf("%w: could not find field causing newly referenced type %s in type %s", ErrStore, name, ntname)
				}

				// note: we are updating the previous tv's ReferencedBy, not tidy but it is safe.
				registered[name].Current.ReferencedBy[ntv.name] = struct{}{}
				updateReferencedBy[name] = struct{}{}
			}
			if otv == nil {
				continue
			}
			// Look for references that were removed.
			// We cannot use summary field otv.references, it isn't set, we go to the source,
			// otv.Fields[].References.
			orefs := map[string]struct{}{}
			for _, f := range otv.Fields {
				for _, name := range f.References {
					orefs[name] = struct{}{}
				}
			}
			for name := range orefs {
				if _, ok := ntv.references[name]; ok {
					continue
				}
				if rtv, ok := registered[name]; !ok {
					return fmt.Errorf("%w: type %q formerly referenced by %q not yet registered", ErrStore, name, ntv.name)
				} else if _, ok := rtv.Current.ReferencedBy[ntv.name]; !ok {
					return fmt.Errorf("%w: formerly referenced type %q missing from %q", ErrStore, name, ntv.name)
				}
				// note: we are updating the previous tv's ReferencedBy, not tidy but it is safe.
				delete(registered[name].Current.ReferencedBy, ntv.name)
				updateReferencedBy[name] = struct{}{}
			}
		}

		// Update/create new typeversions based on updated ReferencedBy.
		for name := range updateReferencedBy {
			// If we already created a new typeVersion in this Register, we can just update it
			// again. Otherwise we create a new typeVersion, but none of the other checks
			// (eg index) because those weren't changed (or we would have a new typeversion already).
			// We don't update ntypeversions/otypeversions, the changed ReferencedBy aren't relevant below this point.
			ntvp, ok := ntypeversions[name]
			if !ok {
				st := registered[name]
				ntv := *st.Current
				ntv.Version++
				st.Versions[ntv.Version] = &ntv
				st.Current = &ntv
				db.types[st.Type] = *st
				db.typeNames[st.Name] = *st
				ntvp = &ntv
			}

			k, v, err := packSchema(ntvp)
			if err != nil {
				return fmt.Errorf("internal error: packing schema for type %q", ntvp.name)
			}
			tb, err := tx.bucket(bucketKey{ntvp.name, "types"})
			if err != nil {
				return err
			}
			// note: we don't track types bucket operations in stats.
			if err := tb.Put(k, v); err != nil {
				return fmt.Errorf("storing new schema: %w", err)
			}
		}

		// Now that all ReferencedBy are up to date, verify that all referenced types were
		// registered in this call.
		// The whole point of this exercise is to catch a Register of a type that is
		// referenced, but whose type isn't registered. If we would allow registering just this
		// referenced type, users can delete data that is still referenced by the
		// not-registered registering type.
		for _, st := range registered {
			for name := range st.Current.ReferencedBy {
				if _, ok := registered[name]; !ok {
					return fmt.Errorf("%w: must register %q that references %q in same Open/Register call", ErrType, name, st.Name)
				}
			}
		}

		// Check that any new nonzero constraints are correct.
		for _, tv := range ntypeversions {
			otv, ok := otypeversions[tv.name]
			if !ok {
				continue
			}

			st := db.typeNames[tv.name]
			if err := tx.checkNonzero(st, tv, otv.Fields, tv.Fields); err != nil {
				return err
			}
		}

		// Drop old/modified indices.
		for name, tindices := range oindices {
			for iname, idx := range tindices {
				var drop bool
				if _, ok := nindices[name]; !ok {
					drop = true
				} else if _, ok := nindices[name][iname]; !ok {
					drop = true
				} else if !idx.typeEqual(nindices[name][iname]) {
					drop = true
				}
				if !drop {
					continue
				}
				b, err := tx.typeBucket(name)
				if err != nil {
					return err
				}
				ibname := fmt.Sprintf("index.%s", iname)
				tx.stats.Bucket.Delete++
				if err := b.DeleteBucket([]byte(ibname)); err != nil {
					return fmt.Errorf("%w: deleting bucket %q for old/modified index: %v", ErrStore, ibname, err)
				}
			}
		}

		// Create new/modified indices.
		for name, tindices := range nindices {
			// First prepare, checking if we should create this index and preparing the index bucket if so.
			var idxs []*index
			var ibs []*bolt.Bucket
			for iname, idx := range tindices {
				var create bool
				if _, ok := oindices[name]; !ok {
					create = true
				} else if _, ok := oindices[name][iname]; !ok {
					create = true
				} else if !idx.typeEqual(oindices[name][iname]) {
					create = true
				}
				if !create {
					continue
				}
				b, err := tx.typeBucket(name)
				if err != nil {
					return err
				}
				ibname := []byte(fmt.Sprintf("index.%s", iname))
				tx.stats.Bucket.Put++
				ib, err := b.CreateBucket(ibname)
				if err != nil {
					return fmt.Errorf("%w: creating bucket %q for old/modified index: %v", ErrStore, ibname, err)
				}
				idxs = append(idxs, idx)
				ibs = append(ibs, ib)
			}

			if len(idxs) == 0 {
				continue
			}

			st := db.typeNames[name]
			rb, err := tx.recordsBucket(name, st.Current.fillPercent)
			if err != nil {
				return err
			}

			// We first generate all keys. Then sort them and insert them.
			// Random inserts can be slow in boltdb. We can efficiently verify
			// that the values are indeed unique by keeping track of the non-PK
			// prefix length and checking the key inserted previously.
			type key struct {
				buf []byte
				pre uint16
			}
			ibkeys := make([][]key, len(idxs))

			ctxDone := ctx.Done()
			err = rb.ForEach(func(bk, bv []byte) error {
				tx.stats.Records.Cursor++

				select {
				case <-ctxDone:
					return tx.ctx.Err()
				default:
				}

				rv := reflect.New(st.Type).Elem()
				if err := st.parse(rv, bv); err != nil {
					return fmt.Errorf("parsing record for index for %s: %w", name, err)
				}

				for i, idx := range idxs {
					ikl, err := idx.packKey(rv, bk)
					if err != nil {
						return fmt.Errorf("creating key for %s.%s: %w", name, idx.Name, err)
					}
					for _, ik := range ikl {
						ibkeys[i] = append(ibkeys[i], key{ik.full, uint16(len(ik.pre))})
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("preparing index keys for type %q: %w", name, err)
			}

			insertKeys := func(idx *index, ib *bolt.Bucket, keys []key) error {
				ib.FillPercent = 1
				defer func() {
					ib.FillPercent = 0.5
				}()
				for i, k := range keys {
					if idx.Unique && i > 0 {
						prev := keys[i-1]
						if bytes.Equal(prev.buf[:prev.pre], k.buf[:k.pre]) {
							// Do quite a bit of work to make a helpful error message.
							a := reflect.New(reflect.TypeOf(idx.tv.Fields[0].Type.zeroKey())).Elem()
							b := reflect.New(reflect.TypeOf(idx.tv.Fields[0].Type.zeroKey())).Elem()
							parsePK(a, prev.buf[prev.pre:]) // Ignore error, nothing to do.
							parsePK(b, k.buf[k.pre:])       // Ignore error, nothing to do.
							var dup []any
							_, values, _ := idx.parseKey(k.buf, true)
							for i := range values {
								x := reflect.New(reflect.TypeOf(idx.Fields[i].Type.zeroKey())).Elem()
								parsePK(x, values[i]) // Ignore error, nothing to do.
								dup = append(dup, x.Interface())
							}
							return fmt.Errorf("%w: duplicate value %v on index %s.%s for ids %v and %v", ErrUnique, dup, name, idx.Name, a.Interface(), b.Interface())
						}
					}
					tx.stats.Index.Put++
					if err := ib.Put(k.buf, []byte{}); err != nil {
						return fmt.Errorf("inserting index key into %s.%s: %w", name, idxs[i].Name, err)
					}
				}
				return nil
			}

			// Now do all sorts + inserts.
			for i, ib := range ibs {
				idx := idxs[i]
				keys := ibkeys[i]
				sort.Slice(keys, func(i, j int) bool {
					return bytes.Compare(keys[i].buf, keys[j].buf) < 0
				})
				if err := insertKeys(idx, ib, keys); err != nil {
					return err
				}
				ibkeys[i] = nil
			}
		}
		return nil
	})
}

// parseSchema parses a schema from the type bucket into a typeversion.
func parseSchema(bk, bv []byte) (*typeVersion, error) {
	if len(bk) != 4 {
		return nil, fmt.Errorf("%w: version: got %d bytes, need 4", ErrStore, len(bk))
	}
	version := binary.BigEndian.Uint32(bk)

	// We store these in self-describing json, to prevent complications if we want to adjust our formats in the future.

	var tv typeVersion
	if err := json.Unmarshal(bv, &tv); err != nil {
		return nil, fmt.Errorf("%w: unmarshal schema: %v", ErrStore, err)
	}
	if tv.Version != version {
		return nil, fmt.Errorf("%w: version in schema %d does not match key %d", ErrStore, tv.Version, version)
	}
	switch tv.OndiskVersion {
	case ondiskVersion1, ondiskVersion2:
	default:
		return nil, fmt.Errorf("internal error: OndiskVersion %d not recognized/supported", tv.OndiskVersion)
	}

	// Fill references, used for comparing/checking schema updates.
	tv.references = map[string]struct{}{}
	for _, f := range tv.Fields {
		for _, ref := range f.References {
			tv.references[ref] = struct{}{}
		}
	}

	// Resolve fieldType.structFields, for referencing defined types, used for
	// supporting cyclic types. The type itself always implicitly has sequence 1.
	seqFields := map[int][]field{1: tv.Fields}
	origOndiskVersion := tv.OndiskVersion
	for i := range tv.Fields {
		if err := tv.resolveStructFields(seqFields, &tv.Fields[i].Type); err != nil {
			return nil, fmt.Errorf("%w: resolving struct fields for referencing types: %v", ErrStore, err)
		}
	}
	if tv.OndiskVersion != origOndiskVersion {
		return nil, fmt.Errorf("%w: resolving cyclic types changed ondisk version from %d to %d", ErrStore, origOndiskVersion, tv.OndiskVersion)
	}

	return &tv, nil
}

// Resolve structFields in ft (and recursively), either by setting it to Fields
// (common), or by setting it to the fields of a referenced type in case of a
// cyclic data type.
func (tv *typeVersion) resolveStructFields(seqFields map[int][]field, ft *fieldType) error {
	if ft.Kind == kindStruct {
		if ft.FieldsTypeSeq < 0 {
			var ok bool
			ft.structFields, ok = seqFields[-ft.FieldsTypeSeq]
			if !ok {
				return fmt.Errorf("reference to undefined FieldsTypeSeq %d (n %d)", -ft.FieldsTypeSeq, len(seqFields))
			}
			if len(ft.DefinitionFields) != 0 {
				return fmt.Errorf("reference to FieldsTypeSeq while also defining fields")
			}
		} else if ft.FieldsTypeSeq > 0 {
			if _, ok := seqFields[ft.FieldsTypeSeq]; ok {
				return fmt.Errorf("duplicate definition of FieldsTypeSeq %d (n %d)", ft.FieldsTypeSeq, len(seqFields))
			}
			seqFields[ft.FieldsTypeSeq] = ft.DefinitionFields
			ft.structFields = ft.DefinitionFields
		}
		// note: ondiskVersion1 does not have/use this field, so it defaults to 0.
		if ft.FieldsTypeSeq == 0 {
			ft.structFields = ft.DefinitionFields
		}

		for i := range ft.DefinitionFields {
			if err := tv.resolveStructFields(seqFields, &ft.DefinitionFields[i].Type); err != nil {
				return err
			}
		}
	}

	xftl := []*fieldType{ft.MapKey, ft.MapValue, ft.ListElem}
	for _, xft := range xftl {
		if xft == nil {
			continue
		}
		if err := tv.resolveStructFields(seqFields, xft); err != nil {
			return err
		}
	}
	return nil
}

// packSchema returns a key and value to store in the types bucket.
func packSchema(tv *typeVersion) ([]byte, []byte, error) {
	switch tv.OndiskVersion {
	case ondiskVersion1, ondiskVersion2:
	default:
		return nil, nil, fmt.Errorf("internal error: invalid OndiskVersion %d", tv.OndiskVersion)
	}
	v, err := json.Marshal(tv)
	if err != nil {
		return nil, nil, fmt.Errorf("internal error: marshal schema: %v", err)
	}
	k := binary.BigEndian.AppendUint32(nil, tv.Version)
	return k, v, nil
}

func gatherTypeVersion(t reflect.Type) (*typeVersion, error) {
	if t.NumField() == 0 {
		return nil, fmt.Errorf("%w: type must have at least one field", ErrType)
	}
	tname, err := typeName(t)
	if err != nil {
		return nil, err
	}
	tv := &typeVersion{
		Version:       0,              // Set by caller.
		OndiskVersion: ondiskVersion2, // When opening a database with ondiskVersion1, we add a new typeVersion.
		ReferencedBy:  map[string]struct{}{},
		name:          tname,
		fillPercent:   0.5,
	}

	// The type being parsed implicitly has sequence 1. Next struct types will be
	// assigned the next value (based on length of typeseqs). FieldTypes referencing
	// another type are resolved below, after all fields have been gathered.
	typeSeqs := map[reflect.Type]int{t: 1}
	tv.Fields, tv.embedFields, err = gatherTypeFields(typeSeqs, t, true, true, false, true)
	if err != nil {
		return nil, err
	}
	tags, err := newStoreTags(t.Field(0).Tag.Get("bstore"), true)
	if err != nil {
		return nil, err
	}
	tv.Noauto = tags.Has("noauto")
	if tv.Noauto {
		switch tv.Fields[0].Type.Kind {
		case kindInt, kindInt8, kindInt16, kindInt32, kindInt64, kindUint, kindUint8, kindUint16, kindUint32, kindUint64:
		default:
			return nil, fmt.Errorf("%w: cannot have noauto on non-integer primary key field", ErrType)
		}
	}

	// Resolve structFields for the typeFields that reference an earlier defined type,
	// using the same function as used when loading a type from disk.
	seqFields := map[int][]field{1: tv.Fields}
	for i := range tv.Fields {
		if err := tv.resolveStructFields(seqFields, &tv.Fields[i].Type); err != nil {
			return nil, fmt.Errorf("%w: resolving struct fields for referencing types: %v", ErrStore, err)
		}
	}

	// Find indices.
	tv.Indices = map[string]*index{}

	addIndex := func(unique bool, iname string, fields ...*field) error {
		idx := tv.Indices[iname]
		if idx != nil {
			return fmt.Errorf("%w: duplicate unique/index %q", ErrType, iname)
		}
		idx = &index{unique, iname, nil, tv}
		tv.Indices[iname] = idx
		nslice := 0
		for _, f := range fields {
			// todo: can we have a unique index on bytes? seems like this should be possible to have max 1 []byte in an index key, only to be used for unique get plans.
			if f.Type.Ptr {
				return fmt.Errorf("%w: cannot have index/unique on ptr field %s.%s", ErrType, tname, f.Name)
			}
			switch f.Type.Kind {
			case kindBool, kindInt8, kindInt16, kindInt32, kindInt64, kindInt, kindUint8, kindUint16, kindUint32, kindUint64, kindUint, kindString, kindTime:
			case kindSlice:
				nslice++
				if nslice > 1 {
					return fmt.Errorf("%w: can only have one slice field in index, for field %q", ErrType, f.Name)
				}
				if unique {
					return fmt.Errorf("%w: can only use slice field %v in field %q as index without unique", ErrType, f.Type.Kind, f.Name)
				}
			default:
				return fmt.Errorf("%w: cannot use type %v in field %q as index/unique", ErrType, f.Type.Kind, f.Name)
			}

			if f.indices == nil {
				f.indices = map[string]*index{}
			}
			f.indices[iname] = idx
			idx.Fields = append(idx.Fields, *f)
		}
		return nil
	}

	fields := map[string]*field{}
	for i, f := range tv.Fields {
		fields[f.Name] = &tv.Fields[i]
	}

	addNamedIndex := func(unique bool, tag string, f *field) error {
		t := strings.Split(tag, " ")
		if len(t) > 2 {
			return fmt.Errorf("%w: invalid unique/index, too many tokens in %q", ErrType, tag)
		}
		iname := t[0]
		if len(t) == 2 {
			iname = t[1]
		}

		names := strings.Split(t[0], "+")
		if names[0] != f.Name {
			return fmt.Errorf("%w: invalid unique/index %q, first field must be same as struct field %q", ErrType, iname, f.Name)
		}
		seen := map[string]struct{}{}
		var ifields []*field
		for _, fname := range names {
			if _, ok := seen[fname]; ok {
				return fmt.Errorf("%w: duplicate field %q in unique/index %q", ErrType, fname, iname)
			}
			seen[fname] = struct{}{}
			xf := fields[fname]
			if xf == nil {
				return fmt.Errorf("%w: unknown field %q in unique/index %q", ErrType, fname, iname)
			}
			ifields = append(ifields, xf)
		}
		return addIndex(unique, iname, ifields...)
	}

	for i := range tv.Fields {
		f := &tv.Fields[i]
		rft := t.FieldByIndex(f.structField.Index)
		tags, err := newStoreTags(rft.Tag.Get("bstore"), i == 0)
		if err != nil {
			return nil, err
		}
		if tags.Has("unique") {
			if err := addIndex(true, f.Name, f); err != nil {
				return nil, err
			}
		}
		if tags.Has("index") {
			if err := addIndex(false, f.Name, f); err != nil {
				return nil, err
			}
		}
		for _, name := range tags.List("unique") {
			if err := addNamedIndex(true, name, f); err != nil {
				return nil, err
			}
		}
		for _, name := range tags.List("index") {
			if err := addNamedIndex(false, name, f); err != nil {
				return nil, err
			}
		}
	}

	// Gather references. Add indices if they don't already exist.
	tv.references = map[string]struct{}{}
	for i := range tv.Fields {
		f := &tv.Fields[i]
		refseen := map[string]struct{}{}
		tags, err := newStoreTags(f.structField.Tag.Get("bstore"), i == 0)
		if err != nil {
			return nil, err
		}
		for _, name := range tags.List("ref") {
			if _, ok := refseen[name]; ok {
				return nil, fmt.Errorf("%w: duplicate references %q in field %q", ErrType, name, f.Name)
			}
			refseen[name] = struct{}{}
			tv.references[name] = struct{}{}

			iname := f.Name + ":" + name
			if idx, ok := tv.Indices[iname]; ok {
				if len(idx.Fields) != 1 || idx.Fields[0].Name != f.Name {
					return nil, fmt.Errorf("%w: reference requires an index, but another index with name %q for the field already exists", ErrType, iname)
				}
			} else {
				if err := addIndex(false, iname, f); err != nil {
					return nil, err
				}
			}
		}
	}

	return tv, nil
}

// gatherTypeFields gathers fields for a struct. If needFirst is true, the first
// field must not be ignored and be a valid primary key field (eg no pointer).
// topLevel must be true only for the top-level struct fields, not for fields of
// deeper levels. Deeper levels cannot have index/unique constraints.
func gatherTypeFields(typeSeqs map[reflect.Type]int, t reflect.Type, needFirst, topLevel, inMap, newSeq bool) ([]field, []embed, error) {
	var fields []field
	var embedFields []embed

	names := map[string]struct{}{}
	for i, sf := range reflect.VisibleFields(t) {
		tags, err := newStoreTags(sf.Tag.Get("bstore"), i == 0 && needFirst && topLevel)
		if err != nil {
			return nil, nil, err
		}
		nonzero := tags.Has("nonzero")
		if i == 0 && needFirst {
			if !sf.IsExported() {
				return nil, nil, fmt.Errorf("%w: first field is primary key and must be exported", ErrType)
			}
			if sf.Anonymous {
				// todo: We don't allow this now because the code often reads tv.Fields[0] to get the
				// PK field. We could allow it, but it could confuse users, thinking the entire
				// struct would become a PK.
				return nil, nil, fmt.Errorf("%w: first field cannot be an embed/anonymous field", ErrType)
			}
			if nonzero {
				return nil, nil, fmt.Errorf("%w: superfluous nonzero tag on primary key", ErrType)
			}
			if err := checkKeyType(sf.Type); err != nil {
				return nil, nil, err
			}
		}
		if nonzero && sf.Anonymous {
			return nil, nil, fmt.Errorf("%w: cannot have nonzero on embed/anonymous field %q", ErrType, sf.Name)
		}
		if tags.Has("-") && sf.Anonymous {
			return nil, nil, fmt.Errorf(`%w: cannot have "-" on embed/anonymous field %q`, ErrType, sf.Name)
		}
		if !sf.IsExported() || tags.Has("-") {
			continue
		}
		if !topLevel && (tags.Has("unique") || tags.Has("index")) {
			return nil, nil, fmt.Errorf("%w: %q", errNestedIndex, sf.Name)
		}

		name, err := tags.Get("name")
		if err != nil {
			return nil, nil, err
		} else if name == "" {
			name = sf.Name
		}
		if _, ok := names[name]; ok {
			return nil, nil, fmt.Errorf("%w: duplicate field %q", ErrType, name)
		}
		names[name] = struct{}{}

		ft, err := gatherFieldType(typeSeqs, sf.Type, inMap, newSeq && !sf.Anonymous)
		if err != nil {
			return nil, nil, fmt.Errorf("field %q: %w", sf.Name, err)
		}

		// Parse a default value.
		var def reflect.Value
		defstr, err := tags.Get("default")
		if err != nil {
			return nil, nil, fmt.Errorf("field %q: %w", sf.Name, err)
		} else if defstr != "" {
			if inMap {
				return nil, nil, fmt.Errorf("%w: cannot have default value inside a map value", ErrType)
			}
			var defv any
			convert := true
			switch ft.Kind {
			case kindBool:
				convert = false
				switch defstr {
				case "true":
					defv = true
				case "false":
					defv = false
				default:
					err = fmt.Errorf("%w: bad bool value %q for %s.%s", ErrType, defstr, t.Name(), sf.Name)
				}
			case kindInt, kindInt32:
				defv, err = strconv.ParseInt(defstr, 0, 32)
			case kindInt8:
				defv, err = strconv.ParseInt(defstr, 0, 8)
			case kindInt16:
				defv, err = strconv.ParseInt(defstr, 0, 16)
			case kindInt64:
				defv, err = strconv.ParseInt(defstr, 0, 64)
			case kindUint, kindUint32:
				defv, err = strconv.ParseUint(defstr, 0, 32)
			case kindUint8:
				defv, err = strconv.ParseUint(defstr, 0, 8)
			case kindUint16:
				defv, err = strconv.ParseUint(defstr, 0, 16)
			case kindUint64:
				defv, err = strconv.ParseUint(defstr, 0, 64)
			case kindFloat32:
				defv, err = strconv.ParseFloat(defstr, 32)
			case kindFloat64:
				defv, err = strconv.ParseFloat(defstr, 64)
			case kindString:
				convert = false
				defv = defstr
			case kindTime:
				convert = false
				if defstr == "now" {
					defv = zerotime // Sentinel value recognized during evaluation.
				} else {
					defv, err = time.Parse(time.RFC3339, defstr)
				}
			default:
				return nil, nil, fmt.Errorf("%w: default not supported for type %v", ErrType, ft.Kind)
			}
			if err != nil {
				return nil, nil, fmt.Errorf("%w: bad default value %q for %s %s.%s", ErrType, defstr, ft.Kind, t.Name(), sf.Name)
			}
			deft := sf.Type
			if ft.Ptr {
				deft = sf.Type.Elem()
			}
			def = reflect.ValueOf(defv)
			if convert {
				def = def.Convert(deft)
			}
		}

		// We don't store anonymous/embed fields, unless it is a cyclic type, because then
		// we wouldn't have included any of its type's fields.
		if sf.Anonymous && ft.FieldsTypeSeq == 0 {
			e := embed{name, ft, sf}
			embedFields = append(embedFields, e)
		} else {
			f := field{name, ft, nonzero, tags.List("ref"), defstr, def, sf, false, nil}
			fields = append(fields, f)
		}
	}
	return fields, embedFields, nil
}

// checkKeyType returns an error if the type is not valid for use as primary key.
// similar to storeType.keyValue
func checkKeyType(t reflect.Type) error {
	k, err := typeKind(t)
	if err != nil {
		return err
	}
	switch k {
	case kindBytes, kindString, kindBool, kindInt, kindInt8, kindInt16, kindInt32, kindInt64, kindUint, kindUint8, kindUint16, kindUint32, kindUint64:
		return nil
	}
	return fmt.Errorf("%w: type %v not valid for primary key", ErrType, t)
}

func gatherFieldType(typeSeqs map[reflect.Type]int, t reflect.Type, inMap, newSeq bool) (fieldType, error) {
	ft := fieldType{}
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		ft.Ptr = true
	}

	k, err := typeKind(t)
	if err != nil {
		return fieldType{}, err
	}
	ft.Kind = k
	switch ft.Kind {
	case kindSlice:
		l, err := gatherFieldType(typeSeqs, t.Elem(), inMap, newSeq)
		if err != nil {
			return ft, fmt.Errorf("slice: %w", err)
		}
		ft.ListElem = &l
	case kindArray:
		l, err := gatherFieldType(typeSeqs, t.Elem(), inMap, newSeq)
		if err != nil {
			return ft, fmt.Errorf("array: %w", err)
		}
		ft.ListElem = &l
		ft.ArrayLength = t.Len()
	case kindMap:
		kft, err := gatherFieldType(typeSeqs, t.Key(), true, newSeq)
		if err != nil {
			return ft, fmt.Errorf("map key: %w", err)
		}
		if kft.Ptr {
			return ft, fmt.Errorf("%w: map key with pointer type not supported", ErrType)
		}
		vft, err := gatherFieldType(typeSeqs, t.Elem(), true, newSeq)
		if err != nil {
			return ft, fmt.Errorf("map value: %w", err)
		}
		ft.MapKey = &kft
		ft.MapValue = &vft
	case kindStruct:
		// If this is a known type, track a reference to the earlier defined type. Once the
		// type with all Fields is fully parsed, the references will be resolved.
		if seq, ok := typeSeqs[t]; ok {
			ft.FieldsTypeSeq = -seq
			return ft, nil
		}

		// If we are processing an anonymous (embed) field, we don't assign a new seq,
		// because we won't be walking it when resolving again.
		seq := len(typeSeqs) + 1
		if newSeq {
			typeSeqs[t] = seq
			ft.FieldsTypeSeq = seq
		}
		fields, _, err := gatherTypeFields(typeSeqs, t, false, false, inMap, newSeq)
		if err != nil {
			return fieldType{}, fmt.Errorf("struct: %w", err)
		}
		ft.DefinitionFields = fields
	}
	return ft, nil
}

// Prepare all types for parsing into the current type represented by ntv.
// We have to look at later typeVersions that may have removed a field. If so,
// we will not set it on t but leave it at its default value.
func (st storeType) prepare(ntv *typeVersion) {
	var l []*typeVersion
	for _, tv := range st.Versions {
		l = append(l, tv)
	}
	sort.Slice(l, func(i, j int) bool {
		return l[i].Version < l[j].Version
	})
	var later [][]field
	for _, tv := range l {
		later = append(later, tv.Fields)
	}
	for i, tv := range l {
		tv.prepare(ntv, later[i+1:])
	}
}

// prepare for use with parse.
func (tv typeVersion) prepare(ntv *typeVersion, later [][]field) {
	for i, f := range tv.Fields {
		nlater, nmvlater, skip := lookupLater(f.Name, later)
		if skip {
			continue
		}
		tv.Fields[i].prepare(ntv.Fields, nlater, nmvlater)
	}
}

// Lookup field "name" in "later", which is list of future fields.
// If the named field disappears in a future field list, skip will be true.
// Otherwise, in each future list of fields, the matching field is looked up and
// returned. For map types, the returned first list is for keys and second list for
// map values. For other types, only the first list is set.
func lookupLater(name string, later [][]field) (nlater, nmvlater [][]field, skip bool) {
	// If a later typeVersion did not have this field, we will not parse it into the
	// latest reflect type. This is old data that was discarded with a typeVersion
	// change.
tv:
	for _, newerFields := range later {
		for _, nf := range newerFields {
			if nf.Name == name {
				n, nmv := nf.Type.laterFields()
				nlater = append(nlater, n)
				nmvlater = append(nmvlater, nmv)
				continue tv
			}
		}
		return nil, nil, true
	}
	return nlater, nmvlater, false
}

func (f *field) prepare(nfields []field, later, mvlater [][]field) {
	if f.prepared {
		return
	}
	f.prepared = true
	for _, nf := range nfields {
		if nf.Name == f.Name {
			f.structField = nf.structField
			f.Type.prepare(&nf.Type, later, mvlater)
		}
	}
}

func (ft fieldType) laterFields() (later, mvlater []field) {
	if ft.MapKey != nil {
		later, _ = ft.MapKey.laterFields()
		mvlater, _ = ft.MapValue.laterFields()
		return later, mvlater
	} else if ft.ListElem != nil {
		return ft.ListElem.laterFields()
	}
	return ft.structFields, nil
}

func (ft fieldType) prepare(nft *fieldType, later, mvlater [][]field) {
	for i, f := range ft.structFields {
		nlater, nmvlater, skip := lookupLater(f.Name, later)
		if skip {
			continue
		}
		ft.structFields[i].prepare(nft.structFields, nlater, nmvlater)
	}
	if ft.MapKey != nil {
		ft.MapKey.prepare(nft.MapKey, later, nil)
		ft.MapValue.prepare(nft.MapValue, mvlater, nil)
	}
	if ft.ListElem != nil {
		ft.ListElem.prepare(nft.ListElem, later, mvlater)
	}
}

// typeEqual compares two typeVersions, typically the current for a
// storeType and a potential new typeVersion for a type that is being
// registered.
// If a field changes (add/remove/modify, including struct tag), a type is no
// longer equal.
// Does not take fields Version or Name into account.
func (tv typeVersion) typeEqual(ntv typeVersion) bool {
	if tv.OndiskVersion != ntv.OndiskVersion {
		return false
	}
	if tv.Noauto != ntv.Noauto {
		return false
	}
	if len(tv.Fields) != len(ntv.Fields) {
		return false
	}
	for i, f := range tv.Fields {
		if !f.typeEqual(ntv.Fields[i]) {
			return false
		}
	}

	// note: embedFields are not relevant for equality, they are just a convenient way to set multiple fields.

	if len(tv.Indices) != len(ntv.Indices) {
		return false
	}
	for name, idx := range tv.Indices {
		if nidx, ok := ntv.Indices[name]; !ok || !idx.typeEqual(nidx) {
			return false
		}
	}

	return true
}

func (f field) typeEqual(nf field) bool {
	if f.Name != nf.Name || !f.Type.typeEqual(nf.Type) || f.Nonzero != nf.Nonzero || f.Default != nf.Default {
		return false
	}
	if len(f.References) != len(nf.References) {
		return false
	}
	for i, s := range f.References {
		if s != nf.References[i] {
			return false
		}
	}
	return true
}

func (ft fieldType) typeEqual(nft fieldType) bool {
	if ft.Ptr != nft.Ptr || ft.Kind != nft.Kind {
		return false
	}
	if ft.FieldsTypeSeq != nft.FieldsTypeSeq {
		return false
	}
	if len(ft.DefinitionFields) != len(nft.DefinitionFields) {
		return false
	}
	for i, f := range ft.DefinitionFields {
		if !f.typeEqual(nft.DefinitionFields[i]) {
			return false
		}
	}
	if ft.MapKey != nil && (!ft.MapKey.typeEqual(*nft.MapKey) || !ft.MapValue.typeEqual(*nft.MapValue)) {
		return false
	}
	if ft.ListElem != nil && !ft.ListElem.typeEqual(*nft.ListElem) {
		return false
	}
	if ft.ArrayLength != nft.ArrayLength {
		return false
	}
	return true
}

func (idx *index) typeEqual(nidx *index) bool {
	if idx.Unique != nidx.Unique || idx.Name != nidx.Name {
		return false
	}
	if len(idx.Fields) != len(nidx.Fields) {
		return false
	}
	for i, f := range idx.Fields {
		if !f.typeEqual(nidx.Fields[i]) {
			return false
		}
	}
	return true
}

// checkTypes checks if typeVersions otv and ntv are consistent with
// their field types. E.g. an int32 can be changed into an int64, but an int64 cannot
// into an int32. Indices that need to be recreated (for an int width change) are
// recorded in recreateIndices.
func (tx *Tx) checkTypes(otv, ntv *typeVersion, recreateIndices map[string]struct{}) error {
	// Used to track that two nonzero FieldsTypeSeq have been checked, to prevent
	// recursing while checking.
	checked := map[[2]int]struct{}{}

	for _, f := range ntv.Fields {
		for _, of := range otv.Fields {
			if f.Name != of.Name {
				continue
			}
			increase, err := of.Type.compatible(f.Type, checked)
			if err != nil {
				return fmt.Errorf("%w: field %q: %s", ErrIncompatible, f.Name, err)
			}
			if increase {
				// Indices involving this field need to be recreated. The indices are packed with fixed widths.
				for name, idx := range otv.Indices {
					for _, ifield := range idx.Fields {
						if ifield.Name == f.Name {
							recreateIndices[name] = struct{}{}
							break
						}
					}
				}
			}
			break
		}
	}
	return nil
}

// compatible returns if ft and nft's types are compatible (with recursive checks
// for maps/slices/structs). If not an error is returned. If they are, the first
// return value indicates if this is a field that needs it index recreated
// (currently for ints that are packed with fixed width encoding).
func (ft fieldType) compatible(nft fieldType, checked map[[2]int]struct{}) (bool, error) {
	need := func(incr bool, l ...kind) (bool, error) {
		for _, k := range l {
			if nft.Kind == k {
				return incr, nil
			}
		}
		return false, fmt.Errorf("%w: need %v have %v", ErrIncompatible, l, nft.Kind)
	}

	k := ft.Kind
	nk := nft.Kind

	// We refuse to change pointers to non-pointers for composite types that have
	// fields with Nonzero set: nil values would become zero values.
	if ft.Ptr && !nft.Ptr && k == nk && nft.hasNonzeroField(false) {
		// todo: we could verify all data is nonzero?
		return false, fmt.Errorf("%w: type changing from ptr to non-ptr cannot have nonzero fields", ErrIncompatible)
	}

	switch k {
	case kindBytes, kindBool, kindBinaryMarshal, kindString, kindFloat32, kindFloat64, kindTime:
		return need(false, ft.Kind)
	case kindInt8:
		if nk == k {
			return false, nil
		}
		return need(true, kindInt16, kindInt32, kindInt, kindInt64)
	case kindInt16:
		if nk == k {
			return false, nil
		}
		return need(true, kindInt32, kindInt, kindInt64)
	case kindInt32, kindInt:
		if nk == k {
			return false, nil
		}
		return need(true, kindInt32, kindInt, kindInt64)
	case kindInt64:
		return need(false, kindInt64)
	case kindUint8:
		if nk == k {
			return false, nil
		}
		return need(true, kindUint16, kindUint32, kindUint, kindUint64)
	case kindUint16:
		if nk == k {
			return false, nil
		}
		return need(true, kindUint32, kindUint, kindUint64)
	case kindUint32, kindUint:
		if nk == k {
			return false, nil
		}
		return need(true, kindUint32, kindUint, kindUint64)
	case kindUint64:
		return need(false, kindUint64)
	case kindMap:
		if nk != k {
			return false, fmt.Errorf("map to %v: %w", nk, ErrIncompatible)
		}
		if _, err := ft.MapKey.compatible(*nft.MapKey, checked); err != nil {
			return false, fmt.Errorf("map key: %w", err)
		}
		if _, err := ft.MapValue.compatible(*nft.MapValue, checked); err != nil {
			return false, fmt.Errorf("map value: %w", err)
		}
		return false, nil
	case kindSlice:
		if nk != k {
			return false, fmt.Errorf("slice to %v: %w", nk, ErrIncompatible)
		}
		if _, err := ft.ListElem.compatible(*nft.ListElem, checked); err != nil {
			return false, fmt.Errorf("slice: %w", err)
		}
		return false, nil
	case kindArray:
		if nk != k {
			return false, fmt.Errorf("array to %v: %w", nk, ErrIncompatible)
		}
		if nft.ArrayLength != ft.ArrayLength {
			return false, fmt.Errorf("array size cannot change (from %d to %d)", ft.ArrayLength, nft.ArrayLength)
		}
		if _, err := ft.ListElem.compatible(*nft.ListElem, checked); err != nil {
			return false, fmt.Errorf("array: %w", err)
		}
		return false, nil
	case kindStruct:
		if nk != k {
			return false, fmt.Errorf("struct to %v: %w", nk, ErrIncompatible)
		}

		// For ondiskVersion2, the seqs are both nonzero, and we must check that we already
		// did the check to prevent recursion.
		haveSeq := nft.FieldsTypeSeq != 0 || ft.FieldsTypeSeq != 0
		if haveSeq {
			k := [2]int{nft.FieldsTypeSeq, ft.FieldsTypeSeq}
			if _, ok := checked[k]; ok {
				return false, nil
			}
			checked[k] = struct{}{} // Set early to prevent recursion in call below.
		}

		for _, nf := range nft.structFields {
			for _, f := range ft.structFields {
				if nf.Name == f.Name {
					_, err := f.Type.compatible(nf.Type, checked)
					if err != nil {
						return false, fmt.Errorf("field %q: %w", nf.Name, err)
					}
					break
				}
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("internal error: missing case for kind %v", k)
}

func (ft fieldType) hasNonzeroField(stopAtPtr bool) bool {
	if ft.Ptr && stopAtPtr {
		return false
	}
	switch ft.Kind {
	case kindMap:
		return ft.MapValue.hasNonzeroField(true)
	case kindSlice, kindArray:
		return ft.ListElem.hasNonzeroField(true)
	case kindStruct:
		for _, f := range ft.structFields {
			if f.Nonzero || f.Type.hasNonzeroField(true) {
				return true
			}
		}
	}
	return false
}
