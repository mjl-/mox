package bstore

import (
	"bytes"
	"fmt"
	"reflect"

	bolt "go.etcd.io/bbolt"
)

func (tx *Tx) structptr(value any) (reflect.Value, error) {
	rv := reflect.ValueOf(value)
	if !rv.IsValid() || rv.Kind() != reflect.Ptr || !rv.Elem().IsValid() || rv.Type().Elem().Kind() != reflect.Struct {
		return reflect.Value{}, fmt.Errorf("%w: value must be non-nil pointer to a struct, is %T", ErrParam, value)
	}
	rv = rv.Elem()
	return rv, nil
}

func (tx *Tx) structOrStructptr(value any) (reflect.Value, error) {
	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return reflect.Value{}, fmt.Errorf("%w: value must be non-nil if pointer", ErrParam)
	}
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
		if !rv.IsValid() {
			return rv, fmt.Errorf("%w: value must be non-nil if pointer", ErrParam)
		}
	}
	if rv.Kind() != reflect.Struct {
		return reflect.Value{}, fmt.Errorf("%w: value must be a struct or pointer to a struct, is %T", ErrParam, value)
	}
	return rv, nil
}

// update indices by comparing indexed fields of the ov (old) and v (new). Only if
// the fields changed will the index be updated. Either ov or v may be the
// reflect.Value zero value, indicating there is no old/new value and the index
// should be updated.
func (tx *Tx) updateIndices(tv *typeVersion, pk []byte, ov, v reflect.Value) error {

	changed := func(idx *index) bool {
		for _, f := range idx.Fields {
			rofv := ov.FieldByIndex(f.structField.Index)
			nofv := v.FieldByIndex(f.structField.Index)
			// note: checking the interface values is enough, we only allow comparable types as index fields.
			if rofv.Interface() != nofv.Interface() {
				return true
			}
		}
		return false
	}

	for _, idx := range tv.Indices {
		var add, remove bool
		if !ov.IsValid() {
			add = true
		} else if !v.IsValid() {
			remove = true
		} else if !changed(idx) {
			continue
		} else {
			add, remove = true, true
		}

		ib, err := tx.indexBucket(idx)
		if err != nil {
			return err
		}
		if remove {
			_, ik, err := idx.packKey(ov, pk)
			if err != nil {
				return err
			}
			tx.stats.Index.Delete++
			if sanityChecks {
				tx.stats.Index.Get++
				if ib.Get(ik) == nil {
					return fmt.Errorf("internal error: key missing from index")
				}
			}
			if err := ib.Delete(ik); err != nil {
				return fmt.Errorf("%w: removing from index: %s", ErrStore, err)
			}
		}
		if add {
			prek, ik, err := idx.packKey(v, pk)
			if err != nil {
				return err
			}
			if idx.Unique {
				tx.stats.Index.Cursor++
				if xk, _ := ib.Cursor().Seek(prek); xk != nil && bytes.HasPrefix(xk, prek) {
					return fmt.Errorf("%w: %q", ErrUnique, idx.Name)
				}
			}

			tx.stats.Index.Put++
			if err := ib.Put(ik, []byte{}); err != nil {
				return fmt.Errorf("inserting into index: %w", err)
			}
		}
	}
	return nil
}

func (tx *Tx) checkReferences(tv *typeVersion, pk []byte, ov, rv reflect.Value) error {
	for _, f := range tv.Fields {
		if len(f.References) == 0 {
			continue
		}
		frv := rv.FieldByIndex(f.structField.Index)
		if frv.IsZero() || (ov.IsValid() && ov.FieldByIndex(f.structField.Index).Interface() == frv.Interface()) {
			continue
		}
		k, err := packPK(frv)
		if err != nil {
			return err
		}
		for _, name := range f.References {
			rb, err := tx.recordsBucket(name, tv.fillPercent)
			if err != nil {
				return err
			}
			if rb.Get(k) == nil {
				return fmt.Errorf("%w: value %v from field %q to %q", ErrReference, frv.Interface(), f.Name, name)
			}
		}
	}
	return nil
}

func (tx *Tx) addStats() {
	tx.db.statsMutex.Lock()
	tx.db.stats.add(tx.stats)
	tx.db.statsMutex.Unlock()
	tx.stats = Stats{}
}

// Get fetches records by their primary key from the database. Each value must
// be a pointer to a struct.
//
// ErrAbsent is returned if the record does not exist.
func (tx *Tx) Get(values ...any) error {
	if tx.db == nil {
		return errTxClosed
	}

	for _, value := range values {
		tx.stats.Get++
		rv, err := tx.structptr(value)
		if err != nil {
			return err
		}
		st, err := tx.db.storeType(rv.Type())
		if err != nil {
			return err
		}
		rb, err := tx.recordsBucket(st.Current.name, st.Current.fillPercent)
		if err != nil {
			return err
		}
		k, _, _, err := st.Current.keyValue(tx, rv, false, rb)
		if err != nil {
			return err
		}
		tx.stats.Records.Get++
		bv := rb.Get(k)
		if bv == nil {
			return ErrAbsent
		}
		if err := st.parse(rv, bv); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes values by their primary key from the database. Each value
// must be a struct or pointer to a struct. Indices are automatically updated
// and referential integrity is maintained.
//
// ErrAbsent is returned if the record does not exist.
// ErrReference is returned if another record still references this record.
func (tx *Tx) Delete(values ...any) error {
	if tx.db == nil {
		return errTxClosed
	}

	for _, value := range values {
		tx.stats.Delete++
		rv, err := tx.structOrStructptr(value)
		if err != nil {
			return err
		}
		st, err := tx.db.storeType(rv.Type())
		if err != nil {
			return err
		}
		rb, err := tx.recordsBucket(st.Current.name, st.Current.fillPercent)
		if err != nil {
			return err
		}
		k, _, _, err := st.Current.keyValue(tx, rv, false, rb)
		if err != nil {
			return err
		}
		tx.stats.Records.Get++
		bv := rb.Get(k)
		if bv == nil {
			return ErrAbsent
		}
		rov, err := st.parseNew(k, bv)
		if err != nil {
			return fmt.Errorf("parsing current value: %w", err)
		}
		if err := tx.delete(rb, st, k, rov); err != nil {
			return err
		}
	}
	return nil
}

func (tx *Tx) delete(rb *bolt.Bucket, st storeType, k []byte, rov reflect.Value) error {
	// Check that anyone referencing this type does not reference this record.
	for _, refBy := range st.Current.referencedBy {
		if ib, err := tx.indexBucket(refBy); err != nil {
			return err
		} else {
			tx.stats.Index.Cursor++
			if xk, _ := ib.Cursor().Seek(k); xk != nil && bytes.HasPrefix(xk, k) {
				return fmt.Errorf("%w: index %q", ErrReference, refBy.Name)
			}
		}
	}

	// Delete value from indices.
	if err := tx.updateIndices(st.Current, k, rov, reflect.Value{}); err != nil {
		return fmt.Errorf("removing from indices: %w", err)
	}

	tx.stats.Records.Delete++
	return rb.Delete(k)
}

// Update updates records represented by values by their primary keys into the
// database. Each value must be a pointer to a struct. Indices are
// automatically updated.
//
// ErrAbsent is returned if the record does not exist.
func (tx *Tx) Update(values ...any) error {
	if tx.db == nil {
		return errTxClosed
	}

	for _, value := range values {
		tx.stats.Update++
		rv, err := tx.structptr(value)
		if err != nil {
			return err
		}

		st, err := tx.db.storeType(rv.Type())
		if err != nil {
			return err
		}

		if err := tx.put(st, rv, false); err != nil {
			return err
		}
	}
	return nil
}

// Insert inserts values as new records into the database. Each value must be a
// pointer to a struct. If the primary key field is zero and autoincrement is not
// disabled, the next sequence is assigned. Indices are automatically updated.
//
// ErrUnique is returned if the record already exists.
// ErrSeq is returned if no next autoincrement integer is available.
// ErrZero is returned if a nonzero constraint would be violated.
// ErrReference is returned if another record is referenced that does not exist.
func (tx *Tx) Insert(values ...any) error {
	if tx.db == nil {
		return errTxClosed
	}

	for _, value := range values {
		tx.stats.Insert++
		rv, err := tx.structptr(value)
		if err != nil {
			return err
		}

		st, err := tx.db.storeType(rv.Type())
		if err != nil {
			return err
		}

		if err := st.Current.applyDefault(rv); err != nil {
			return err
		}

		if err := tx.put(st, rv, true); err != nil {
			return err
		}
	}
	return nil
}

func (tx *Tx) put(st storeType, rv reflect.Value, insert bool) error {
	rb, err := tx.recordsBucket(st.Current.name, st.Current.fillPercent)
	if err != nil {
		return err
	}
	k, krv, seq, err := st.Current.keyValue(tx, rv, insert, rb)
	if err != nil {
		return err
	}
	if insert {
		tx.stats.Records.Get++
		bv := rb.Get(k)
		if bv != nil {
			return fmt.Errorf("%w: record already exists", ErrUnique)
		}
		err := tx.insert(rb, st, rv, krv, k)
		if err != nil && seq {
			// Zero out the generated sequence.
			krv.Set(reflect.Zero(krv.Type()))
		}
		return err
	} else {
		tx.stats.Records.Get++
		bv := rb.Get(k)
		if bv == nil {
			return ErrAbsent
		}
		ov, err := st.parseNew(k, bv)
		if err != nil {
			return fmt.Errorf("parsing current value: %w", err)
		}
		return tx.update(rb, st, rv, ov, k)
	}
}

func (tx *Tx) insert(rb *bolt.Bucket, st storeType, rv, krv reflect.Value, k []byte) error {
	v, err := st.pack(rv)
	if err != nil {
		return err
	}
	if err := tx.checkReferences(st.Current, k, reflect.Value{}, rv); err != nil {
		return err
	}
	if err := tx.updateIndices(st.Current, k, reflect.Value{}, rv); err != nil {
		return fmt.Errorf("updating indices for inserted value: %w", err)
	}
	tx.stats.Records.Put++
	if err := rb.Put(k, v); err != nil {
		return err
	}
	rv.Field(0).Set(krv)
	return nil
}

func (tx *Tx) update(rb *bolt.Bucket, st storeType, rv, rov reflect.Value, k []byte) error {
	if st.Current.equal(rov, rv) {
		return nil
	}

	v, err := st.pack(rv)
	if err != nil {
		return err
	}
	if err := tx.checkReferences(st.Current, k, rov, rv); err != nil {
		return err
	}
	if err := tx.updateIndices(st.Current, k, rov, rv); err != nil {
		return fmt.Errorf("updating indices for updated record: %w", err)
	}
	tx.stats.Records.Put++
	return rb.Put(k, v)
}

// Begin starts a transaction.
//
// If writable is true, the transaction allows modifications.  Only one writable
// transaction can be active at a time on a DB. No read-only transactions can be
// active at the same time. Attempting to begin a read-only transaction from a
// writable transaction leads to deadlock.
//
// A writable Tx can be committed or rolled back. A read-only transaction must
// always be rolled back.
func (db *DB) Begin(writable bool) (*Tx, error) {
	btx, err := db.bdb.Begin(writable)
	if err != nil {
		return nil, err
	}
	db.typesMutex.RLock()
	tx := &Tx{db: db, btx: btx}
	if writable {
		tx.stats.Writes++
	} else {
		tx.stats.Reads++
	}
	return tx, nil
}

// Rollback aborts and cancels any changes made in this transaction.
// Statistics are added to its DB.
func (tx *Tx) Rollback() error {
	if tx.db == nil {
		return errTxClosed
	}

	tx.addStats()
	tx.db.typesMutex.RUnlock()
	err := tx.btx.Rollback()
	tx.db = nil
	return err
}

// Commit commits changes made in the transaction to the database.
// Statistics are added to its DB.
func (tx *Tx) Commit() error {
	if tx.db == nil {
		return errTxClosed
	}

	tx.addStats()
	tx.db.typesMutex.RUnlock()
	err := tx.btx.Commit()
	if err != nil {
		tx.btx.Rollback() // Nothing to do for error.
	}
	tx.db = nil
	return err
}
