package bstore

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Types returns the types present in the database, regardless of whether they
// are currently registered using Open or Register. Useful for exporting data
// with Keys and Records.
func (tx *Tx) Types() ([]string, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}

	var types []string
	err := tx.btx.ForEach(func(bname []byte, b *bolt.Bucket) error {
		// note: we do not track stats for types operations.

		types = append(types, string(bname))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return types, nil
}

// prepareType prepares typeName for export/introspection with DB.Keys,
// DB.Record, DB.Records. It is different in that it does not require a
// reflect.Type to parse into. It parses to a map, e.g. for export to JSON.
func (db *DB) prepareType(tx *Tx, typeName string) (map[uint32]*typeVersion, *typeVersion, *bolt.Bucket, []string, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, nil, nil, nil, err
	}

	rb, err := tx.recordsBucket(typeName, 0.5)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tb, err := tx.bucket(bucketKey{typeName, "types"})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	versions := map[uint32]*typeVersion{}
	var tv *typeVersion
	err = tb.ForEach(func(bk, bv []byte) error {
		// note: we do not track stats for types operations.

		ntv, err := parseSchema(bk, bv)
		if err != nil {
			return err
		}

		versions[ntv.Version] = ntv
		if tv == nil || ntv.Version > tv.Version {
			tv = ntv
		}

		return nil
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if tv == nil {
		return nil, nil, nil, nil, fmt.Errorf("%w: no type versions", ErrStore)
	}
	fields := make([]string, len(tv.Fields))
	for i, f := range tv.Fields {
		fields[i] = f.Name
	}
	return versions, tv, rb, fields, nil
}

// Keys returns the parsed primary keys for the type "typeName". The type does
// not have to be registered with Open or Register. For use with Record(s) to
// export data.
func (tx *Tx) Keys(typeName string, fn func(pk any) error) error {
	_, tv, rb, _, err := tx.db.prepareType(tx, typeName)
	if err != nil {
		return err
	}

	ctxDone := tx.ctx.Done()

	v := reflect.New(reflect.TypeOf(tv.Fields[0].Type.zeroKey())).Elem()
	return rb.ForEach(func(bk, bv []byte) error {
		tx.stats.Records.Cursor++

		select {
		case <-ctxDone:
			return tx.ctx.Err()
		default:
		}

		if err := parsePK(v, bk); err != nil {
			return err
		}
		return fn(v.Interface())
	})
}

// Record returns the record with primary "key" for "typeName" parsed as map.
// "Fields" is set to the fields of the type. The type does not have to be
// registered with Open or Register.  Record parses the data without the Go
// type present. BinaryMarshal fields are returned as bytes.
func (tx *Tx) Record(typeName, key string, fields *[]string) (map[string]any, error) {
	versions, tv, rb, xfields, err := tx.db.prepareType(tx, typeName)
	if err != nil {
		return nil, err
	}
	*fields = xfields

	var kv any
	switch tv.Fields[0].Type.Kind {
	case kindBool:
		switch key {
		case "true":
			kv = true
		case "false":
			kv = false
		default:
			err = fmt.Errorf("%w: invalid bool %q", ErrParam, key)
		}
	case kindInt8:
		kv, err = strconv.ParseInt(key, 10, 8)
	case kindInt16:
		kv, err = strconv.ParseInt(key, 10, 16)
	case kindInt32:
		kv, err = strconv.ParseInt(key, 10, 32)
	case kindInt:
		kv, err = strconv.ParseInt(key, 10, 32)
	case kindInt64:
		kv, err = strconv.ParseInt(key, 10, 64)
	case kindUint8:
		kv, err = strconv.ParseUint(key, 10, 8)
	case kindUint16:
		kv, err = strconv.ParseUint(key, 10, 16)
	case kindUint32:
		kv, err = strconv.ParseUint(key, 10, 32)
	case kindUint:
		kv, err = strconv.ParseUint(key, 10, 32)
	case kindUint64:
		kv, err = strconv.ParseUint(key, 10, 64)
	case kindString:
		kv = key
	case kindBytes:
		kv = []byte(key) // todo: or decode from base64?
	default:
		return nil, fmt.Errorf("internal error: unknown primary key kind %v", tv.Fields[0].Type.Kind)
	}
	if err != nil {
		return nil, err
	}
	pkv := reflect.ValueOf(kv)
	k, err := typeKind(pkv.Type())
	if err != nil {
		return nil, err
	}
	if k != tv.Fields[0].Type.Kind {
		// Convert from various int types above to required type. The ParseInt/ParseUint
		// calls already validated that the values fit.
		pkt := reflect.TypeOf(tv.Fields[0].Type.zeroKey())
		pkv = pkv.Convert(pkt)
	}
	pk, err := packPK(pkv)
	if err != nil {
		return nil, err
	}

	tx.stats.Records.Get++
	bv := rb.Get(pk)
	if bv == nil {
		return nil, ErrAbsent
	}
	record, err := parseMap(versions, pk, bv)
	if err != nil {
		return nil, err
	}
	return record, nil
}

// Records calls "fn" for each record of "typeName". Records sets "fields" to
// the fields of the type. The type does not have to be registered with Open or
// Register.  Record parses the data without the Go type present. BinaryMarshal
// fields are returned as bytes.
func (tx *Tx) Records(typeName string, fields *[]string, fn func(map[string]any) error) error {
	versions, _, rb, xfields, err := tx.db.prepareType(tx, typeName)
	if err != nil {
		return err
	}
	*fields = xfields

	ctxDone := tx.ctx.Done()

	return rb.ForEach(func(bk, bv []byte) error {
		tx.stats.Records.Cursor++

		select {
		case <-ctxDone:
			return tx.ctx.Err()
		default:
		}

		record, err := parseMap(versions, bk, bv)
		if err != nil {
			return err
		}
		return fn(record)
	})
}

// parseMap parses a record into a map with the right typeVersion from versions.
func parseMap(versions map[uint32]*typeVersion, bk, bv []byte) (record map[string]any, rerr error) {
	p := &parser{buf: bv, orig: bv}
	var version uint32

	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(parseErr); ok {
			rerr = fmt.Errorf("%w (version %d, buf %x orig %x)", err.err, version, p.buf, p.orig)
			return
		}
		panic(x)
	}()

	version = uint32(p.Uvarint())
	tv := versions[version]
	if tv == nil {
		return nil, fmt.Errorf("%w: unknown type version %d", ErrStore, version)
	}

	r := map[string]any{}

	v := reflect.New(reflect.TypeOf(tv.Fields[0].Type.zeroKey())).Elem()
	err := parsePK(v, bk)
	if err != nil {
		return nil, err
	}
	r[tv.Fields[0].Name] = v.Interface()

	// todo: Should we be looking at the most recent tv, and hiding fields
	// that have been removed in a later typeVersion? Like we do for real
	// parsing into reflect value?
	fm := p.Fieldmap(len(tv.Fields) - 1)
	for i, f := range tv.Fields[1:] {
		if fm.Nonzero(i) {
			r[f.Name] = f.Type.parseValue(p)
		} else {
			r[f.Name] = f.Type.zeroExportValue()
		}
	}

	if len(p.buf) != 0 {
		return nil, fmt.Errorf("%w: leftover data after parsing (%d %x %q)", ErrStore, len(p.buf), p.buf, p.buf)
	}

	return r, nil
}

func (ft fieldType) parseValue(p *parser) any {
	switch ft.Kind {
	case kindBytes:
		return p.TakeBytes(false)
	case kindBinaryMarshal:
		// We don't have the type available, so we just return the binary data.
		return p.TakeBytes(false)
	case kindBool:
		if !ft.Ptr {
			return true
		}
		buf := p.Take(1)
		return buf[0] != 0
	case kindInt8:
		return int8(p.Varint())
	case kindInt16:
		return int16(p.Varint())
	case kindInt32:
		return int32(p.Varint())
	case kindInt:
		i := p.Varint()
		if i < math.MinInt32 || i > math.MaxInt32 {
			p.Errorf("%w: int %d does not fit in int32", ErrStore, i)
		}
		return int(i)
	case kindInt64:
		return p.Varint()
	case kindUint8:
		return uint8(p.Uvarint())
	case kindUint16:
		return uint16(p.Uvarint())
	case kindUint32:
		return uint32(p.Uvarint())
	case kindUint:
		i := p.Uvarint()
		if i > math.MaxUint32 {
			p.Errorf("%w: uint %d does not fit in uint32", ErrStore, i)
		}
		return uint(i)
	case kindUint64:
		return p.Uvarint()
	case kindFloat32:
		return math.Float32frombits(uint32(p.Uvarint()))
	case kindFloat64:
		return math.Float64frombits(p.Uvarint())
	case kindString:
		return string(p.TakeBytes(false))
	case kindTime:
		var t time.Time
		err := t.UnmarshalBinary(p.TakeBytes(false))
		if err != nil {
			p.Errorf("%w: parsing time: %v", ErrStore, err)
		}
		return t
	case kindSlice:
		un := p.Uvarint()
		n := p.checkInt(un)
		fm := p.Fieldmap(n)
		var l []any
		for i := 0; i < n; i++ {
			if fm.Nonzero(i) {
				l = append(l, ft.ListElem.parseValue(p))
			} else {
				// Always add zero elements, or we would change the number of elements in a list.
				l = append(l, ft.ListElem.zeroExportValue())
			}
		}
		return l
	case kindArray:
		n := ft.ArrayLength
		l := make([]any, n)
		fm := p.Fieldmap(n)
		for i := 0; i < n; i++ {
			if fm.Nonzero(i) {
				l[i] = ft.ListElem.parseValue(p)
			} else {
				// Always add zero elements, or we would change the number of elements in the
				// array.
				l[i] = ft.ListElem.zeroExportValue()
			}
		}
		return l
	case kindMap:
		un := p.Uvarint()
		n := p.checkInt(un)
		fm := p.Fieldmap(n)
		m := map[string]any{}
		for i := 0; i < n; i++ {
			// Converting to string can be ugly, but the best we can do.
			k := fmt.Sprintf("%v", ft.MapKey.parseValue(p))
			if _, ok := m[k]; ok {
				return fmt.Errorf("%w: duplicate key %q in map", ErrStore, k)
			}
			var v any
			if fm.Nonzero(i) {
				v = ft.MapValue.parseValue(p)
			} else {
				v = ft.MapValue.zeroExportValue()
			}
			m[k] = v
		}
		return m
	case kindStruct:
		fm := p.Fieldmap(len(ft.structFields))
		m := map[string]any{}
		for i, f := range ft.structFields {
			if fm.Nonzero(i) {
				m[f.Name] = f.Type.parseValue(p)
			} else {
				m[f.Name] = f.Type.zeroExportValue()
			}
		}
		return m
	}
	p.Errorf("internal error: unhandled field type %v", ft.Kind)
	panic("cannot happen")
}

var zeroExportValues = map[kind]any{
	kindBytes:         []byte(nil),
	kindBinaryMarshal: []byte(nil), // We don't have the actual type available, so we just return binary data.
	kindBool:          false,
	kindInt8:          int8(0),
	kindInt16:         int16(0),
	kindInt32:         int32(0),
	kindInt:           int(0),
	kindInt64:         int64(0),
	kindUint8:         uint8(0),
	kindUint16:        uint16(0),
	kindUint32:        uint32(0),
	kindUint:          uint(0),
	kindUint64:        uint64(0),
	kindFloat32:       float32(0),
	kindFloat64:       float64(0),
	kindString:        "",
	kindTime:          zerotime,
	kindSlice:         []any(nil),
	kindMap:           map[string]any(nil),
	kindStruct:        map[string]any(nil),
	// kindArray handled in zeroExportValue()
}

// zeroExportValue returns the zero value for a fieldType for use with exporting.
func (ft fieldType) zeroExportValue() any {
	if ft.Kind == kindArray {
		ev := ft.ListElem.zeroExportValue()
		l := make([]any, ft.ArrayLength)
		for i := 0; i < ft.ArrayLength; i++ {
			l[i] = ev
		}
		return l
	}
	v, ok := zeroExportValues[ft.Kind]
	if !ok {
		panic(fmt.Errorf("internal error: unhandled zero value for field type %v", ft.Kind))
	}
	return v
}

var zeroKeys = map[kind]any{
	kindBytes:  []byte(nil),
	kindBool:   false,
	kindInt8:   int8(0),
	kindInt16:  int16(0),
	kindInt32:  int32(0),
	kindInt:    int(0),
	kindInt64:  int64(0),
	kindUint8:  uint8(0),
	kindUint16: uint16(0),
	kindUint32: uint32(0),
	kindUint:   uint(0),
	kindUint64: uint64(0),
	kindString: "",
	kindTime:   zerotime,
	// kindSlice handled in zeroKeyValue()
}

// zeroKeyValue returns the zero value for a fieldType for use with exporting.
func (ft fieldType) zeroKey() any {
	k := ft.Kind
	if k == kindSlice {
		k = ft.ListElem.Kind
	}
	v, ok := zeroKeys[k]
	if !ok {
		panic(fmt.Errorf("internal error: unhandled zero value for field type %v", ft.Kind))
	}
	return v
}
