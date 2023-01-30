package bstore

import (
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"time"
)

/*
The records buckets map a primary key to the record data. The primary key is of
a form that we can scan/range over. So fixed with for integers. For strings and
bytes they are just their byte representation. We do not store the PK in the
record data. This means we cannot store a time.Time as primary key, because we
cannot have the timezone encoded for comparison reasons.

Index keys are similar to PK's. Unique and non-unique indices are encoded the
same. The stored values are always empty, the key consists of the field values
the index was created for, followed by the PK. The encoding of a field is nearly
the same as the encoding of that type as a primary key. The differences: strings
end with a \0 to make them self-delimiting; byte slices are not allowed because
they are not self-delimiting; time.Time is allowed because the time is available
in full (with timezone) in the record data.
*/

// packPK returns the PK bytes representation for the PK value rv.
func packPK(rv reflect.Value) ([]byte, error) {
	kv := rv.Interface()
	var buf []byte
	switch k := kv.(type) {
	case string:
		buf = []byte(k)
	case []byte:
		buf = k
	case bool:
		var b byte
		if k {
			b = 1
		}
		buf = []byte{b}
	case int8:
		buf = []byte{byte(uint8(k + math.MinInt8))}
	case int16:
		buf = binary.BigEndian.AppendUint16(nil, uint16(k+math.MinInt16))
	case int32:
		buf = binary.BigEndian.AppendUint32(nil, uint32(k+math.MinInt32))
	case int:
		if k < math.MinInt32 || k > math.MaxInt32 {
			return nil, fmt.Errorf("%w: int %d does not fit in int32", ErrParam, k)
		}
		buf = binary.BigEndian.AppendUint32(nil, uint32(k+math.MinInt32))
	case int64:
		buf = binary.BigEndian.AppendUint64(nil, uint64(k+math.MinInt64))
	case uint8:
		buf = []byte{k}
	case uint16:
		buf = binary.BigEndian.AppendUint16(nil, k)
	case uint32:
		buf = binary.BigEndian.AppendUint32(nil, k)
	case uint:
		if k > math.MaxUint32 {
			return nil, fmt.Errorf("%w: uint %d does not fit in uint32", ErrParam, k)
		}
		buf = binary.BigEndian.AppendUint32(nil, uint32(k))
	case uint64:
		buf = binary.BigEndian.AppendUint64(nil, k)
	default:
		return nil, fmt.Errorf("%w: unsupported primary key type %T", ErrType, kv)
	}
	return buf, nil
}

// parsePK parses primary key bk into rv.
func parsePK(rv reflect.Value, bk []byte) error {
	k, err := typeKind(rv.Type())
	if err != nil {
		return err
	}
	switch k {
	case kindBytes:
		buf := make([]byte, len(bk))
		copy(buf, bk)
		rv.SetBytes(buf)
		return nil
	case kindString:
		rv.SetString(string(bk))
		return nil
	}

	var need int
	switch k {
	case kindBool, kindInt8, kindUint8:
		need = 1
	case kindInt16, kindUint16:
		need = 2
	case kindInt32, kindUint32, kindInt, kindUint:
		need = 4
	case kindInt64, kindUint64:
		need = 8
	}
	if len(bk) != need {
		return fmt.Errorf("%w: got %d bytes for PK, need %d", ErrStore, len(bk), need)
	}

	switch k {
	case kindBool:
		rv.SetBool(bk[0] != 0)
	case kindInt8:
		rv.SetInt(int64(int8(bk[0]) - math.MinInt8))
	case kindInt16:
		rv.SetInt(int64(int16(binary.BigEndian.Uint16(bk)) - math.MinInt16))
	case kindInt32, kindInt:
		rv.SetInt(int64(int32(binary.BigEndian.Uint32(bk)) - math.MinInt32))
	case kindInt64:
		rv.SetInt(int64(int64(binary.BigEndian.Uint64(bk)) - math.MinInt64))
	case kindUint8:
		rv.SetUint(uint64(bk[0]))
	case kindUint16:
		rv.SetUint(uint64(binary.BigEndian.Uint16(bk)))
	case kindUint32, kindUint:
		rv.SetUint(uint64(binary.BigEndian.Uint32(bk)))
	case kindUint64:
		rv.SetUint(uint64(binary.BigEndian.Uint64(bk)))
	default:
		// note: we cannot have kindTime as primary key at the moment.
		return fmt.Errorf("%w: unsupported primary key type %v", ErrType, rv.Type())
	}
	return nil
}

// parseKey parses the PK (last element) of an index key.
// If all is set, also gathers the values before and returns them in the second
// parameter.
func (idx *index) parseKey(buf []byte, all bool) ([]byte, [][]byte, error) {
	var err error
	var keys [][]byte
	take := func(n int) {
		if len(buf) < n {
			err = fmt.Errorf("%w: not enough bytes in index key", ErrStore)
			return
		}
		if all {
			keys = append(keys, buf[:n])
		}
		buf = buf[n:]
	}
fields:
	for _, f := range idx.Fields {
		if err != nil {
			break
		}
		switch f.Type.Kind {
		case kindString:
			for i, b := range buf {
				if b == 0 {
					if all {
						keys = append(keys, buf[:i])
					}
					buf = buf[i+1:]
					continue fields
				}
			}
			err = fmt.Errorf("%w: bad string without 0 in index key", ErrStore)
		case kindBool:
			take(1)
		case kindInt8, kindUint8:
			take(1)
		case kindInt16, kindUint16:
			take(2)
		case kindInt32, kindUint32, kindInt, kindUint:
			take(4)
		case kindInt64, kindUint64:
			take(8)
		case kindTime:
			take(8 + 4)
		}
	}
	if err != nil {
		return nil, nil, err
	}

	pk := buf

	switch idx.tv.Fields[0].Type.Kind {
	case kindBool:
		take(1)
	case kindInt8, kindUint8:
		take(1)
	case kindInt16, kindUint16:
		take(2)
	case kindInt32, kindInt, kindUint32, kindUint:
		take(4)
	case kindInt64, kindUint64:
		take(8)
	}
	if len(pk) != len(buf) && len(buf) != 0 {
		return nil, nil, fmt.Errorf("%w: leftover bytes in index key (%x)", ErrStore, buf)
	}
	if all {
		return pk, keys[:len(keys)-1], nil
	}
	return pk, nil, nil
}

// packKey returns a key to store in an index: first the prefix without pk, then
// the prefix including pk.
func (idx *index) packKey(rv reflect.Value, pk []byte) ([]byte, []byte, error) {
	var l []reflect.Value
	for _, f := range idx.Fields {
		frv := rv.FieldByIndex(f.structField.Index)
		l = append(l, frv)
	}
	return packIndexKeys(l, pk)
}

// packIndexKeys packs values from l, followed by the pk.
// It returns the key prefix (without pk), and full key with pk.
func packIndexKeys(l []reflect.Value, pk []byte) ([]byte, []byte, error) {
	var prek, ik []byte
	for _, frv := range l {
		k, err := typeKind(frv.Type())
		if err != nil {
			return nil, nil, err
		}
		var buf []byte
		switch k {
		case kindBool:
			buf = []byte{0}
			if frv.Bool() {
				buf[0] = 1
			}
		case kindInt8:
			buf = []byte{byte(int8(frv.Int()) + math.MinInt8)}
		case kindInt16:
			buf = binary.BigEndian.AppendUint16(nil, uint16(int16(frv.Int())+math.MinInt16))
		case kindInt32:
			buf = binary.BigEndian.AppendUint32(nil, uint32(int32(frv.Int())+math.MinInt32))
		case kindInt:
			i := frv.Int()
			if i < math.MinInt32 || i > math.MaxInt32 {
				return nil, nil, fmt.Errorf("%w: int value %d does not fit in int32", ErrParam, i)
			}
			buf = binary.BigEndian.AppendUint32(nil, uint32(int32(i)+math.MinInt32))
		case kindInt64:
			buf = binary.BigEndian.AppendUint64(nil, uint64(frv.Int()+math.MinInt64))
		case kindUint8:
			buf = []byte{byte(frv.Uint())}
		case kindUint16:
			buf = binary.BigEndian.AppendUint16(nil, uint16(frv.Uint()))
		case kindUint32:
			buf = binary.BigEndian.AppendUint32(nil, uint32(frv.Uint()))
		case kindUint:
			i := frv.Uint()
			if i > math.MaxUint32 {
				return nil, nil, fmt.Errorf("%w: uint value %d does not fit in uint32", ErrParam, i)
			}
			buf = binary.BigEndian.AppendUint32(nil, uint32(i))
		case kindUint64:
			buf = binary.BigEndian.AppendUint64(nil, uint64(frv.Uint()))
		case kindString:
			buf = []byte(frv.String())
			for _, c := range buf {
				if c == 0 {
					return nil, nil, fmt.Errorf("%w: string used as index key cannot have \\0", ErrParam)
				}
			}
			buf = append(buf, 0)
		case kindTime:
			tm := frv.Interface().(time.Time)
			buf = binary.BigEndian.AppendUint64(nil, uint64(tm.Unix()+math.MinInt64))
			buf = binary.BigEndian.AppendUint32(buf, uint32(tm.Nanosecond()))
		default:
			return nil, nil, fmt.Errorf("internal error: bad type %v for index", frv.Type()) // todo: should be caught when making index type
		}
		ik = append(ik, buf...)
	}
	n := len(ik)
	ik = append(ik, pk...)
	prek = ik[:n]
	return prek, ik, nil
}
