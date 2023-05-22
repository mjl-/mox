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
a form that we can scan/range over. So fixed width for integers. For strings and
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
		ft := f.Type
		if ft.Kind == kindSlice {
			// For an index on a slice, we store each value in the slice in a separate index key.
			ft = *ft.ListElem
		}
		switch ft.Kind {
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
		default:
			err = fmt.Errorf("%w: unhandled kind %v for index key", ErrStore, ft.Kind)
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

type indexkey struct {
	pre  []byte // Packed fields excluding PK, a slice of full.
	full []byte // Packed fields including PK.
}

// packKey returns keys to store in an index: first the key prefixes without pk, then
// the prefixes including pk.
func (idx *index) packKey(rv reflect.Value, pk []byte) ([]indexkey, error) {
	var l []reflect.Value
	for _, f := range idx.Fields {
		frv := rv.FieldByIndex(f.structField.Index)
		l = append(l, frv)
	}
	return packIndexKeys(l, pk)
}

// packIndexKeys packs values from l, followed by the pk.
// It returns the key prefixes (without pk), and full keys with pk.
func packIndexKeys(l []reflect.Value, pk []byte) ([]indexkey, error) {
	ikl := []indexkey{{}}
	for _, frv := range l {
		bufs, err := packIndexKey(frv)
		if err != nil {
			return nil, err
		}

		if len(bufs) == 1 {
			for i := range ikl {
				ikl[i].full = append(ikl[i].full, bufs[0]...)
			}
		} else if len(ikl) == 1 && len(bufs) > 1 {
			nikl := make([]indexkey, len(bufs))
			for i, buf := range bufs {
				nikl[i] = indexkey{full: append(append([]byte{}, ikl[0].full...), buf...)}
			}
			ikl = nikl
		} else if len(bufs) == 0 {
			return nil, nil
		} else {
			return nil, fmt.Errorf("%w: multiple index fields that result in multiple values, or no data for index key, %d keys so far, %d new buffers", ErrStore, len(ikl), len(bufs))
		}
	}
	for i := range ikl {
		n := len(ikl[i].full)
		ikl[i].full = append(ikl[i].full, pk...)
		ikl[i].pre = ikl[i].full[:n]
	}
	return ikl, nil
}

func packIndexKey(frv reflect.Value) ([][]byte, error) {
	k, err := typeKind(frv.Type())
	if err != nil {
		return nil, err
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
			return nil, fmt.Errorf("%w: int value %d does not fit in int32", ErrParam, i)
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
			return nil, fmt.Errorf("%w: uint value %d does not fit in uint32", ErrParam, i)
		}
		buf = binary.BigEndian.AppendUint32(nil, uint32(i))
	case kindUint64:
		buf = binary.BigEndian.AppendUint64(nil, uint64(frv.Uint()))
	case kindString:
		buf = []byte(frv.String())
		for _, c := range buf {
			if c == 0 {
				return nil, fmt.Errorf("%w: string used as index key cannot have \\0", ErrParam)
			}
		}
		buf = append(buf, 0)
	case kindTime:
		tm := frv.Interface().(time.Time)
		buf = binary.BigEndian.AppendUint64(nil, uint64(tm.Unix()+math.MinInt64))
		buf = binary.BigEndian.AppendUint32(buf, uint32(tm.Nanosecond()))
	case kindSlice:
		n := frv.Len()
		bufs := make([][]byte, n)
		for i := 0; i < n; i++ {
			nbufs, err := packIndexKey(frv.Index(i))
			if err != nil {
				return nil, fmt.Errorf("packing element from slice field: %w", err)
			}
			if len(nbufs) != 1 {
				return nil, fmt.Errorf("packing element from slice field resulted in multiple buffers (%d)", len(bufs))
			}
			bufs[i] = nbufs[0]
		}
		return bufs, nil
	default:
		return nil, fmt.Errorf("internal error: bad type %v for index", frv.Type()) // todo: should be caught when making index type
	}
	return [][]byte{buf}, nil
}
