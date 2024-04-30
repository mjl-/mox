package bstore

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"time"
)

type parser struct {
	buf  []byte
	orig []byte
}

func (p *parser) Errorf(format string, args ...any) {
	panic(parseErr{fmt.Errorf(format, args...)})
}

func (p *parser) checkInt(un uint64) int {
	if un > math.MaxInt32 {
		p.Errorf("%w: uvarint %d does not fit in int32", ErrStore, un)
	}
	return int(un)
}

// Fieldmap starts a new fieldmap for n fields.
func (p *parser) Fieldmap(n int) fieldmap {
	// log.Printf("parse fieldmap %d bits", n)
	nb := (n + 7) / 8
	buf := p.Take(nb)
	return fieldmap{n, buf, 0, 0, p.Errorf}
}

// Take reads nb bytes.
func (p *parser) Take(nb int) []byte {
	// log.Printf("take %d", nb)
	if len(p.buf) < nb {
		p.Errorf("%w: not enough bytes", ErrStore)
	}
	buf := p.buf[:nb]
	p.buf = p.buf[nb:]
	return buf
}

// TakeBytes reads a uvarint representing the size of the bytes, followed by
// that number of bytes.
// dup is needed if you need to hold on to the bytes. Values from BoltDB are
// only valid in the transaction, and not meant to be modified and are
// memory-mapped read-only.
func (p *parser) TakeBytes(dup bool) []byte {
	un := p.Uvarint()
	n := p.checkInt(un)
	buf := p.Take(n)
	if dup {
		// todo: check for a max size, beyond which we refuse to allocate?
		nbuf := make([]byte, len(buf))
		copy(nbuf, buf)
		buf = nbuf
	}
	return buf
}

func (p *parser) Uvarint() uint64 {
	v, n := binary.Uvarint(p.buf)
	if n == 0 {
		p.Errorf("%w: uvarint: not enough bytes", ErrStore)
	}
	if n < 0 {
		p.Errorf("%w: uvarint overflow", ErrStore)
	}
	// log.Printf("take uvarint, %d bytes", n)
	p.buf = p.buf[n:]
	return v
}

func (p *parser) Varint() int64 {
	v, n := binary.Varint(p.buf)
	if n == 0 {
		p.Errorf("%w: varint: not enough bytes", ErrStore)
	}
	if n < 0 {
		p.Errorf("%w: varint overflow", ErrStore)
	}
	// log.Printf("take varint, %d bytes", n)
	p.buf = p.buf[n:]
	return v
}

type parseErr struct {
	err error
}

// parse rv (reflect.Struct) from buf.
// does not part primary key field.
func (st storeType) parse(rv reflect.Value, buf []byte) (rerr error) {
	p := &parser{buf: buf, orig: buf}
	var version uint32
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		perr, ok := x.(parseErr)
		if ok {
			rerr = fmt.Errorf("%w (version %d, buf %x, orig %x)", perr.err, version, p.buf, p.orig)
			return
		}
		panic(x)
	}()

	version = uint32(p.Uvarint())
	tv, ok := st.Versions[version]
	if !ok {
		return fmt.Errorf("%w: unknown type version %d", ErrStore, version)
	}

	tv.parse(p, rv)

	if len(p.buf) != 0 {
		return fmt.Errorf("%w: leftover data after parsing (%d, %x %q)", ErrStore, len(p.buf), p.buf, p.buf)
	}

	return nil
}

// parseNew parses bk and bv into a newly created value of type st.Type.
func (st storeType) parseNew(bk, bv []byte) (reflect.Value, error) {
	rv := reflect.New(st.Type).Elem()
	if err := st.parseFull(rv, bk, bv); err != nil {
		return reflect.Value{}, err
	}
	return rv, nil
}

// parseFull parses a full record from bk and bv into value rv, which must be
// of type st.Type.
func (st storeType) parseFull(rv reflect.Value, bk, bv []byte) error {
	if err := parsePK(rv.Field(0), bk); err != nil {
		return err
	}
	err := st.parse(rv, bv)
	if err != nil {
		return err
	}
	return nil
}

func (tv typeVersion) parse(p *parser, rv reflect.Value) {
	// First field is the primary key, stored as boltdb key only, not in
	// the value.
	fm := p.Fieldmap(len(tv.Fields) - 1)
	for i, f := range tv.Fields[1:] {
		if f.structField.Type == nil {
			// Do not parse this field in the current Go type, but
			// we must still skip over the bytes.
			if fm.Nonzero(i) {
				f.Type.skip(p)
			}
			continue
		}
		if fm.Nonzero(i) {
			f.Type.parse(p, rv.FieldByIndex(f.structField.Index))
		} else if f.Nonzero {
			// Consistency check. Should not happen, we enforce nonzeroness.
			p.Errorf("%w: unexpected nonzero value for %q", ErrStore, f.Name)
		} else {
			rv.FieldByIndex(f.structField.Index).Set(reflect.Zero(f.structField.Type))
		}
	}
}

// parse a nonzero fieldType.
func (ft fieldType) parse(p *parser, rv reflect.Value) {
	// Because we allow schema changes from ptr to nonptr, rv can be a
	// pointer or direct value regardless of ft.Ptr.
	if rv.Kind() == reflect.Ptr {
		nrv := reflect.New(rv.Type().Elem())
		rv.Set(nrv)
		rv = nrv.Elem()
	}
	switch ft.Kind {
	case kindBytes:
		rv.SetBytes(p.TakeBytes(true))
	case kindBinaryMarshal:
		buf := p.TakeBytes(false)
		t := rv.Type()
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		v := reflect.New(t)
		err := v.Interface().(encoding.BinaryUnmarshaler).UnmarshalBinary(buf)
		if err != nil {
			panic(parseErr{err})
		}
		if rv.Type().Kind() == reflect.Ptr {
			rv.Set(v)
		} else {
			rv.Set(v.Elem())
		}
	case kindBool:
		if ft.Ptr {
			buf := p.Take(1)
			rv.SetBool(buf[0] != 0)
		} else {
			rv.SetBool(true)
		}
	case kindInt:
		v := p.Varint()
		if v < math.MinInt32 || v > math.MaxInt32 {
			p.Errorf("%w: int %d does not fit in int32", ErrStore, v)
		}
		rv.SetInt(v)
	case kindInt8, kindInt16, kindInt32, kindInt64:
		rv.SetInt(p.Varint())
	case kindUint:
		v := p.Uvarint()
		if v > math.MaxUint32 {
			p.Errorf("%w: uint %d does not fit in uint32", ErrStore, v)
		}
		rv.SetUint(v)
	case kindUint8, kindUint16, kindUint32, kindUint64:
		rv.SetUint(p.Uvarint())
	case kindFloat32:
		rv.SetFloat(float64(math.Float32frombits(uint32(p.Uvarint()))))
	case kindFloat64:
		rv.SetFloat(math.Float64frombits(p.Uvarint()))
	case kindString:
		rv.SetString(string(p.TakeBytes(false)))
	case kindTime:
		err := rv.Addr().Interface().(*time.Time).UnmarshalBinary(p.TakeBytes(false))
		if err != nil {
			p.Errorf("%w: parsing time: %s", ErrStore, err)
		}
	case kindSlice:
		un := p.Uvarint()
		n := p.checkInt(un)
		fm := p.Fieldmap(n)
		slc := reflect.MakeSlice(rv.Type(), n, n)
		for i := 0; i < int(n); i++ {
			if fm.Nonzero(i) {
				ft.ListElem.parse(p, slc.Index(i))
			}
		}
		rv.Set(slc)
	case kindArray:
		n := ft.ArrayLength
		fm := p.Fieldmap(n)
		for i := 0; i < n; i++ {
			if fm.Nonzero(i) {
				ft.ListElem.parse(p, rv.Index(i))
			}
		}
	case kindMap:
		un := p.Uvarint()
		n := p.checkInt(un)
		fm := p.Fieldmap(n)
		mp := reflect.MakeMapWithSize(rv.Type(), n)
		for i := 0; i < n; i++ {
			mk := reflect.New(rv.Type().Key()).Elem()
			ft.MapKey.parse(p, mk)
			mv := reflect.New(rv.Type().Elem()).Elem()
			if fm.Nonzero(i) {
				ft.MapValue.parse(p, mv)
			}
			mp.SetMapIndex(mk, mv)
		}
		rv.Set(mp)
	case kindStruct:
		fm := p.Fieldmap(len(ft.structFields))
		strct := reflect.New(rv.Type()).Elem()
		for i, f := range ft.structFields {
			if f.structField.Type == nil {
				if fm.Nonzero(i) {
					f.Type.skip(p)
				}
				continue
			}
			if fm.Nonzero(i) {
				f.Type.parse(p, strct.FieldByIndex(f.structField.Index))
			} else if f.Nonzero {
				// Consistency check, we enforce that nonzero is not stored if not allowed.
				p.Errorf("%w: %q", ErrZero, f.Name)
			} else {
				strct.FieldByIndex(f.structField.Index).Set(reflect.Zero(f.structField.Type))
			}
		}
		rv.Set(strct)
	default:
		p.Errorf("internal error: unhandled field type") // should be prevented when registering type
	}
}

// skip over the bytes for this fieldType. Needed when an older typeVersion has
// a field that the current reflect.Type does not (can) have.
func (ft fieldType) skip(p *parser) {
	switch ft.Kind {
	case kindBytes, kindBinaryMarshal, kindString:
		p.TakeBytes(false)
	case kindBool:
		if ft.Ptr {
			p.Take(1)
		}
	case kindInt8, kindInt16, kindInt32, kindInt, kindInt64:
		p.Varint()
	case kindUint8, kindUint16, kindUint32, kindUint, kindUint64, kindFloat32, kindFloat64:
		p.Uvarint()
	case kindTime:
		p.TakeBytes(false)
	case kindSlice:
		un := p.Uvarint()
		n := p.checkInt(un)
		fm := p.Fieldmap(n)
		for i := 0; i < n; i++ {
			if fm.Nonzero(i) {
				ft.ListElem.skip(p)
			}
		}
	case kindArray:
		n := ft.ArrayLength
		fm := p.Fieldmap(n)
		for i := 0; i < n; i++ {
			if fm.Nonzero(i) {
				ft.ListElem.skip(p)
			}
		}
	case kindMap:
		un := p.Uvarint()
		n := p.checkInt(un)
		fm := p.Fieldmap(n)
		for i := 0; i < n; i++ {
			ft.MapKey.skip(p)
			if fm.Nonzero(i) {
				ft.MapValue.skip(p)
			}
		}
	case kindStruct:
		fm := p.Fieldmap(len(ft.structFields))
		for i, f := range ft.structFields {
			if fm.Nonzero(i) {
				f.Type.skip(p)
			}
		}
	default:
		p.Errorf("internal error: unhandled field type") // should be prevented when registering type
	}
}
