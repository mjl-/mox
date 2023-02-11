package bstore

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"time"
)

// fieldmap represents a bitmap indicating which fields are actually stored and
// can be parsed. zero values for fields are not otherwise stored.
type fieldmap struct {
	max    int    // Required number of fields.
	buf    []byte // Bitmap, we write the next 0/1 at bit n.
	n      int    // Fields seen so far.
	offset int    // In final output, we write buf back after finish. Only relevant for packing.
	Errorf func(format string, args ...any)
}

// add bit to fieldmap indicating if the field is nonzero.
func (f *fieldmap) Field(nonzero bool) {
	o := f.n / 8
	if f.n >= f.max {
		f.Errorf("internal error: too many fields, max %d", f.max)
	}
	if nonzero {
		f.buf[o] |= 1 << (7 - f.n%8)
	}
	f.n++
}

// check if field i is nonzero.
func (f *fieldmap) Nonzero(i int) bool {
	v := f.buf[i/8]&(1<<(7-i%8)) != 0
	return v
}

type packer struct {
	b         *bytes.Buffer
	offset    int
	fieldmaps []*fieldmap // Pending fieldmaps, not excluding fieldmap below.
	fieldmap  *fieldmap   // Currently active.
	popped    []*fieldmap // Completed fieldmaps, to be written back during finish.
}

func (p *packer) Errorf(format string, args ...any) {
	panic(packErr{fmt.Errorf(format, args...)})
}

// Push a new fieldmap on the stack for n fields.
func (p *packer) PushFieldmap(n int) {
	p.fieldmaps = append(p.fieldmaps, p.fieldmap)
	buf := make([]byte, (n+7)/8)
	p.fieldmap = &fieldmap{max: n, buf: buf, offset: p.offset, Errorf: p.Errorf}
	p.Write(buf) // Updates offset. Write errors cause panic.
}

// Pop a fieldmap from the stack. It is remembered in popped for writing the
// bytes during finish.
func (p *packer) PopFieldmap() {
	if p.fieldmap.n != p.fieldmap.max {
		p.Errorf("internal error: fieldmap n %d != max %d", p.fieldmap.n, p.fieldmap.max)
	}
	p.popped = append(p.popped, p.fieldmap)
	p.fieldmap = p.fieldmaps[len(p.fieldmaps)-1]
	p.fieldmaps = p.fieldmaps[:len(p.fieldmaps)-1]
}

// Finish writes back finished (popped) fieldmaps to the correct offset,
// returning the final bytes representation of this record.
func (p *packer) Finish() []byte {
	if p.fieldmap != nil {
		p.Errorf("internal error: leftover fieldmap during finish")
	}
	buf := p.b.Bytes()
	for _, f := range p.popped {
		copy(buf[f.offset:], f.buf)
	}
	return buf
}

// Field adds field with nonzeroness to the current fieldmap.
func (p *packer) Field(nonzero bool) {
	p.fieldmap.Field(nonzero)
}

func (p *packer) Write(buf []byte) (int, error) {
	n, err := p.b.Write(buf)
	if err != nil {
		p.Errorf("write: %w", err)
	}
	if n > 0 {
		p.offset += n
	}
	return n, err
}

func (p *packer) AddBytes(buf []byte) {
	p.Uvarint(uint64(len(buf)))
	p.Write(buf) // Write errors cause panic.
}

func (p *packer) Uvarint(v uint64) {
	buf := make([]byte, binary.MaxVarintLen64)
	o := binary.PutUvarint(buf, v)
	p.Write(buf[:o]) // Write errors cause panic.
}

func (p *packer) Varint(v int64) {
	buf := make([]byte, binary.MaxVarintLen64)
	o := binary.PutVarint(buf, v)
	p.Write(buf[:o]) // Write errors cause panic.
}

type packErr struct {
	err error
}

// pack rv (reflect.Struct), excluding the primary key field.
func (st storeType) pack(rv reflect.Value) (rbuf []byte, rerr error) {
	p := &packer{b: &bytes.Buffer{}}
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		perr, ok := x.(packErr)
		if ok {
			rerr = perr.err
			return
		}
		panic(x)
	}()
	st.Current.pack(p, rv)
	return p.Finish(), nil
}

func (tv typeVersion) pack(p *packer, rv reflect.Value) {
	// When parsing, the same typeVersion (type schema) is used to
	// interpret the bytes correctly.
	p.Uvarint(uint64(tv.Version))

	p.PushFieldmap(len(tv.Fields) - 1)

	for _, f := range tv.Fields[1:] {
		nrv := rv.FieldByIndex(f.structField.Index)
		if f.Type.isZero(nrv) {
			if f.Nonzero {
				p.Errorf("%w: %q", ErrZero, f.Name)
			}
			p.Field(false)
			// Pretend to pack to get the nonzero checks.
			if nrv.IsValid() && (nrv.Kind() != reflect.Ptr || !nrv.IsNil()) {
				f.Type.pack(&packer{b: &bytes.Buffer{}}, nrv)
			}
		} else {
			p.Field(true)
			f.Type.pack(p, nrv)
		}
	}
	p.PopFieldmap()
}

// pack the nonzero value rv.
func (ft fieldType) pack(p *packer, rv reflect.Value) {
	if ft.Ptr {
		rv = rv.Elem()
	}
	switch ft.Kind {
	case kindBytes:
		p.AddBytes(rv.Bytes())
	case kindBinaryMarshal:
		v := rv
		buf, err := v.Interface().(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			p.Errorf("marshalbinary: %w", err)
		}
		p.AddBytes(buf)
	case kindBool:
		if ft.Ptr {
			var b byte = 0
			if rv.Bool() {
				b = 1
			}
			p.Write([]byte{b})
		}
		// If not pointer, no value is needed. If false, we would not get here, there would
		// be a 0 in the fieldmap.
	case kindInt:
		v := rv.Int()
		if v < math.MinInt32 || v > math.MaxInt32 {
			p.Errorf("%w: int %d does not fit in int32", ErrParam, v)
		}
		p.Varint(v)
	case kindInt8, kindInt16, kindInt32, kindInt64:
		p.Varint(rv.Int())
	case kindUint8, kindUint16, kindUint32, kindUint64:
		p.Uvarint(rv.Uint())
	case kindUint:
		v := rv.Uint()
		if v > math.MaxUint32 {
			p.Errorf("%w: uint %d does not fit in uint32", ErrParam, v)
		}
		p.Uvarint(v)
	case kindFloat32:
		p.Uvarint(uint64(math.Float32bits(rv.Interface().(float32))))
	case kindFloat64:
		p.Uvarint(uint64(math.Float64bits(rv.Interface().(float64))))
	case kindString:
		p.AddBytes([]byte(rv.String()))
	case kindTime:
		buf, err := rv.Interface().(time.Time).MarshalBinary()
		if err != nil {
			p.Errorf("%w: pack time: %s", ErrParam, err)
		}
		p.AddBytes(buf)
	case kindSlice:
		n := rv.Len()
		p.Uvarint(uint64(n))
		p.PushFieldmap(n)
		for i := 0; i < n; i++ {
			nrv := rv.Index(i)
			if ft.List.isZero(nrv) {
				p.Field(false)
				// Pretend to pack to get the nonzero checks of the element.
				if nrv.IsValid() && (nrv.Kind() != reflect.Ptr || !nrv.IsNil()) {
					ft.List.pack(&packer{b: &bytes.Buffer{}}, nrv)
				}
			} else {
				p.Field(true)
				ft.List.pack(p, nrv)
			}
		}
		p.PopFieldmap()
	case kindMap:
		// We write a fieldmap for zeroness of the values. The keys are unique, so there
		// can only be max 1 zero key. But there can be many zero values. struct{} is
		// common in Go, good to support that efficiently.
		n := rv.Len()
		p.Uvarint(uint64(n))
		p.PushFieldmap(n)
		iter := rv.MapRange()
		for iter.Next() {
			ft.MapKey.pack(p, iter.Key())
			v := iter.Value()
			if ft.MapValue.isZero(v) {
				p.Field(false)
				// Pretend to pack to get the nonzero checks of the key type.
				if v.IsValid() && (v.Kind() != reflect.Ptr || !v.IsNil()) {
					ft.MapValue.pack(&packer{b: &bytes.Buffer{}}, v)
				}
			} else {
				p.Field(true)
				ft.MapValue.pack(p, v)
			}
		}
		p.PopFieldmap()
	case kindStruct:
		p.PushFieldmap(len(ft.Fields))
		for _, f := range ft.Fields {
			nrv := rv.FieldByIndex(f.structField.Index)
			if f.Type.isZero(nrv) {
				if f.Nonzero {
					p.Errorf("%w: %q", ErrZero, f.Name)
				}
				p.Field(false)
				// Pretend to pack to get the nonzero checks.
				if nrv.IsValid() && (nrv.Kind() != reflect.Ptr || !nrv.IsNil()) {
					f.Type.pack(&packer{b: &bytes.Buffer{}}, nrv)
				}
			} else {
				p.Field(true)
				f.Type.pack(p, nrv)
			}
		}
		p.PopFieldmap()
	default:
		p.Errorf("internal error: unhandled field type") // should be prevented when registering type
	}
}
