package sconf

import (
	"bufio"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/mjl-/xfmt"
)

var errNoElem = errors.New("no elements")

type writeError struct{ error }

type writer struct {
	out      *bufio.Writer
	wrote    int
	prefix   string
	keepZero bool // If set, we also write zero values.
	docs     bool // If set, we write comments.
}

func (w *writer) error(err error) {
	panic(writeError{err})
}

func (w *writer) check(err error) {
	if err != nil {
		w.error(err)
	}
}

func (w *writer) write(s string) {
	n, err := w.out.WriteString(s)
	w.check(err)
	w.wrote += n
}

func (w *writer) flush() {
	err := w.out.Flush()
	w.check(err)
}

func (w *writer) indent() {
	w.prefix += "\t"
}

func (w *writer) unindent() {
	w.prefix = w.prefix[:len(w.prefix)-1]
}

func isOptional(sconfTag string) bool {
	return hasTagWord(sconfTag, "optional")
}

func isIgnore(sconfTag string) bool {
	return hasTagWord(sconfTag, "-") || hasTagWord(sconfTag, "ignore")
}

func hasTagWord(sconfTag, word string) bool {
	l := strings.Split(sconfTag, ",")
	for _, s := range l {
		if s == word {
			return true
		}
	}
	return false
}

func (w *writer) describeMap(v reflect.Value) {
	t := v.Type()
	if t.Key().Kind() != reflect.String {
		w.error(fmt.Errorf("map key must be string"))
	}
	keys := v.MapKeys()
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].String() < keys[j].String()
	})
	have := false
	for _, k := range keys {
		have = true
		w.write(w.prefix)
		w.write(k.String() + ":")
		mv := v.MapIndex(k)
		if !w.keepZero && mv.Kind() == reflect.Struct && isEmptyStruct(mv) {
			w.write(" nil\n")
			continue
		}
		w.describeValue(mv)
	}
	if have {
		return
	}
	w.write(w.prefix)
	w.write("x:")
	w.describeValue(reflect.Zero(t.Elem()))
}

// whether v is a zero value of a struct type with all fields optional or
// ignored, causing it to write nothing when using Write.
func isEmptyStruct(v reflect.Value) bool {
	if v.Kind() != reflect.Struct {
		panic("not a struct")
	}
	t := v.Type()
	n := t.NumField()
	for i := 0; i < n; i++ {
		ft := t.Field(i)
		tag := ft.Tag.Get("sconf")
		if !ft.IsExported() || isIgnore(tag) {
			continue
		}
		if !isOptional(tag) {
			return false
		}
		if !isZeroIgnored(v.Field(i)) {
			return false
		}
	}
	return true
}

// whether v is zero, taking ignored values into account.
func isZeroIgnored(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Slice, reflect.Map:
		return v.Len() == 0
	case reflect.Ptr:
		return v.IsZero() || isZeroIgnored(v.Elem())
	case reflect.Struct:
		t := v.Type()
		n := t.NumField()
		for i := 0; i < n; i++ {
			ft := t.Field(i)
			tag := ft.Tag.Get("sconf")
			if !ft.IsExported() || isIgnore(tag) {
				continue
			}
			if !isZeroIgnored(v.Field(i)) {
				return false
			}
		}
		return true
	default:
		return v.IsZero()
	}
}

func (w *writer) describeStruct(v reflect.Value) {
	t := v.Type()
	n := t.NumField()
	for i := 0; i < n; i++ {
		f := t.Field(i)
		fv := v.Field(i)
		if !f.IsExported() || isIgnore(f.Tag.Get("sconf")) {
			continue
		}
		if !w.keepZero && isOptional(f.Tag.Get("sconf")) && isZeroIgnored(fv) {
			continue
		}
		if w.docs {
			doc := f.Tag.Get("sconf-doc")
			optional := isOptional(f.Tag.Get("sconf"))
			if doc != "" || optional {
				s := "\n"
				if w.wrote == 0 {
					// No empty line at start of file.
					s = ""
				}
				// Treat two blank lines as section separator: the comments are not joined with
				// lines with just "#", but instead with empty lines. To allow a hack where the
				// first field of a config struct gives some context about the file.
				sections := strings.Split(doc, "\n\n\n")
				for si, section := range sections {
					if si > 0 {
						s += "\n\n\n"
					}
					for i, line := range strings.Split(section, "\n") {
						if i > 0 {
							s += "\n"
						}
						s += w.prefix + "#"
						if line != "" {
							s += " " + line
						}
					}
				}
				if optional {
					opt := "(optional)"
					if !strings.HasSuffix(doc, " ") {
						s += " "
					}
					s += opt
				}
				s += "\n"
				b := &strings.Builder{}
				err := xfmt.Format(b, strings.NewReader(s), xfmt.Config{MaxWidth: 80})
				w.check(err)
				w.write(b.String())
			}
		}
		w.write(w.prefix)
		w.write(f.Name + ":")
		w.describeValue(fv)
	}
}

func (w *writer) describeValue(v reflect.Value) {
	t := v.Type()
	i := v.Interface()

	if t == durationType {
		w.write(fmt.Sprintf(" %s\n", i))
		return
	}

	switch t.Kind() {
	default:
		w.error(fmt.Errorf("unsupported value %v", t.Kind()))
		return

	case reflect.Bool:
		w.write(fmt.Sprintf(" %v\n", i))

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		w.write(fmt.Sprintf(" %d\n", i))

	case reflect.Float32, reflect.Float64:
		w.write(fmt.Sprintf(" %f\n", i))

	case reflect.String:
		if strings.Contains(v.String(), "\n") {
			w.error(fmt.Errorf("unsupported multiline string"))
		}
		w.write(fmt.Sprintf(" %s\n", i))

	case reflect.Slice:
		w.write("\n")
		w.indent()
		w.describeSlice(v)
		w.unindent()

	case reflect.Ptr:
		var pv reflect.Value
		if v.IsNil() {
			pv = reflect.New(t.Elem()).Elem()
		} else {
			pv = v.Elem()
		}
		w.describeValue(pv)

	case reflect.Struct:
		w.write("\n")
		w.indent()
		w.describeStruct(v)
		w.unindent()

	case reflect.Map:
		w.write("\n")
		w.indent()
		w.describeMap(v)
		w.unindent()
	}
}

func (w *writer) describeSlice(v reflect.Value) {
	describeElem := func(vv reflect.Value) {
		w.write(w.prefix)
		w.write("-")
		w.describeValue(vv)
	}

	n := v.Len()
	if n == 0 {
		if w.keepZero {
			describeElem(reflect.New(v.Type().Elem()))
		} else {
			w.error(errNoElem)
		}
	}

	for i := 0; i < n; i++ {
		describeElem(v.Index(i))
	}
}
