package sconf

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type parser struct {
	prefix     string        // indented string
	input      *bufio.Reader // for reading lines at a time
	line       string        // last read line
	linenumber int
}

type parseError struct {
	err error
}

func parse(path string, src io.Reader, dst interface{}) (err error) {
	p := &parser{
		input: bufio.NewReader(src),
	}
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		perr, ok := x.(parseError)
		if ok {
			err = fmt.Errorf("%s:%d: %v", path, p.linenumber, perr.err)
			return
		}
		panic(x)
	}()
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Ptr {
		p.stop("destination not a pointer")
	}
	p.parseStruct0(v.Elem())
	return
}

func (p *parser) stop(err string) {
	panic(parseError{errors.New(err)})
}

func (p *parser) check(err error, action string) {
	if err != nil {
		p.stop(fmt.Sprintf("%s: %s", action, err))
	}
}

func (p *parser) string() string {
	return p.line
}

func (p *parser) leave(s string) {
	p.line = s
}

func (p *parser) consume() string {
	s := p.line
	p.line = ""
	return s
}

// Next returns whether the next line is properly indented, reading data as necessary.
func (p *parser) next() bool {
	for p.line == "" {
		s, err := p.input.ReadString('\n')
		if s == "" {
			if err == io.EOF {
				return false
			}
			p.stop(err.Error())
		}
		p.linenumber++
		if strings.HasPrefix(strings.TrimSpace(s), "#") {
			continue
		}
		p.line = strings.TrimSuffix(s, "\n")
	}

	// Less indenting than expected. Let caller stop, returning to its caller for lower-level indent.
	r := strings.HasPrefix(p.line, p.prefix)
	return r
}

func (p *parser) indent() {
	p.prefix += "\t"
	if !p.next() {
		p.stop("expected indent")
	}
}

func (p *parser) unindent() {
	p.prefix = p.prefix[1:]
}

var durationType = reflect.TypeOf(time.Duration(0))

func (p *parser) parseValue(v reflect.Value) reflect.Value {
	t := v.Type()

	if t == durationType {
		s := p.consume()
		d, err := time.ParseDuration(s)
		p.check(err, "parsing duration")
		v.Set(reflect.ValueOf(d))
		return v
	}

	switch t.Kind() {
	default:
		p.stop(fmt.Sprintf("cannot parse type %v", t.Kind()))

	case reflect.Bool:
		s := p.consume()
		switch s {
		case "false":
			v.SetBool(false)
		case "true":
			v.SetBool(true)
		default:
			p.stop(fmt.Sprintf("bad boolean value %q", s))
		}

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		s := p.consume()
		x, err := strconv.ParseInt(s, 10, 64)
		p.check(err, "parsing integer")
		v.SetInt(x)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		s := p.consume()
		x, err := strconv.ParseUint(s, 10, 64)
		p.check(err, "parsing integer")
		v.SetUint(x)

	case reflect.Float32, reflect.Float64:
		s := p.consume()
		x, err := strconv.ParseFloat(s, 64)
		p.check(err, "parsing float")
		v.SetFloat(x)

	case reflect.String:
		v.SetString(p.consume())

	case reflect.Slice:
		v = p.parseSlice(v)

	case reflect.Ptr:
		vv := reflect.New(t.Elem())
		p.parseValue(vv.Elem())
		v.Set(vv)

	case reflect.Struct:
		p.parseStruct(v)

	case reflect.Map:
		v = reflect.MakeMap(t)
		p.parseMap(v)
	}
	return v
}

func (p *parser) parseSlice(v reflect.Value) reflect.Value {
	if v.Type().Elem().Kind() == reflect.Uint8 {
		s := p.consume()
		buf, err := base64.StdEncoding.DecodeString(s)
		p.check(err, "parsing base64")
		v.SetBytes(buf)
		return v
	}

	p.indent()
	defer p.unindent()
	return p.parseSlice0(v)
}

func (p *parser) parseSlice0(v reflect.Value) reflect.Value {
	for p.next() {
		s := p.string()
		prefix := p.prefix + "-"
		if !strings.HasPrefix(s, prefix) {
			p.stop(fmt.Sprintf("expected item, prefix %q, saw %q", prefix, s))
		}
		s = s[len(prefix):]
		if s != "" {
			if !strings.HasPrefix(s, " ") {
				p.stop("missing space after -")
			}
			s = s[1:]
		}
		p.leave(s)
		vv := reflect.New(v.Type().Elem()).Elem()
		vv = p.parseValue(vv)
		v = reflect.Append(v, vv)
	}
	return v
}

func (p *parser) parseStruct(v reflect.Value) {
	p.indent()
	defer p.unindent()
	p.parseStruct0(v)
}

func (p *parser) parseStruct0(v reflect.Value) {
	seen := map[string]struct{}{}
	var zeroValue reflect.Value
	t := v.Type()
	for p.next() {
		s := p.string()
		s = s[len(p.prefix):]
		l := strings.SplitN(s, ":", 2)
		if len(l) != 2 {
			p.stop("missing key: value")
		}
		k := l[0]
		if k == "" {
			p.stop("empty key")
		}
		if _, ok := seen[k]; ok {
			p.stop("duplicate key")
		}
		seen[k] = struct{}{}
		s = l[1]
		if s != "" && !strings.HasPrefix(s, " ") {
			p.stop("no space after colon")
		}
		if s != "" {
			s = s[1:]
		}
		p.leave(s)

		vv := v.FieldByName(k)
		if vv == zeroValue {
			p.stop(fmt.Sprintf("unknown key %q", k))
		}
		if ft, _ := t.FieldByName(k); isIgnore(ft.Tag.Get("sconf")) {
			p.stop(fmt.Sprintf("unknown key %q (has ignore tag)", k))
		}
		vv.Set(p.parseValue(vv))
	}

	n := t.NumField()
	for i := 0; i < n; i++ {
		f := t.Field(i)
		if isIgnore(f.Tag.Get("sconf")) || isOptional(f.Tag.Get("sconf")) {
			continue
		}
		if _, ok := seen[f.Name]; !ok {
			p.stop(fmt.Sprintf("missing required key %q", f.Name))
		}
	}
}

func (p *parser) parseMap(v reflect.Value) {
	p.indent()
	defer p.unindent()
	p.parseMap0(v)
}

func (p *parser) parseMap0(v reflect.Value) {
	seen := map[string]struct{}{}
	t := v.Type()
	for p.next() {
		s := p.string()
		s = s[len(p.prefix):]
		l := strings.SplitN(s, ":", 2)
		if len(l) != 2 {
			p.stop("missing key: value")
		}
		k := l[0]
		if k == "" {
			p.stop("empty key")
		}
		if _, ok := seen[k]; ok {
			p.stop("duplicate key")
		}
		seen[k] = struct{}{}
		s = l[1]
		if s != "" && !strings.HasPrefix(s, " ") {
			p.stop("no space after colon")
		}
		if s != "" {
			s = s[1:]
		}

		vv := reflect.New(t.Elem()).Elem()
		if s == "nil" {
			// Special value "nil" means the zero value, no further parsing of a value.
			p.leave("")
		} else {
			p.leave(s)
			vv = p.parseValue(vv)
		}
		v.SetMapIndex(reflect.ValueOf(k), vv)
	}
}
