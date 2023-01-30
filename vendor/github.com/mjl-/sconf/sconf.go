package sconf

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"reflect"
)

// ParseFile reads an sconf file from path into dst.
func ParseFile(path string, dst interface{}) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	return parse(path, src, dst)
}

// Parse reads an sconf file from a reader into dst.
func Parse(src io.Reader, dst interface{}) error {
	return parse("", src, dst)
}

// Describe writes an example sconf file describing v to w. The file includes all
// fields, values and documentation on the fields as configured with the "sconf"
// and "sconf-doc" struct tags. Describe does not detect recursive values and will
// attempt to write them.
func Describe(w io.Writer, v interface{}) error {
	return describe(w, v, true, true)
}

// Write writes a valid sconf file describing v to w, without comments, without
// zero values of optional fields. Write does not detect recursive values and
// will attempt to write them.
func Write(w io.Writer, v interface{}) error {
	return describe(w, v, false, false)
}

// WriteDocs is like Write, but does write comments.
func WriteDocs(w io.Writer, v interface{}) error {
	return describe(w, v, false, true)
}

func describe(w io.Writer, v interface{}, keepZero bool, docs bool) (err error) {
	value := reflect.ValueOf(v)
	t := value.Type()
	if t.Kind() == reflect.Ptr {
		value = value.Elem()
		t = value.Type()
	}
	if t.Kind() != reflect.Struct {
		return fmt.Errorf("top level object must be a struct, is a %T", v)
	}
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if e, ok := x.(writeError); ok {
			err = error(e)
		} else {
			panic(x)
		}
	}()
	wr := &writer{out: bufio.NewWriter(w), keepZero: keepZero, docs: docs}
	wr.describeStruct(value)
	wr.flush()
	return nil
}
