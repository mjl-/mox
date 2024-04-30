package moxio

// similar between ../moxio/limitreader.go and ../webapi/limitreader.go

import (
	"errors"
	"io"
)

var ErrLimit = errors.New("input exceeds maximum size") // Returned by LimitReader.

// LimitReader reads up to Limit bytes, returning an error if more bytes are
// read. LimitReader can be used to enforce a maximum input length.
type LimitReader struct {
	R     io.Reader
	Limit int64
}

// Read reads bytes from the underlying reader.
func (r *LimitReader) Read(buf []byte) (int, error) {
	n, err := r.R.Read(buf)
	if n > 0 {
		r.Limit -= int64(n)
		if r.Limit < 0 {
			return 0, ErrLimit
		}
	}
	return n, err
}
