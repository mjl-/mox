package moxio

import (
	"io"
)

// AtReader is turns an io.ReaderAt into a io.Reader by keeping track of the
// offset.
type AtReader struct {
	R      io.ReaderAt
	Offset int64
}

func (r *AtReader) Read(buf []byte) (int, error) {
	n, err := r.R.ReadAt(buf, r.Offset)
	if n > 0 {
		r.Offset += int64(n)
	}
	return n, err
}
