package moxio

import (
	"io"
)

// LimitAtReader is a reader at that returns ErrLimit if reads would extend
// beyond Limit.
type LimitAtReader struct {
	R     io.ReaderAt
	Limit int64
}

// ReadAt passes the read on to R, but returns an error if the read data would extend beyond Limit.
func (r *LimitAtReader) ReadAt(buf []byte, offset int64) (int, error) {
	if offset+int64(len(buf)) > r.Limit {
		return 0, ErrLimit
	}
	return r.R.ReadAt(buf, offset)
}
