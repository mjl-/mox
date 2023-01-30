package smtpserver

import (
	"errors"
	"io"
)

var errMessageTooLarge = errors.New("maximum message size exceeded")

type limitWriter struct {
	maxSize int64
	w       io.Writer
	written int64
}

func (w *limitWriter) Write(buf []byte) (int, error) {
	if w.written+int64(len(buf)) > w.maxSize {
		return 0, errMessageTooLarge
	}
	n, err := w.w.Write(buf)
	if n > 0 {
		w.written += int64(n)
	}
	return n, err
}
