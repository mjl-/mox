package moxio

import (
	"encoding/base64"
	"io"
)

// implement io.Closer
type closerFunc func() error

func (f closerFunc) Close() error {
	return f()
}

// Base64Writer turns a writer for data into one that writes base64 content on
// \r\n separated lines of max 78+2 characters length.
func Base64Writer(w io.Writer) io.WriteCloser {
	lw := &lineWrapper{w: w}
	bw := base64.NewEncoder(base64.StdEncoding, lw)
	return struct {
		io.Writer
		io.Closer
	}{
		Writer: bw,
		Closer: closerFunc(func() error {
			if err := bw.Close(); err != nil {
				return err
			}
			return lw.Close()
		}),
	}
}

type lineWrapper struct {
	w io.Writer
	n int // Written on current line.
}

func (lw *lineWrapper) Write(buf []byte) (int, error) {
	wrote := 0
	for len(buf) > 0 {
		n := 78 - lw.n
		if n > len(buf) {
			n = len(buf)
		}
		nn, err := lw.w.Write(buf[:n])
		if nn > 0 {
			wrote += nn
			buf = buf[nn:]
		}
		if err != nil {
			return wrote, err
		}
		lw.n += nn
		if lw.n == 78 {
			_, err := lw.w.Write([]byte("\r\n"))
			if err != nil {
				return wrote, err
			}
			lw.n = 0
		}
	}
	return wrote, nil
}

func (lw *lineWrapper) Close() error {
	if lw.n > 0 {
		lw.n = 0
		_, err := lw.w.Write([]byte("\r\n"))
		return err
	}
	return nil
}
