package moxio

import (
	"io"

	"github.com/mjl-/mox/mlog"
)

type writer struct {
	log    *mlog.Log
	prefix string
	w      io.Writer
}

// NewTraceWriter wraps "w" into a writer that logs all writes to "log" with
// log level trace, prefixed with "prefix".
func NewTraceWriter(log *mlog.Log, prefix string, w io.Writer) io.Writer {
	return writer{log, prefix, w}
}

// Write logs a trace line for writing buf to the client, then writes to the
// client.
func (w writer) Write(buf []byte) (int, error) {
	w.log.Trace(w.prefix + string(buf))
	return w.w.Write(buf)
}

type reader struct {
	log    *mlog.Log
	prefix string
	r      io.Reader
}

// NewTraceReader wraps reader "r" into a reader that logs all reads to "log"
// with log level trace, prefixed with "prefix".
func NewTraceReader(log *mlog.Log, prefix string, r io.Reader) io.Reader {
	return reader{log, prefix, r}
}

// Read does a single Read on its underlying reader, logs data of successful
// reads, and returns the data read.
func (r reader) Read(buf []byte) (int, error) {
	n, err := r.r.Read(buf)
	if n > 0 {
		r.log.Trace(r.prefix + string(buf[:n]))
	}
	return n, err
}
