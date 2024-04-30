package moxio

import (
	"io"
	"log/slog"

	"github.com/mjl-/mox/mlog"
)

type TraceWriter struct {
	log    mlog.Log
	prefix string
	w      io.Writer
	level  slog.Level
}

// NewTraceWriter wraps "w" into a writer that logs all writes to "log" with
// log level trace, prefixed with "prefix".
func NewTraceWriter(log mlog.Log, prefix string, w io.Writer) *TraceWriter {
	return &TraceWriter{log, prefix, w, mlog.LevelTrace}
}

// Write logs a trace line for writing buf to the client, then writes to the
// client.
func (w *TraceWriter) Write(buf []byte) (int, error) {
	w.log.Trace(w.level, w.prefix, buf)
	return w.w.Write(buf)
}

func (w *TraceWriter) SetTrace(level slog.Level) {
	w.level = level
}

type TraceReader struct {
	log    mlog.Log
	prefix string
	r      io.Reader
	level  slog.Level
}

// NewTraceReader wraps reader "r" into a reader that logs all reads to "log"
// with log level trace, prefixed with "prefix".
func NewTraceReader(log mlog.Log, prefix string, r io.Reader) *TraceReader {
	return &TraceReader{log, prefix, r, mlog.LevelTrace}
}

// Read does a single Read on its underlying reader, logs data of successful
// reads, and returns the data read.
func (r *TraceReader) Read(buf []byte) (int, error) {
	n, err := r.r.Read(buf)
	if n > 0 {
		r.log.Trace(r.level, r.prefix, buf[:n])
	}
	return n, err
}

func (r *TraceReader) SetTrace(level slog.Level) {
	r.level = level
}
