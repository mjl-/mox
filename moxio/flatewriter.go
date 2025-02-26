package moxio

import (
	"github.com/mjl-/flate"
)

// FlateWriter wraps a flate.Writer and ensures no Write/Flush/Close calls are made
// again on the underlying flate writer when a panic came out of the flate writer
// (e.g. raised by the destination writer of the flate writer). After a panic
// "through" a flate.Writer, its state is inconsistent and further calls could
// panic with out of bounds slice accesses.
type FlateWriter struct {
	w     *flate.Writer
	panic any
}

func NewFlateWriter(w *flate.Writer) *FlateWriter {
	return &FlateWriter{w, nil}
}

func (w *FlateWriter) checkBroken() func() {
	if w.panic != nil {
		panic(w.panic)
	}
	return func() {
		x := recover()
		if x == nil {
			return
		}
		w.panic = x
		panic(x)
	}
}

func (w *FlateWriter) Write(data []byte) (int, error) {
	defer w.checkBroken()()
	return w.w.Write(data)
}

func (w *FlateWriter) Flush() error {
	defer w.checkBroken()()
	return w.w.Flush()
}

func (w *FlateWriter) Close() error {
	defer w.checkBroken()()
	return w.w.Close()
}
