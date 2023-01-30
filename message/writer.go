package message

import (
	"io"
)

// Writer is a write-through helper, collecting properties about the written
// message.
type Writer struct {
	Writer      io.Writer
	HaveHeaders bool
	Has8bit     bool // Whether a byte with the high/8bit has been read. So whether this is 8BITMIME instead of 7BIT.
	Size        int64
	tail        [3]byte // For detecting crlfcrlf.
	// todo: should be parsing headers here, as we go
}

// Write implements io.Writer.
func (w *Writer) Write(buf []byte) (int, error) {
	if !w.HaveHeaders && len(buf) > 0 {
		get := func(i int) byte {
			if i < 0 {
				return w.tail[3+i]
			}
			return buf[i]
		}

		for i, b := range buf {
			if b == '\n' && get(i-3) == '\r' && get(i-2) == '\n' && get(i-1) == '\r' {
				w.HaveHeaders = true
				break
			}
		}

		n := len(buf)
		if n > 3 {
			n = 3
		}
		copy(w.tail[:], w.tail[n:])
		copy(w.tail[3-n:], buf[len(buf)-n:])
	}
	if !w.Has8bit {
		for _, b := range buf {
			if b&0x80 != 0 {
				w.Has8bit = true
				break
			}
		}
	}
	n, err := w.Writer.Write(buf)
	if n > 0 {
		w.Size += int64(n)
	}
	return n, err
}
