package message

import (
	"io"
)

// Writer is a write-through helper, collecting properties about the written
// message and replacing bare \n line endings with \r\n.
type Writer struct {
	writer io.Writer

	HaveBody bool  // Body is optional in a message. ../rfc/5322:343
	Has8bit  bool  // Whether a byte with the high/8bit has been read. So whether this needs SMTP 8BITMIME instead of 7BIT.
	Size     int64 // Number of bytes written, may be different from bytes read due to LF to CRLF conversion.

	tail [3]byte // For detecting header/body-separating crlf.
	// todo: should be parsing headers here, as we go
}

func NewWriter(w io.Writer) *Writer {
	// Pretend we already saw \r\n, for handling empty header.
	return &Writer{writer: w, tail: [3]byte{0, '\r', '\n'}}
}

// Write implements io.Writer, and writes buf as message to the Writer's underlying
// io.Writer. It converts bare new lines (LF) to carriage returns with new lines
// (CRLF).
func (w *Writer) Write(buf []byte) (int, error) {
	origtail := w.tail

	if !w.HaveBody && len(buf) > 0 {
		get := func(i int) byte {
			if i < 0 {
				return w.tail[3+i]
			}
			return buf[i]
		}

		for i, b := range buf {
			if b == '\n' && (get(i-1) == '\n' || get(i-1) == '\r' && get(i-2) == '\n') {
				w.HaveBody = true
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

	wrote := 0
	o := 0
Top:
	for o < len(buf) {
		for i := o; i < len(buf); i++ {
			if buf[i] == '\n' && (i > 0 && buf[i-1] != '\r' || i == 0 && origtail[2] != '\r') {
				// Write buffer leading up to missing \r.
				if i > o {
					n, err := w.writer.Write(buf[o:i])
					if n > 0 {
						wrote += n
						w.Size += int64(n)
					}
					if err != nil {
						return wrote, err
					}
				}
				n, err := w.writer.Write([]byte{'\r', '\n'})
				if n == 2 {
					wrote += 1 // For only the newline.
					w.Size += int64(2)
				}
				if err != nil {
					return wrote, err
				}
				o = i + 1
				continue Top
			}
		}
		n, err := w.writer.Write(buf[o:])
		if n > 0 {
			wrote += n
			w.Size += int64(n)
		}
		if err != nil {
			return wrote, err
		}
		break
	}
	return wrote, nil
}
