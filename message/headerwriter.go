package message

import (
	"bytes"
	"fmt"
	"strings"
)

// HeaderWriter helps create headers, folding to the next line when it would
// become too large. Useful for creating Received and DKIM-Signature headers.
type HeaderWriter struct {
	b        *strings.Builder
	lineLen  int
	nonfirst bool
}

// Addf formats the string and calls Add.
func (w *HeaderWriter) Addf(separator string, format string, args ...any) {
	w.Add(separator, fmt.Sprintf(format, args...))
}

// Add adds texts, each separated by separator. Individual elements in text are
// not wrapped.
func (w *HeaderWriter) Add(separator string, texts ...string) {
	if w.b == nil {
		w.b = &strings.Builder{}
	}
	for _, text := range texts {
		n := len(text)
		if w.nonfirst && w.lineLen > 1 && w.lineLen+len(separator)+n > 78 {
			w.b.WriteString("\r\n\t")
			w.lineLen = 1
		} else if w.nonfirst && separator != "" {
			w.b.WriteString(separator)
			w.lineLen += len(separator)
		}
		w.b.WriteString(text)
		w.lineLen += len(text)
		w.nonfirst = true
	}
}

// AddWrap adds data. If text is set, wrapping happens at space/tab, otherwise
// anywhere in the buffer (e.g. for base64 data).
func (w *HeaderWriter) AddWrap(buf []byte, text bool) {
	for len(buf) > 0 {
		line := buf
		n := 78 - w.lineLen
		if len(buf) > n {
			if text {
				if i := bytes.LastIndexAny(buf[:n], " \t"); i > 0 {
					n = i
				} else if i = bytes.IndexAny(buf, " \t"); i > 0 {
					n = i
				}
			}
			line, buf = buf[:n], buf[n:]
		} else {
			buf = nil
			n = len(buf)
		}
		w.b.Write(line)
		w.lineLen += n
		if len(buf) > 0 {
			w.b.WriteString("\r\n\t")
			w.lineLen = 1
		}
	}
}

// Newline starts a new line.
func (w *HeaderWriter) Newline() {
	w.b.WriteString("\r\n\t")
	w.lineLen = 1
	w.nonfirst = true
}

// String returns the header in string form, ending with \r\n.
func (w *HeaderWriter) String() string {
	return w.b.String() + "\r\n"
}
