package moxio

import (
	"io"
	"strings"

	"golang.org/x/text/encoding/ianaindex"
)

// DecodeReader returns a reader that reads from r, decoding as charset. If
// charset is empty, us-ascii, utf-8 or unknown, the original reader is
// returned and no decoding takes place.
func DecodeReader(charset string, r io.Reader) io.Reader {
	switch strings.ToLower(charset) {
	case "", "us-ascii", "utf-8":
		return r
	}
	enc, _ := ianaindex.MIME.Encoding(charset)
	if enc == nil {
		enc, _ = ianaindex.IANA.Encoding(charset)
	}
	// todo: ianaindex doesn't know all encodings, e.g. gb2312. should we transform them, with which code?
	if enc == nil {
		return r
	}
	return enc.NewDecoder().Reader(r)
}
