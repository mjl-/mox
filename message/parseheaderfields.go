package message

import (
	"bytes"
	"fmt"
	"net/mail"
	"net/textproto"
)

// ParseHeaderFields parses only the header fields in "fields" from the complete
// header buffer "header", while using "scratch" as temporary space, prevent lots
// of unneeded allocations when only a few headers are needed.
func ParseHeaderFields(header []byte, scratch []byte, fields [][]byte) (textproto.MIMEHeader, error) {
	// todo: should not use mail.ReadMessage, it allocates a bufio.Reader. should implement header parsing ourselves.

	// Gather the raw lines for the fields, with continuations, without the other
	// headers. Put them in a byte slice and only parse those headers. For now, use
	// mail.ReadMessage without letting it do allocations for all headers.
	scratch = scratch[:0]
	var keepcontinuation bool
	for len(header) > 0 {
		if header[0] == ' ' || header[0] == '\t' {
			// Continuation.
			i := bytes.IndexByte(header, '\n')
			if i < 0 {
				i = len(header)
			} else {
				i++
			}
			if keepcontinuation {
				scratch = append(scratch, header[:i]...)
			}
			header = header[i:]
			continue
		}
		i := bytes.IndexByte(header, ':')
		if i < 0 || i > 0 && (header[i-1] == ' ' || header[i-1] == '\t') {
			i = bytes.IndexByte(header, '\n')
			if i < 0 {
				break
			}
			header = header[i+1:]
			keepcontinuation = false
			continue
		}
		k := header[:i]
		keepcontinuation = false
		for _, f := range fields {
			if bytes.EqualFold(k, f) {
				keepcontinuation = true
				break
			}
		}
		i = bytes.IndexByte(header, '\n')
		if i < 0 {
			i = len(header)
		} else {
			i++
		}
		if keepcontinuation {
			scratch = append(scratch, header[:i]...)
		}
		header = header[i:]
	}

	if len(scratch) == 0 {
		return nil, nil
	}

	scratch = append(scratch, "\r\n"...)

	msg, err := mail.ReadMessage(bytes.NewReader(scratch))
	if err != nil {
		return nil, fmt.Errorf("reading message header")
	}
	return textproto.MIMEHeader(msg.Header), nil
}
