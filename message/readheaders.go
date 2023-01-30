package message

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

var crlf2x = []byte("\r\n\r\n")

var ErrHeaderSeparator = errors.New("no header separator found")

// ReadHeaders returns the headers of a message, ending with a single crlf.
// Returns ErrHeaderSeparator if no header separator is found.
func ReadHeaders(msg *bufio.Reader) ([]byte, error) {
	buf := []byte{}
	for {
		line, err := msg.ReadBytes('\n')
		if err != io.EOF && err != nil {
			return nil, err
		}
		buf = append(buf, line...)
		if bytes.HasSuffix(buf, crlf2x) {
			return buf[:len(buf)-2], nil
		}
		if err == io.EOF {
			return nil, ErrHeaderSeparator
		}
	}
}
