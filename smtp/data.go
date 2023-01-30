package smtp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

var errMissingCRLF = errors.New("missing crlf at end of message")

// DataWrite reads data (a mail message) from r, and writes it to smtp
// connection w with dot stuffing, as required by the SMTP data command.
func DataWrite(w io.Writer, r io.Reader) error {
	// ../rfc/5321:2003

	var prevlast, last byte = '\r', '\n' // Start on a new line, so we insert a dot if the first byte is a dot.
	// todo: at least for smtp submission we should probably set a max line length, eg 1000 octects including crlf. ../rfc/5321:3512
	// todo: at least for smtp submission or a pedantic mode, we should refuse messages with bare \r or bare \n.
	buf := make([]byte, 8*1024)
	for {
		nr, err := r.Read(buf)
		if nr > 0 {
			// Process buf by writing a line at a time, and checking if the next character
			// after the line starts with a dot. Insert an extra dot if so.
			p := buf[:nr]
			for len(p) > 0 {
				if p[0] == '.' && prevlast == '\r' && last == '\n' {
					if _, err := w.Write([]byte{'.'}); err != nil {
						return err
					}
				}
				// Look for the next newline, or end of buffer.
				n := 0
				for n < len(p) {
					c := p[n]
					n++
					if c == '\n' {
						break
					}
				}
				if _, err := w.Write(p[:n]); err != nil {
					return err
				}
				// Keep track of the last two bytes we've written.
				if n == 1 {
					prevlast, last = last, p[0]
				} else {
					prevlast, last = p[n-2], p[n-1]
				}
				p = p[n:]
			}
		}
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}
	if prevlast != '\r' || last != '\n' {
		return errMissingCRLF
	}
	if _, err := w.Write(dotcrlf); err != nil {
		return err
	}
	return nil
}

var dotcrlf = []byte(".\r\n")

// DataReader is an io.Reader that reads data from an SMTP DATA command, doing dot
// unstuffing and returning io.EOF when a bare dot is received. Use NewDataReader.
type DataReader struct {
	// ../rfc/5321:2003
	r           *bufio.Reader
	plast, last byte
	buf         []byte // From previous read.
	err         error  // Read error, for after r.buf is exhausted.
}

// NewDataReader returns an initialized DataReader.
func NewDataReader(r *bufio.Reader) *DataReader {
	return &DataReader{
		r: r,
		// Set up initial state to accept a message that is only "." and CRLF.
		plast: '\r',
		last:  '\n',
	}
}

// Read implements io.Reader.
func (r *DataReader) Read(p []byte) (int, error) {
	wrote := 0
	for len(p) > 0 {
		// Read until newline as long as it fits in the buffer.
		if len(r.buf) == 0 {
			if r.err != nil {
				break
			}
			// todo: set a max length, eg 1000 octets including crlf excluding potential leading dot. ../rfc/5321:3512
			r.buf, r.err = r.r.ReadSlice('\n')
			if r.err == bufio.ErrBufferFull {
				r.err = nil
			} else if r.err == io.EOF {
				// Mark EOF as bad for now. If we see the ending dotcrlf below, err becomes regular
				// io.EOF again.
				r.err = io.ErrUnexpectedEOF
			}
		}
		if len(r.buf) > 0 {
			// We require crlf. A bare LF is not a line ending. ../rfc/5321:2032
			// todo: we could return an error for a bare \n.
			if r.plast == '\r' && r.last == '\n' {
				if bytes.Equal(r.buf, dotcrlf) {
					r.buf = nil
					r.err = io.EOF
					break
				} else if r.buf[0] == '.' {
					r.buf = r.buf[1:]
				}
			}
			n := len(r.buf)
			if n > len(p) {
				n = len(p)
			}
			copy(p, r.buf[:n])
			if n == 1 {
				r.plast, r.last = r.last, r.buf[0]
			} else if n > 1 {
				r.plast, r.last = r.buf[n-2], r.buf[n-1]
			}
			p = p[n:]
			r.buf = r.buf[n:]
			wrote += n
		}
	}
	return wrote, r.err
}
