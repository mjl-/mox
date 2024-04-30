package smtp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

var ErrCRLF = errors.New("invalid bare carriage return or newline")

var errMissingCRLF = errors.New("missing crlf at end of message")

// DataWrite reads data (a mail message) from r, and writes it to smtp
// connection w with dot stuffing, as required by the SMTP data command.
//
// Messages with bare carriage returns or bare newlines result in an error.
func DataWrite(w io.Writer, r io.Reader) error {
	// ../rfc/5321:2003

	var prevlast, last byte = '\r', '\n' // Start on a new line, so we insert a dot if the first byte is a dot.
	// todo: at least for smtp submission we should probably set a max line length, eg 1000 octects including crlf. ../rfc/5321:3512
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
				firstcr := -1
				for n < len(p) {
					c := p[n]
					if c == '\n' {
						if firstcr < 0 {
							if n > 0 || last != '\r' {
								// Bare newline.
								return ErrCRLF
							}
						} else if firstcr != n-1 {
							// Bare carriage return.
							return ErrCRLF
						}
						n++
						break
					} else if c == '\r' && firstcr < 0 {
						firstcr = n
					}
					n++
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
//
// Bare carriage returns, and the sequences "[^\r]\n." and "\n.\n" result in an
// error.
type DataReader struct {
	// ../rfc/5321:2003
	r           *bufio.Reader
	plast, last byte
	buf         []byte // From previous read.
	err         error  // Read error, for after r.buf is exhausted.

	// When we see invalid combinations of CR and LF, we keep reading, and report an
	// error at the final "\r\n.\r\n". We cannot just stop reading and return an error,
	// the SMTP protocol would become out of sync.
	badcrlf bool
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
			// Reject bare \r.
			for i, c := range r.buf {
				if c == '\r' && (i == len(r.buf) || r.buf[i+1] != '\n') {
					r.badcrlf = true
				}
			}

			// We require crlf. A bare LF is not a line ending for the end of the SMTP
			// transaction. ../rfc/5321:2032
			// Bare newlines are accepted as message data, unless around a bare dot. The SMTP
			// server adds missing carriage returns. We don't reject bare newlines outright,
			// real-world messages like that occur.
			if r.plast == '\r' && r.last == '\n' {
				if bytes.Equal(r.buf, dotcrlf) {
					r.buf = nil
					r.err = io.EOF
					if r.badcrlf {
						r.err = ErrCRLF
					}
					break
				} else if r.buf[0] == '.' {
					// Reject "\r\n.\n".
					if len(r.buf) >= 2 && r.buf[1] == '\n' {
						r.badcrlf = true
					}
					r.buf = r.buf[1:]
				}
			} else if r.last == '\n' && (bytes.HasPrefix(r.buf, []byte(".\n")) || bytes.HasPrefix(r.buf, []byte(".\r\n"))) {
				// Reject "[^\r]\n.\n" and "[^\r]\n.\r\n"
				r.badcrlf = true
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
