package smtp

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDataWrite(t *testing.T) {
	checkBad := func(s string, expErr error) {
		t.Helper()
		if err := DataWrite(io.Discard, strings.NewReader(s)); err == nil || !errors.Is(err, expErr) {
			t.Fatalf("got err %v, expected %v", err, expErr)
		}
	}

	checkBad("bad", errMissingCRLF)
	checkBad(".", errMissingCRLF)
	checkBad("bare \r is bad\r\n", ErrCRLF)
	checkBad("bare \n is bad\r\n", ErrCRLF)
	checkBad("\n.\nis bad\r\n", ErrCRLF)
	checkBad("\r.\ris bad\r\n", ErrCRLF)
	checkBad("\r\n.\ris bad\r\n", ErrCRLF)
	checkBad("\r\n.\nis bad\r\n", ErrCRLF)
	checkBad("\n.\ris bad\r\n", ErrCRLF)
	checkBad("\n.\r\nis bad\r\n", ErrCRLF)

	check := func(msg, want string) {
		t.Helper()
		w := &strings.Builder{}
		if err := DataWrite(w, strings.NewReader(msg)); err != nil {
			t.Fatalf("writing smtp data: %s", err)
		}
		got := w.String()
		if got != want {
			t.Fatalf("got %q, expected %q, for msg %q", got, want, msg)
		}
	}

	check("", ".\r\n")
	check(".\r\n", "..\r\n.\r\n")
	check("header: abc\r\n\r\nmessage\r\n", "header: abc\r\n\r\nmessage\r\n.\r\n")
}

func TestDataReader(t *testing.T) {
	// Copy with a 1 byte buffer for reading.
	smallCopy := func(d io.Writer, r io.Reader) (int, error) {
		var wrote int
		buf := make([]byte, 1)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				nn, err := d.Write(buf)
				if nn > 0 {
					wrote += nn
				}
				if err != nil {
					return wrote, err
				}
			}
			if err == io.EOF {
				break
			} else if err != nil {
				return wrote, err
			}
		}
		return wrote, nil
	}

	check := func(data, want string, expErr error) {
		t.Helper()

		s := &strings.Builder{}
		dr := NewDataReader(bufio.NewReader(strings.NewReader(data)))
		if _, err := io.Copy(s, dr); err != nil {
			if expErr == nil || !errors.Is(err, expErr) {
				t.Fatalf("got err %v, expected %v", err, expErr)
			}
		} else if got := s.String(); got != want {
			t.Fatalf("got %q, expected %q, for %q", got, want, data)
		}

		s = &strings.Builder{}
		dr = NewDataReader(bufio.NewReader(strings.NewReader(data)))
		if _, err := smallCopy(s, dr); err != nil {
			if expErr == nil || !errors.Is(err, expErr) {
				t.Fatalf("got err %v, expected %v", err, expErr)
			}
		} else if got := s.String(); got != want {
			t.Fatalf("got %q, expected %q, for %q", got, want, data)
		}
	}

	check("test\r\n.\r\n", "test\r\n", nil)
	check(".\r\n", "", nil)
	check(".test\r\n.\r\n", "test\r\n", nil) // Unnecessary dot, but valid in SMTP.
	check("..test\r\n.\r\n", ".test\r\n", nil)

	check("..test\ntest.\n\r\n.\r\n", ".test\ntest.\n\r\n", nil) // Bare newlines are allowed.
	check("..test\ntest\n", "", io.ErrUnexpectedEOF)             // Missing end-of-message.

	// Bare \r is rejected.
	check("bare \r is rejected\r\n.\r\n", "", ErrCRLF)
	check("bad:\r.\ris rejected\r\n.\r\n", "", ErrCRLF)
	check("bad:\r.\nis rejected\r\n.\r\n", "", ErrCRLF)

	// Suspicious bare newlines around a dot are rejected.
	check("bad:\n.\nis rejected\r\n.\r\n", "", ErrCRLF)
	check("bad:\n.\r\nis rejected\r\n.\r\n", "", ErrCRLF)
	check("bad:\r\n.\nis rejected\r\n.\r\n", "", ErrCRLF)

	// Suspicious near-smtp-endings at start of message.
	check(".\ris rejected\r\n.\r\n", "", ErrCRLF)
	check(".\nis rejected\r\n.\r\n", "", ErrCRLF)
	check("\n.\ris rejected\r\n.\r\n", "", ErrCRLF)
	check("\r.\ris rejected\r\n.\r\n", "", ErrCRLF)
	check("\n.\nis rejected\r\n.\r\n", "", ErrCRLF)
	check("\r.\nis rejected\r\n.\r\n", "", ErrCRLF)
	check("\r.\r\nis rejected\r\n.\r\n", "", ErrCRLF)
	check("\n.\r\nis rejected\r\n.\r\n", "", ErrCRLF)
	check("\r\n.\ris rejected\r\n.\r\n", "", ErrCRLF)
	check("\r\n.\nis rejected\r\n.\r\n", "", ErrCRLF)

	s := &strings.Builder{}
	dr := NewDataReader(bufio.NewReader(strings.NewReader("no end")))
	if _, err := io.Copy(s, dr); err != io.ErrUnexpectedEOF {
		t.Fatalf("got err %v, expected io.ErrUnexpectedEOF", err)
	}
}

func TestDataWriteLineBoundaries(t *testing.T) {
	const valid = "Subject: test\r\n\r\nbody\r\n"
	if err := DataWrite(io.Discard, &oneReader{[]byte(valid)}); err != nil {
		t.Fatalf("data write: %v", err)
	}
}

// oneReader returns data one byte at a time.
type oneReader struct {
	buf []byte
}

func (r *oneReader) Read(buf []byte) (int, error) {
	if len(r.buf) == 0 {
		return 0, io.EOF
	}
	if len(buf) == 0 {
		return 0, nil
	}
	buf[0] = r.buf[0]
	r.buf = r.buf[1:]
	return 1, nil
}
