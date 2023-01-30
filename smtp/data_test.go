package smtp

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDataWrite(t *testing.T) {
	if err := DataWrite(io.Discard, strings.NewReader("bad")); err == nil || !errors.Is(err, errMissingCRLF) {
		t.Fatalf("got err %v, expected errMissingCRLF", err)
	}
	if err := DataWrite(io.Discard, strings.NewReader(".")); err == nil || !errors.Is(err, errMissingCRLF) {
		t.Fatalf("got err %v, expected errMissingCRLF", err)
	}

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

	check := func(data, want string) {
		t.Helper()

		s := &strings.Builder{}
		dr := NewDataReader(bufio.NewReader(strings.NewReader(data)))
		if _, err := io.Copy(s, dr); err != nil {
			t.Fatalf("got err %v", err)
		} else if got := s.String(); got != want {
			t.Fatalf("got %q, expected %q, for %q", got, want, data)
		}

		s = &strings.Builder{}
		dr = NewDataReader(bufio.NewReader(strings.NewReader(data)))
		if _, err := smallCopy(s, dr); err != nil {
			t.Fatalf("got err %v", err)
		} else if got := s.String(); got != want {
			t.Fatalf("got %q, expected %q, for %q", got, want, data)
		}
	}

	check("test\r\n.\r\n", "test\r\n")
	check(".\r\n", "")
	check(".test\r\n.\r\n", "test\r\n") // Unnecessary dot, but valid in SMTP.
	check("..test\r\n.\r\n", ".test\r\n")

	s := &strings.Builder{}
	dr := NewDataReader(bufio.NewReader(strings.NewReader("no end")))
	if _, err := io.Copy(s, dr); err != io.ErrUnexpectedEOF {
		t.Fatalf("got err %v, expected io.ErrUnexpectedEOF", err)
	}
}
