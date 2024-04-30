package moxio

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/mjl-/mox/mlog"
)

func TestBufpool(t *testing.T) {
	bp := NewBufpool(1, 8)
	a := bp.get()
	b := bp.get()
	for i := 0; i < len(a); i++ {
		a[i] = 1
	}
	log := mlog.New("moxio", nil)
	bp.put(log, a, len(a)) // Will be stored.
	bp.put(log, b, 0)      // Will be discarded.
	na := bp.get()
	if fmt.Sprintf("%p", a) != fmt.Sprintf("%p", na) {
		t.Fatalf("received unexpected new buf %p != %p", a, na)
	}
	for _, c := range na {
		if c != 0 {
			t.Fatalf("reused buf not cleared")
		}
	}

	if _, err := bp.Readline(log, bufio.NewReader(strings.NewReader("this is too long"))); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("expected ErrLineTooLong, got error %v", err)
	}
	if _, err := bp.Readline(log, bufio.NewReader(strings.NewReader("short"))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrLineTooLong, got error %v", err)
	}

	er := errReader{fmt.Errorf("bad")}
	if _, err := bp.Readline(log, bufio.NewReader(er)); err == nil || !errors.Is(err, er.err) {
		t.Fatalf("got unexpected error %s", err)
	}

	if line, err := bp.Readline(log, bufio.NewReader(strings.NewReader("ok\r\n"))); line != "ok" {
		t.Fatalf(`got %q, err %v, expected line "ok"`, line, err)
	}
	if line, err := bp.Readline(log, bufio.NewReader(strings.NewReader("ok\n"))); line != "ok" {
		t.Fatalf(`got %q, err %v, expected line "ok"`, line, err)
	}
}

type errReader struct {
	err error
}

func (r errReader) Read(buf []byte) (int, error) {
	return 0, r.err
}
