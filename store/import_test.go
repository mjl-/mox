package store

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/mjl-/mox/mlog"
)

func TestMboxReader(t *testing.T) {
	createTemp := func(log mlog.Log, pattern string) (*os.File, error) {
		return os.CreateTemp("", pattern)
	}
	mboxf, err := os.Open("../testdata/importtest.mbox")
	if err != nil {
		t.Fatalf("open mbox: %v", err)
	}
	defer mboxf.Close()

	log := mlog.New("mboxreader", nil)
	mr := NewMboxReader(log, createTemp, mboxf.Name(), mboxf)
	_, mf0, _, err := mr.Next()
	if err != nil {
		t.Fatalf("next mbox message: %v", err)
	}
	defer os.Remove(mf0.Name())
	defer mf0.Close()

	_, mf1, _, err := mr.Next()
	if err != nil {
		t.Fatalf("next mbox message: %v", err)
	}
	defer os.Remove(mf1.Name())
	defer mf1.Close()

	_, _, _, err = mr.Next()
	if err != io.EOF {
		t.Fatalf("got err %v, expected eof for next mbox message", err)
	}
}

func TestMaildirReader(t *testing.T) {
	createTemp := func(log mlog.Log, pattern string) (*os.File, error) {
		return os.CreateTemp("", pattern)
	}
	// todo: rename 1642966915.1.mox to "1642966915.1.mox:2,"? cannot have that name in the git repo because go module (or the proxy) doesn't like it. could also add some flags and test they survive the import.
	newf, err := os.Open("../testdata/importtest.maildir/new")
	if err != nil {
		t.Fatalf("open maildir new: %v", err)
	}
	defer newf.Close()

	curf, err := os.Open("../testdata/importtest.maildir/cur")
	if err != nil {
		t.Fatalf("open maildir cur: %v", err)
	}
	defer curf.Close()

	log := mlog.New("maildirreader", nil)
	mr := NewMaildirReader(log, createTemp, newf, curf)
	_, mf0, _, err := mr.Next()
	if err != nil {
		t.Fatalf("next maildir message: %v", err)
	}
	defer os.Remove(mf0.Name())
	defer mf0.Close()

	_, mf1, _, err := mr.Next()
	if err != nil {
		t.Fatalf("next maildir message: %v", err)
	}
	defer os.Remove(mf1.Name())
	defer mf1.Close()

	_, _, _, err = mr.Next()
	if err != io.EOF {
		t.Fatalf("got err %v, expected eof for next maildir message", err)
	}
}

func TestParseDovecotKeywords(t *testing.T) {
	const data = `0 Old
1 Junk
2 NonJunk
3 $Forwarded
4 $Junk
`
	flags, err := ParseDovecotKeywordsFlags(strings.NewReader(data), mlog.New("dovecotkeywords", nil))
	if err != nil {
		t.Fatalf("parsing dovecot-keywords: %v", err)
	}
	got := strings.Join(flags, ",")
	want := "old,junk,nonjunk,$forwarded,$junk"
	if got != want {
		t.Fatalf("parsing dovecot keywords, got %q, expect %q", got, want)

	}
}
