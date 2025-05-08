package store

import (
	"io"
	"os"
	"path/filepath"
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

	// Maildir uses timestamps and mtime to sort files.
	// At least Dovecot does so:
	// - unix timestamp as the first component of the filename is the "arrival time"
	// - file mtime is IMAP's INTERNALDATE
	// https://doc.dovecot.org/2.3/admin_manual/mailbox_formats/maildir/#usage-of-timestamps
	//
	// I guess that both are more or less the same time, usually, and mox already
	// parses messages in this order (unix timestamp, and if that fails file
	// mtime). However, we want to make sure that mox has sorted all existing
	// messages before starting actual import since that's when ids (unique and
	// strictly increasing integers).
	//
	// This test only uses unix timestamps in filenames since it is simpler.

	var exp_names = []string{
		"cur/1642966915.1.mox",
		"new/1642968136.5.mox",
		"cur/1642970123.9.mox",
		"new/1642972987.13.mox",
	}

	log := mlog.New("maildirreader", nil)
	mr := NewMaildirReader(log, createTemp, newf, curf)

	for _, exp := range exp_names {
		_, mf, fn, err := mr.Next()
		if err != nil {
			t.Fatalf("next maildir message: %v", err)
		}
		defer os.Remove(mf.Name())
		defer mf.Close()

		exp_ := filepath.FromSlash(exp)
		if !strings.HasSuffix(fn, exp_) {
			t.Fatalf("next maildir message should be '%v' instead of '%v'", exp_, fn)
		}
	}

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
