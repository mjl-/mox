package moxio

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mjl-/mox/mlog"
)

func tcheckf(t *testing.T, err error, format string, args ...any) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %s", fmt.Sprintf(format, args...), err)
	}
}

func TestLinkOrCopy(t *testing.T) {
	log := mlog.New("linkorcopy", nil)

	// link in same directory. file exists error. link to file in non-existent
	// directory (exists error). link to file in system temp dir (hopefully other file
	// system).
	src := "linkorcopytest-src.txt"
	f, err := os.Create(src)
	tcheckf(t, err, "creating test file")
	defer os.Remove(src)
	defer f.Close()
	err = LinkOrCopy(log, "linkorcopytest-dst.txt", src, nil, false)
	tcheckf(t, err, "linking file")
	err = os.Remove("linkorcopytest-dst.txt")
	tcheckf(t, err, "remove dst")

	err = LinkOrCopy(log, "bogus/linkorcopytest-dst.txt", src, nil, false)
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got %v", err)
	}

	// Try with copying the file. This can currently only really happen on systems that
	// don't support hardlinking. Because other code and tests already use os.Rename on
	// similar files, which will fail for being cross-filesystem (and we do want
	// users/admins to have the mox temp dir on the same file system as the account
	// files).
	dst := filepath.Join(os.TempDir(), "linkorcopytest-dst.txt")
	err = LinkOrCopy(log, dst, src, nil, true)
	tcheckf(t, err, "copy file")
	err = os.Remove(dst)
	tcheckf(t, err, "removing dst")

	// Copy based on open file.
	_, err = f.Seek(0, 0)
	tcheckf(t, err, "seek to start")
	err = LinkOrCopy(log, dst, src, f, true)
	tcheckf(t, err, "copy file from reader")
	err = os.Remove(dst)
	tcheckf(t, err, "removing dst")
}
