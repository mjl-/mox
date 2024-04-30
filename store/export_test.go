package store

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

func TestExport(t *testing.T) {
	// Set up an account, add 2 messages to different 2 mailboxes. export as tar/zip
	// and maildir/mbox. check there are 2 files in the repo, no errors.txt.

	log := mlog.New("export", nil)

	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/store/mox.conf")
	mox.MustLoadConfig(true, false)
	acc, err := OpenAccount(pkglog, "mjl")
	tcheck(t, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
		acc.CheckClosed()
	}()
	defer Switchboard()()

	msgFile, err := CreateMessageTemp(pkglog, "mox-test-export")
	tcheck(t, err, "create temp")
	defer os.Remove(msgFile.Name()) // To be sure.
	defer msgFile.Close()
	const msg = "test: test\r\n\r\ntest\r\n"
	_, err = msgFile.Write([]byte(msg))
	tcheck(t, err, "write message")

	m := Message{Received: time.Now(), Size: int64(len(msg))}
	err = acc.DeliverMailbox(pkglog, "Inbox", &m, msgFile)
	tcheck(t, err, "deliver")

	m = Message{Received: time.Now(), Size: int64(len(msg))}
	err = acc.DeliverMailbox(pkglog, "Trash", &m, msgFile)
	tcheck(t, err, "deliver")

	var maildirZip, maildirTar, mboxZip, mboxTar bytes.Buffer

	archive := func(archiver Archiver, maildir bool) {
		t.Helper()
		err = ExportMessages(ctxbg, log, acc.DB, acc.Dir, archiver, maildir, "", true)
		tcheck(t, err, "export messages")
		err = archiver.Close()
		tcheck(t, err, "archiver close")
	}

	os.RemoveAll("../testdata/exportmaildir")
	os.RemoveAll("../testdata/exportmbox")

	archive(ZipArchiver{zip.NewWriter(&maildirZip)}, true)
	archive(ZipArchiver{zip.NewWriter(&mboxZip)}, false)
	archive(TarArchiver{tar.NewWriter(&maildirTar)}, true)
	archive(TarArchiver{tar.NewWriter(&mboxTar)}, false)
	archive(DirArchiver{filepath.FromSlash("../testdata/exportmaildir")}, true)
	archive(DirArchiver{filepath.FromSlash("../testdata/exportmbox")}, false)

	const defaultMailboxes = 6 // Inbox, Drafts, etc
	if r, err := zip.NewReader(bytes.NewReader(maildirZip.Bytes()), int64(maildirZip.Len())); err != nil {
		t.Fatalf("reading maildir zip: %v", err)
	} else if len(r.File) != defaultMailboxes*3+2 {
		t.Fatalf("maildir zip, expected %d*3 dirs, and 2 files, got %d files", defaultMailboxes, len(r.File))
	}

	if r, err := zip.NewReader(bytes.NewReader(mboxZip.Bytes()), int64(mboxZip.Len())); err != nil {
		t.Fatalf("reading mbox zip: %v", err)
	} else if len(r.File) != defaultMailboxes {
		t.Fatalf("maildir zip, expected %d files, got %d files", defaultMailboxes, len(r.File))
	}

	checkTarFiles := func(r io.Reader, n int) {
		t.Helper()
		tr := tar.NewReader(r)
		have := 0
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			have++
			if h.Name == "errors.txt" {
				t.Fatalf("got errors.txt")
			}
			_, err = io.Copy(io.Discard, tr)
			tcheck(t, err, "copy")
		}
		if have != n {
			t.Fatalf("got %d files, expected %d", have, n)
		}
	}

	checkTarFiles(&maildirTar, defaultMailboxes*3+2)
	checkTarFiles(&mboxTar, defaultMailboxes)

	checkDirFiles := func(dir string, n int) {
		t.Helper()
		have := 0
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				have++
			}
			return nil
		})
		tcheck(t, err, "walkdir")
		if n != have {
			t.Fatalf("got %d files, expected %d", have, n)
		}
	}

	checkDirFiles(filepath.FromSlash("../testdata/exportmaildir"), 2)
	checkDirFiles(filepath.FromSlash("../testdata/exportmbox"), defaultMailboxes)
}
