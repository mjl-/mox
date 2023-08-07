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

	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = "../testdata/store/mox.conf"
	mox.MustLoadConfig(true, false)
	acc, err := OpenAccount("mjl")
	tcheck(t, err, "open account")
	defer acc.Close()
	defer Switchboard()()

	log := mlog.New("export")

	msgFile, err := CreateMessageTemp("mox-test-export")
	tcheck(t, err, "create temp")
	defer os.Remove(msgFile.Name()) // To be sure.
	const msg = "test: test\r\n\r\ntest\r\n"
	_, err = msgFile.Write([]byte(msg))
	tcheck(t, err, "write message")

	m := Message{Received: time.Now(), Size: int64(len(msg))}
	err = acc.DeliverMailbox(xlog, "Inbox", &m, msgFile, false)
	tcheck(t, err, "deliver")

	m = Message{Received: time.Now(), Size: int64(len(msg))}
	err = acc.DeliverMailbox(xlog, "Trash", &m, msgFile, true)
	tcheck(t, err, "deliver")

	var maildirZip, maildirTar, mboxZip, mboxTar bytes.Buffer

	archive := func(archiver Archiver, maildir bool) {
		t.Helper()
		err = ExportMessages(ctxbg, log, acc.DB, acc.Dir, archiver, maildir, "")
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
	archive(DirArchiver{"../testdata/exportmaildir"}, true)
	archive(DirArchiver{"../testdata/exportmbox"}, false)

	if r, err := zip.NewReader(bytes.NewReader(maildirZip.Bytes()), int64(maildirZip.Len())); err != nil {
		t.Fatalf("reading maildir zip: %v", err)
	} else if len(r.File) != 2*3+2 {
		t.Fatalf("maildir zip, expected 2*3 dirs, and 2 files, got %d files", len(r.File))
	}

	if r, err := zip.NewReader(bytes.NewReader(mboxZip.Bytes()), int64(mboxZip.Len())); err != nil {
		t.Fatalf("reading mbox zip: %v", err)
	} else if len(r.File) != 2 {
		t.Fatalf("maildir zip, 2 files, got %d files", len(r.File))
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

	checkTarFiles(&maildirTar, 2*3+2)
	checkTarFiles(&mboxTar, 2)

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

	checkDirFiles("../testdata/exportmaildir", 2)
	checkDirFiles("../testdata/exportmbox", 2)
}
