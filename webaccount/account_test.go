package webaccount

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

var ctxbg = context.Background()

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

func TestAccount(t *testing.T) {
	os.RemoveAll("../testdata/httpaccount/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/httpaccount/mox.conf")
	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	mox.MustLoadConfig(true, false)
	acc, err := store.OpenAccount("mjl")
	tcheck(t, err, "open account")
	defer func() {
		err = acc.Close()
		tcheck(t, err, "closing account")
	}()
	defer store.Switchboard()()

	log := mlog.New("store")

	test := func(userpass string, expect string) {
		t.Helper()

		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/ignored", nil)
		authhdr := "Basic " + base64.StdEncoding.EncodeToString([]byte(userpass))
		r.Header.Add("Authorization", authhdr)
		_, accName := CheckAuth(ctxbg, log, "webaccount", w, r)
		if accName != expect {
			t.Fatalf("got %q, expected %q", accName, expect)
		}
	}

	const authOK = "mjl@mox.example:test1234"
	const authBad = "mjl@mox.example:badpassword"

	authCtx := context.WithValue(ctxbg, authCtxKey, "mjl")

	test(authOK, "") // No password set yet.
	Account{}.SetPassword(authCtx, "test1234")
	test(authOK, "mjl")
	test(authBad, "")

	fullName, _, dests := Account{}.Account(authCtx)
	Account{}.DestinationSave(authCtx, "mjl@mox.example", dests["mjl@mox.example"], dests["mjl@mox.example"]) // todo: save modified value and compare it afterwards

	Account{}.AccountSaveFullName(authCtx, fullName+" changed") // todo: check if value was changed
	Account{}.AccountSaveFullName(authCtx, fullName)

	go ImportManage()

	// Import mbox/maildir tgz/zip.
	testImport := func(filename string, expect int) {
		t.Helper()

		var reqBody bytes.Buffer
		mpw := multipart.NewWriter(&reqBody)
		part, err := mpw.CreateFormFile("file", path.Base(filename))
		tcheck(t, err, "creating form file")
		buf, err := os.ReadFile(filename)
		tcheck(t, err, "reading file")
		_, err = part.Write(buf)
		tcheck(t, err, "write part")
		err = mpw.Close()
		tcheck(t, err, "close multipart writer")

		r := httptest.NewRequest("POST", "/import", &reqBody)
		r.Header.Add("Content-Type", mpw.FormDataContentType())
		r.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(authOK)))
		w := httptest.NewRecorder()
		Handle(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("import, got status code %d, expected 200: %s", w.Code, w.Body.Bytes())
		}
		m := map[string]string{}
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("parsing import response: %v", err)
		}
		token := m["ImportToken"]

		l := importListener{token, make(chan importEvent, 100), make(chan bool)}
		importers.Register <- &l
		if !<-l.Register {
			t.Fatalf("register failed")
		}
		defer func() {
			importers.Unregister <- &l
		}()
		count := 0
	loop:
		for {
			e := <-l.Events
			if e.Event == nil {
				continue
			}
			switch x := e.Event.(type) {
			case importCount:
				count += x.Count
			case importProblem:
				t.Fatalf("unexpected problem: %q", x.Message)
			case importStep:
			case importDone:
				break loop
			case importAborted:
				t.Fatalf("unexpected aborted import")
			default:
				panic(fmt.Sprintf("missing case for Event %#v", e))
			}
		}
		if count != expect {
			t.Fatalf("imported %d messages, expected %d", count, expect)
		}
	}
	testImport(filepath.FromSlash("../testdata/importtest.mbox.zip"), 2)
	testImport(filepath.FromSlash("../testdata/importtest.maildir.tgz"), 2)

	// Check there are messages, with the right flags.
	acc.DB.Read(ctxbg, func(tx *bstore.Tx) error {
		_, err = bstore.QueryTx[store.Message](tx).FilterEqual("Expunged", false).FilterIn("Keywords", "other").FilterIn("Keywords", "test").Get()
		tcheck(t, err, `fetching message with keywords "other" and "test"`)

		mb, err := acc.MailboxFind(tx, "importtest")
		tcheck(t, err, "looking up mailbox importtest")
		if mb == nil {
			t.Fatalf("missing mailbox importtest")
		}
		sort.Strings(mb.Keywords)
		if strings.Join(mb.Keywords, " ") != "other test" {
			t.Fatalf(`expected mailbox keywords "other" and "test", got %v`, mb.Keywords)
		}

		n, err := bstore.QueryTx[store.Message](tx).FilterEqual("Expunged", false).FilterIn("Keywords", "custom").Count()
		tcheck(t, err, `fetching message with keyword "custom"`)
		if n != 2 {
			t.Fatalf(`got %d messages with keyword "custom", expected 2`, n)
		}

		mb, err = acc.MailboxFind(tx, "maildir")
		tcheck(t, err, "looking up mailbox maildir")
		if mb == nil {
			t.Fatalf("missing mailbox maildir")
		}
		if strings.Join(mb.Keywords, " ") != "custom" {
			t.Fatalf(`expected mailbox keywords "custom", got %v`, mb.Keywords)
		}

		return nil
	})

	testExport := func(httppath string, iszip bool, expectFiles int) {
		t.Helper()

		r := httptest.NewRequest("GET", httppath, nil)
		r.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(authOK)))
		w := httptest.NewRecorder()
		Handle(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("export, got status code %d, expected 200: %s", w.Code, w.Body.Bytes())
		}
		var count int
		if iszip {
			buf := w.Body.Bytes()
			zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
			tcheck(t, err, "reading zip")
			for _, f := range zr.File {
				if !strings.HasSuffix(f.Name, "/") {
					count++
				}
			}
		} else {
			gzr, err := gzip.NewReader(w.Body)
			tcheck(t, err, "gzip reader")
			tr := tar.NewReader(gzr)
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				tcheck(t, err, "next file in tar")
				if !strings.HasSuffix(h.Name, "/") {
					count++
				}
				_, err = io.Copy(io.Discard, tr)
				tcheck(t, err, "reading from tar")
			}
		}
		if count != expectFiles {
			t.Fatalf("export, has %d files, expected %d", count, expectFiles)
		}
	}

	testExport("/mail-export-maildir.tgz", false, 6) // 2 mailboxes, each with 2 messages and a dovecot-keyword file
	testExport("/mail-export-maildir.zip", true, 6)
	testExport("/mail-export-mbox.tgz", false, 2)
	testExport("/mail-export-mbox.zip", true, 2)
}
