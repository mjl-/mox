package webaccount

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"testing"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sherpa"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/webauth"
)

var ctxbg = context.Background()

func init() {
	mox.LimitersInit()
	webauth.BadAuthDelay = 0
}

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

func readBody(r io.Reader) string {
	buf, err := io.ReadAll(r)
	if err != nil {
		return fmt.Sprintf("read error: %s", err)
	}
	return fmt.Sprintf("data: %q", buf)
}

func tneedErrorCode(t *testing.T, code string, fn func()) {
	t.Helper()
	defer func() {
		t.Helper()
		x := recover()
		if x == nil {
			debug.PrintStack()
			t.Fatalf("expected sherpa user error, saw success")
		}
		if err, ok := x.(*sherpa.Error); !ok {
			debug.PrintStack()
			t.Fatalf("expected sherpa error, saw %#v", x)
		} else if err.Code != code {
			debug.PrintStack()
			t.Fatalf("expected sherpa error code %q, saw other sherpa error %#v", code, err)
		}
	}()

	fn()
}

func TestAccount(t *testing.T) {
	os.RemoveAll("../testdata/httpaccount/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/httpaccount/mox.conf")
	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	mox.MustLoadConfig(true, false)
	log := mlog.New("webaccount", nil)
	acc, err := store.OpenAccount(log, "mjl")
	tcheck(t, err, "open account")
	err = acc.SetPassword(log, "test1234")
	tcheck(t, err, "set password")
	defer func() {
		err = acc.Close()
		tcheck(t, err, "closing account")
	}()
	defer store.Switchboard()()

	api := Account{cookiePath: "/account/"}
	apiHandler, err := makeSherpaHandler(api.cookiePath, false)
	tcheck(t, err, "sherpa handler")

	// Record HTTP response to get session cookie for login.
	respRec := httptest.NewRecorder()
	reqInfo := requestInfo{"", "", "", respRec, &http.Request{RemoteAddr: "127.0.0.1:1234"}}
	ctx := context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)

	// Missing login token.
	tneedErrorCode(t, "user:error", func() { api.Login(ctx, "", "mjl@mox.example", "test1234") })

	// Login with loginToken.
	loginCookie := &http.Cookie{Name: "webaccountlogin"}
	loginCookie.Value = api.LoginPrep(ctx)
	reqInfo.Request.Header = http.Header{"Cookie": []string{loginCookie.String()}}

	csrfToken := api.Login(ctx, loginCookie.Value, "mjl@mox.example", "test1234")
	var sessionCookie *http.Cookie
	for _, c := range respRec.Result().Cookies() {
		if c.Name == "webaccountsession" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("missing session cookie")
	}

	// Valid loginToken, but bad credentials.
	loginCookie.Value = api.LoginPrep(ctx)
	reqInfo.Request.Header = http.Header{"Cookie": []string{loginCookie.String()}}
	tneedErrorCode(t, "user:loginFailed", func() { api.Login(ctx, loginCookie.Value, "mjl@mox.example", "badauth") })
	tneedErrorCode(t, "user:loginFailed", func() { api.Login(ctx, loginCookie.Value, "baduser@mox.example", "badauth") })
	tneedErrorCode(t, "user:loginFailed", func() { api.Login(ctx, loginCookie.Value, "baduser@baddomain.example", "badauth") })

	type httpHeaders [][2]string
	ctJSON := [2]string{"Content-Type", "application/json; charset=utf-8"}

	cookieOK := &http.Cookie{Name: "webaccountsession", Value: sessionCookie.Value}
	cookieBad := &http.Cookie{Name: "webaccountsession", Value: "AAAAAAAAAAAAAAAAAAAAAA mjl"}
	hdrSessionOK := [2]string{"Cookie", cookieOK.String()}
	hdrSessionBad := [2]string{"Cookie", cookieBad.String()}
	hdrCSRFOK := [2]string{"x-mox-csrf", string(csrfToken)}
	hdrCSRFBad := [2]string{"x-mox-csrf", "AAAAAAAAAAAAAAAAAAAAAA"}

	testHTTP := func(method, path string, headers httpHeaders, expStatusCode int, expHeaders httpHeaders, check func(resp *http.Response)) {
		t.Helper()

		req := httptest.NewRequest(method, path, nil)
		for _, kv := range headers {
			req.Header.Add(kv[0], kv[1])
		}
		rr := httptest.NewRecorder()
		rr.Body = &bytes.Buffer{}
		handle(apiHandler, false, rr, req)
		if rr.Code != expStatusCode {
			t.Fatalf("got status %d, expected %d (%s)", rr.Code, expStatusCode, readBody(rr.Body))
		}

		resp := rr.Result()
		for _, h := range expHeaders {
			if resp.Header.Get(h[0]) != h[1] {
				t.Fatalf("for header %q got value %q, expected %q", h[0], resp.Header.Get(h[0]), h[1])
			}
		}

		if check != nil {
			check(resp)
		}
	}
	testHTTPAuthAPI := func(method, path string, expStatusCode int, expHeaders httpHeaders, check func(resp *http.Response)) {
		t.Helper()
		testHTTP(method, path, httpHeaders{hdrCSRFOK, hdrSessionOK}, expStatusCode, expHeaders, check)
	}

	userAuthError := func(resp *http.Response, expCode string) {
		t.Helper()

		var response struct {
			Error *sherpa.Error `json:"error"`
		}
		err := json.NewDecoder(resp.Body).Decode(&response)
		tcheck(t, err, "parsing response as json")
		if response.Error == nil {
			t.Fatalf("expected sherpa error with code %s, no error", expCode)
		}
		if response.Error.Code != expCode {
			t.Fatalf("got sherpa error code %q, expected %s", response.Error.Code, expCode)
		}
	}
	badAuth := func(resp *http.Response) {
		t.Helper()
		userAuthError(resp, "user:badAuth")
	}
	noAuth := func(resp *http.Response) {
		t.Helper()
		userAuthError(resp, "user:noAuth")
	}

	testHTTP("POST", "/api/Bogus", httpHeaders{}, http.StatusOK, nil, noAuth)
	testHTTP("POST", "/api/Bogus", httpHeaders{hdrCSRFBad}, http.StatusOK, nil, noAuth)
	testHTTP("POST", "/api/Bogus", httpHeaders{hdrSessionBad}, http.StatusOK, nil, noAuth)
	testHTTP("POST", "/api/Bogus", httpHeaders{hdrCSRFBad, hdrSessionBad}, http.StatusOK, nil, badAuth)
	testHTTP("POST", "/api/Bogus", httpHeaders{hdrCSRFOK}, http.StatusOK, nil, noAuth)
	testHTTP("POST", "/api/Bogus", httpHeaders{hdrSessionOK}, http.StatusOK, nil, noAuth)
	testHTTP("POST", "/api/Bogus", httpHeaders{hdrCSRFBad, hdrSessionOK}, http.StatusOK, nil, badAuth)
	testHTTP("POST", "/api/Bogus", httpHeaders{hdrCSRFOK, hdrSessionBad}, http.StatusOK, nil, badAuth)
	testHTTPAuthAPI("GET", "/api/Types", http.StatusMethodNotAllowed, nil, nil)
	testHTTPAuthAPI("POST", "/api/Types", http.StatusOK, httpHeaders{ctJSON}, nil)

	testHTTP("POST", "/import", httpHeaders{}, http.StatusForbidden, nil, nil)
	testHTTP("POST", "/import", httpHeaders{hdrSessionBad}, http.StatusForbidden, nil, nil)
	testHTTP("GET", "/export/mail-export-maildir.tgz", httpHeaders{}, http.StatusForbidden, nil, nil)
	testHTTP("GET", "/export/mail-export-maildir.tgz", httpHeaders{hdrSessionBad}, http.StatusForbidden, nil, nil)
	testHTTP("GET", "/export/mail-export-maildir.tgz", httpHeaders{hdrSessionOK}, http.StatusForbidden, nil, nil)
	testHTTP("GET", "/export/mail-export-maildir.zip", httpHeaders{}, http.StatusForbidden, nil, nil)
	testHTTP("GET", "/export/mail-export-mbox.tgz", httpHeaders{}, http.StatusForbidden, nil, nil)
	testHTTP("GET", "/export/mail-export-mbox.zip", httpHeaders{}, http.StatusForbidden, nil, nil)

	// SetPassword needs the token.
	sessionToken := store.SessionToken(strings.SplitN(sessionCookie.Value, " ", 2)[0])
	reqInfo = requestInfo{"mjl@mox.example", "mjl", sessionToken, respRec, &http.Request{RemoteAddr: "127.0.0.1:1234"}}
	ctx = context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)

	api.SetPassword(ctx, "test1234")

	fullName, _, dests := api.Account(ctx)
	api.DestinationSave(ctx, "mjl@mox.example", dests["mjl@mox.example"], dests["mjl@mox.example"]) // todo: save modified value and compare it afterwards

	api.AccountSaveFullName(ctx, fullName+" changed") // todo: check if value was changed
	api.AccountSaveFullName(ctx, fullName)

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
		r.Header.Add("x-mox-csrf", string(csrfToken))
		r.Header.Add("Cookie", cookieOK.String())
		w := httptest.NewRecorder()
		handle(apiHandler, false, w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("import, got status code %d, expected 200: %s", w.Code, w.Body.Bytes())
		}
		var m ImportProgress
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("parsing import response: %v", err)
		}

		l := importListener{m.Token, make(chan importEvent, 100), make(chan bool)}
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

		fields := url.Values{"csrf": []string{string(csrfToken)}}
		r := httptest.NewRequest("POST", httppath, strings.NewReader(fields.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Add("Cookie", cookieOK.String())
		w := httptest.NewRecorder()
		handle(apiHandler, false, w, r)
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

	testExport("/export/mail-export-maildir.tgz", false, 6) // 2 mailboxes, each with 2 messages and a dovecot-keyword file
	testExport("/export/mail-export-maildir.zip", true, 6)
	testExport("/export/mail-export-mbox.tgz", false, 2)
	testExport("/export/mail-export-mbox.zip", true, 2)

	api.Logout(ctx)
	tneedErrorCode(t, "server:error", func() { api.Logout(ctx) })
}
