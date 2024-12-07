package webaccount

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sherpa"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/webauth"
	"github.com/mjl-/mox/webhook"
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

func tcompare(t *testing.T, got, expect any) {
	t.Helper()
	if !reflect.DeepEqual(got, expect) {
		t.Fatalf("got:\n%#v\nexpected:\n%#v", got, expect)
	}
}

func TestAccount(t *testing.T) {
	os.RemoveAll("../testdata/httpaccount/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/httpaccount/mox.conf")
	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	mox.MustLoadConfig(true, false)
	log := mlog.New("webaccount", nil)
	acc, err := store.OpenAccount(log, "mjl☺")
	tcheck(t, err, "open account")
	err = acc.SetPassword(log, "test1234")
	tcheck(t, err, "set password")
	defer func() {
		err = acc.Close()
		tcheck(t, err, "closing account")
		acc.CheckClosed()
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
	tneedErrorCode(t, "user:error", func() { api.Login(ctx, "", "mjl☺@mox.example", "test1234") })

	// Login with loginToken.
	loginCookie := &http.Cookie{Name: "webaccountlogin"}
	loginCookie.Value = api.LoginPrep(ctx)
	reqInfo.Request.Header = http.Header{"Cookie": []string{loginCookie.String()}}

	csrfToken := api.Login(ctx, loginCookie.Value, "mjl☺@mox.example", "test1234")
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
	tneedErrorCode(t, "user:loginFailed", func() { api.Login(ctx, loginCookie.Value, "mjl☺@mox.example", "badauth") })
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
	testHTTP("GET", "/export", httpHeaders{}, http.StatusForbidden, nil, nil)
	testHTTP("GET", "/export", httpHeaders{hdrSessionBad}, http.StatusForbidden, nil, nil)
	testHTTP("GET", "/export", httpHeaders{hdrSessionOK}, http.StatusForbidden, nil, nil)

	// SetPassword needs the token.
	sessionToken := store.SessionToken(strings.SplitN(sessionCookie.Value, " ", 2)[0])
	reqInfo = requestInfo{"mjl☺@mox.example", "mjl☺", sessionToken, respRec, &http.Request{RemoteAddr: "127.0.0.1:1234"}}
	ctx = context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)

	api.SetPassword(ctx, "test1234")

	err = queue.Init() // For DB.
	tcheck(t, err, "queue init")
	defer queue.Shutdown()

	account, _, _, _ := api.Account(ctx)

	// Check we don't see the alias member list.
	tcompare(t, len(account.Aliases), 1)
	tcompare(t, account.Aliases[0], config.AddressAlias{
		SubscriptionAddress: "mjl☺@mox.example",
		Alias: config.Alias{
			LocalpartStr: "support",
			Domain:       dns.Domain{ASCII: "mox.example"},
			AllowMsgFrom: true,
		},
	})

	api.DestinationSave(ctx, "mjl☺@mox.example", account.Destinations["mjl☺@mox.example"], account.Destinations["mjl☺@mox.example"]) // todo: save modified value and compare it afterwards

	api.AccountSaveFullName(ctx, account.FullName+" changed") // todo: check if value was changed
	api.AccountSaveFullName(ctx, account.FullName)

	go ImportManage()
	defer func() {
		importers.Stop <- struct{}{}
	}()

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

	testExport := func(format, archive string, expectFiles int) {
		t.Helper()

		fields := url.Values{
			"csrf":      []string{string(csrfToken)},
			"format":    []string{format},
			"archive":   []string{archive},
			"mailbox":   []string{""},
			"recursive": []string{"on"},
		}
		r := httptest.NewRequest("POST", "/export", strings.NewReader(fields.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Add("Cookie", cookieOK.String())
		w := httptest.NewRecorder()
		handle(apiHandler, false, w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("export, got status code %d, expected 200: %s", w.Code, w.Body.Bytes())
		}
		var count int
		if archive == "zip" {
			buf := w.Body.Bytes()
			zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
			tcheck(t, err, "reading zip")
			for _, f := range zr.File {
				if !strings.HasSuffix(f.Name, "/") {
					count++
				}
			}
		} else {
			var src io.Reader = w.Body
			if archive == "tgz" {
				gzr, err := gzip.NewReader(src)
				tcheck(t, err, "gzip reader")
				src = gzr
			}
			tr := tar.NewReader(src)
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

	testExport("maildir", "tgz", 6) // 2 mailboxes, each with 2 messages and a dovecot-keyword file
	testExport("maildir", "zip", 6)
	testExport("mbox", "tar", 2+6) // 2 imported plus 6 default mailboxes (Inbox, Draft, etc)
	testExport("mbox", "zip", 2+6)

	sl := api.SuppressionList(ctx)
	tcompare(t, len(sl), 0)

	api.SuppressionAdd(ctx, "mjl@mox.example", true, "testing")
	tneedErrorCode(t, "user:error", func() { api.SuppressionAdd(ctx, "mjl@mox.example", true, "testing") }) // Duplicate.
	tneedErrorCode(t, "user:error", func() { api.SuppressionAdd(ctx, "bogus", true, "testing") })           // Bad address.

	sl = api.SuppressionList(ctx)
	tcompare(t, len(sl), 1)

	api.SuppressionRemove(ctx, "mjl@mox.example")
	tneedErrorCode(t, "user:error", func() { api.SuppressionRemove(ctx, "mjl@mox.example") }) // Absent.
	tneedErrorCode(t, "user:error", func() { api.SuppressionRemove(ctx, "bogus") })           // Not an address.

	var hooks int
	hookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
		hooks++
	}))
	defer hookServer.Close()

	api.OutgoingWebhookSave(ctx, "http://localhost:1234", "Basic base64", []string{"delivered"})
	api.OutgoingWebhookSave(ctx, "http://localhost:1234", "Basic base64", []string{})
	tneedErrorCode(t, "user:error", func() {
		api.OutgoingWebhookSave(ctx, "http://localhost:1234/outgoing", "Basic base64", []string{"bogus"})
	})
	tneedErrorCode(t, "user:error", func() { api.OutgoingWebhookSave(ctx, "invalid", "Basic base64", nil) })
	api.OutgoingWebhookSave(ctx, "", "", nil) // Restore.

	code, response, errmsg := api.OutgoingWebhookTest(ctx, hookServer.URL, "", webhook.Outgoing{})
	tcompare(t, code, 200)
	tcompare(t, response, "ok\n")
	tcompare(t, errmsg, "")
	tneedErrorCode(t, "user:error", func() { api.OutgoingWebhookTest(ctx, "bogus", "", webhook.Outgoing{}) })

	api.IncomingWebhookSave(ctx, "http://localhost:1234", "Basic base64")
	tneedErrorCode(t, "user:error", func() { api.IncomingWebhookSave(ctx, "invalid", "Basic base64") })
	api.IncomingWebhookSave(ctx, "", "") // Restore.

	code, response, errmsg = api.IncomingWebhookTest(ctx, hookServer.URL, "", webhook.Incoming{})
	tcompare(t, code, 200)
	tcompare(t, response, "ok\n")
	tcompare(t, errmsg, "")
	tneedErrorCode(t, "user:error", func() { api.IncomingWebhookTest(ctx, "bogus", "", webhook.Incoming{}) })

	api.FromIDLoginAddressesSave(ctx, []string{"mjl☺@mox.example"})
	api.FromIDLoginAddressesSave(ctx, []string{"mjl☺@mox.example", "mjl☺+fromid@mox.example"})
	api.FromIDLoginAddressesSave(ctx, []string{})
	tneedErrorCode(t, "user:error", func() { api.FromIDLoginAddressesSave(ctx, []string{"bogus@other.example"}) })

	api.KeepRetiredPeriodsSave(ctx, time.Minute, time.Minute)
	api.KeepRetiredPeriodsSave(ctx, 0, 0) // Restore.

	api.AutomaticJunkFlagsSave(ctx, true, "^(junk|spam)", "^(inbox|neutral|postmaster|dmarc|tlsrpt|rejects)", "")
	api.AutomaticJunkFlagsSave(ctx, false, "", "", "")

	api.JunkFilterSave(ctx, nil)
	jf := config.JunkFilter{
		Threshold: 0.95,
		Params: junk.Params{
			Twograms:    true,
			MaxPower:    0.1,
			TopWords:    10,
			IgnoreWords: 0.1,
		},
	}
	api.JunkFilterSave(ctx, &jf)

	api.RejectsSave(ctx, "Rejects", true)
	api.RejectsSave(ctx, "Rejects", false)
	api.RejectsSave(ctx, "", false) // Restore.

	// Make cert for TLSPublicKey.
	certBuf := fakeCert(t)
	var b bytes.Buffer
	err = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: certBuf})
	tcheck(t, err, "encoding certificate as pem")
	certPEM := b.String()

	err = store.Init(ctx)
	tcheck(t, err, "store init")
	defer func() {
		err := store.Close()
		tcheck(t, err, "store close")
	}()

	tpkl, err := api.TLSPublicKeys(ctx)
	tcheck(t, err, "list tls public keys")
	tcompare(t, len(tpkl), 0)

	tpk, err := api.TLSPublicKeyAdd(ctx, "mjl☺@mox.example", "", false, certPEM)
	tcheck(t, err, "add tls public key")
	// Key already exists.
	tneedErrorCode(t, "user:error", func() { api.TLSPublicKeyAdd(ctx, "mjl☺@mox.example", "", false, certPEM) })

	tpkl, err = api.TLSPublicKeys(ctx)
	tcheck(t, err, "list tls public keys")
	tcompare(t, tpkl, []store.TLSPublicKey{tpk})

	tpk.NoIMAPPreauth = true
	err = api.TLSPublicKeyUpdate(ctx, tpk)
	tcheck(t, err, "tls public key update")
	badtpk := tpk
	badtpk.Fingerprint = "bogus"
	tneedErrorCode(t, "user:error", func() { api.TLSPublicKeyUpdate(ctx, badtpk) })

	tpkl, err = api.TLSPublicKeys(ctx)
	tcheck(t, err, "list tls public keys")
	tcompare(t, len(tpkl), 1)
	tcompare(t, tpkl[0].NoIMAPPreauth, true)

	err = api.TLSPublicKeyRemove(ctx, tpk.Fingerprint)
	tcheck(t, err, "tls public key remove")
	tneedErrorCode(t, "user:error", func() { api.TLSPublicKeyRemove(ctx, tpk.Fingerprint) })

	tpkl, err = api.TLSPublicKeys(ctx)
	tcheck(t, err, "list tls public keys")
	tcompare(t, len(tpkl), 0)

	api.Logout(ctx)
	tneedErrorCode(t, "server:error", func() { api.Logout(ctx) })
}

func fakeCert(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	privKey := ed25519.NewKeyFromSeed(seed) // Fake key, don't use this for real!
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field...
	}
	localCertBuf, err := x509.CreateCertificate(cryptorand.Reader, template, template, privKey.Public(), privKey)
	tcheck(t, err, "making certificate")
	return localCertBuf
}
