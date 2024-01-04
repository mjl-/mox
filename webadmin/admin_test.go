package webadmin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mjl-/sherpa"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
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

func TestAdminAuth(t *testing.T) {
	os.RemoveAll("../testdata/webadmin/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/webadmin/mox.conf")
	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	mox.MustLoadConfig(true, false)

	adminpwhash, err := bcrypt.GenerateFromPassword([]byte("moxtest123"), bcrypt.DefaultCost)
	tcheck(t, err, "generate bcrypt hash")

	path := mox.ConfigDirPath(mox.Conf.Static.AdminPasswordFile)
	err = os.WriteFile(path, adminpwhash, 0660)
	tcheck(t, err, "write password file")
	defer os.Remove(path)

	api := Admin{cookiePath: "/admin/"}
	apiHandler, err := makeSherpaHandler(api.cookiePath, false)
	tcheck(t, err, "sherpa handler")

	respRec := httptest.NewRecorder()
	reqInfo := requestInfo{"", respRec, &http.Request{RemoteAddr: "127.0.0.1:1234"}}
	ctx := context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)

	// Missing login token.
	tneedErrorCode(t, "user:error", func() { api.Login(ctx, "", "moxtest123") })

	// Login with loginToken.
	loginCookie := &http.Cookie{Name: "webadminlogin"}
	loginCookie.Value = api.LoginPrep(ctx)
	reqInfo.Request.Header = http.Header{"Cookie": []string{loginCookie.String()}}

	csrfToken := api.Login(ctx, loginCookie.Value, "moxtest123")
	var sessionCookie *http.Cookie
	for _, c := range respRec.Result().Cookies() {
		if c.Name == "webadminsession" {
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
	tneedErrorCode(t, "user:loginFailed", func() { api.Login(ctx, loginCookie.Value, "badauth") })

	type httpHeaders [][2]string
	ctJSON := [2]string{"Content-Type", "application/json; charset=utf-8"}

	cookieOK := &http.Cookie{Name: "webadminsession", Value: sessionCookie.Value}
	cookieBad := &http.Cookie{Name: "webadminsession", Value: "AAAAAAAAAAAAAAAAAAAAAA"}
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
	testHTTPAuthAPI("GET", "/api/Transports", http.StatusMethodNotAllowed, nil, nil)
	testHTTPAuthAPI("POST", "/api/Transports", http.StatusOK, httpHeaders{ctJSON}, nil)

	// Logout needs session token.
	reqInfo.SessionToken = store.SessionToken(strings.SplitN(sessionCookie.Value, " ", 2)[0])
	ctx = context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)

	api.Logout(ctx)
	tneedErrorCode(t, "server:error", func() { api.Logout(ctx) })
}

func TestCheckDomain(t *testing.T) {
	// NOTE: we aren't currently looking at the results, having the code paths executed is better than nothing.

	log := mlog.New("webadmin", nil)

	resolver := dns.MockResolver{
		MX: map[string][]*net.MX{
			"mox.example.": {{Host: "mail.mox.example.", Pref: 10}},
		},
		A: map[string][]string{
			"mail.mox.example.": {"127.0.0.2"},
		},
		AAAA: map[string][]string{
			"mail.mox.example.": {"127.0.0.2"},
		},
		TXT: map[string][]string{
			"mox.example.":                 {"v=spf1 mx -all"},
			"test._domainkey.mox.example.": {"v=DKIM1;h=sha256;k=ed25519;p=ln5zd/JEX4Jy60WAhUOv33IYm2YZMyTQAdr9stML504="},
			"_dmarc.mox.example.":          {"v=DMARC1; p=reject; rua=mailto:mjl@mox.example"},
			"_smtp._tls.mox.example":       {"v=TLSRPTv1; rua=mailto:tlsrpt@mox.example;"},
			"_mta-sts.mox.example":         {"v=STSv1; id=20160831085700Z"},
		},
		CNAME: map[string]string{},
	}

	listener := config.Listener{
		IPs:            []string{"127.0.0.2"},
		Hostname:       "mox.example",
		HostnameDomain: dns.Domain{ASCII: "mox.example"},
	}
	listener.SMTP.Enabled = true
	listener.AutoconfigHTTPS.Enabled = true
	listener.MTASTSHTTPS.Enabled = true

	mox.Conf.Static.Listeners = map[string]config.Listener{
		"public": listener,
	}
	domain := config.Domain{
		DKIM: config.DKIM{
			Selectors: map[string]config.Selector{
				"test": {
					HashEffective:    "sha256",
					HeadersEffective: []string{"From", "Date", "Subject"},
					Key:              ed25519.NewKeyFromSeed(make([]byte, 32)), // warning: fake zero key, do not copy this code.
					Domain:           dns.Domain{ASCII: "test"},
				},
				"missing": {
					HashEffective:    "sha256",
					HeadersEffective: []string{"From", "Date", "Subject"},
					Key:              ed25519.NewKeyFromSeed(make([]byte, 32)), // warning: fake zero key, do not copy this code.
					Domain:           dns.Domain{ASCII: "missing"},
				},
			},
			Sign: []string{"test", "test2"},
		},
	}
	mox.Conf.Dynamic.Domains = map[string]config.Domain{
		"mox.example": domain,
	}

	// Make a dialer that fails immediately before actually connecting.
	done := make(chan struct{})
	close(done)
	dialer := &net.Dialer{Deadline: time.Now().Add(-time.Second), Cancel: done}

	checkDomain(ctxbg, resolver, dialer, "mox.example")
	// todo: check returned data

	Admin{}.Domains(ctxbg)             // todo: check results
	dnsblsStatus(ctxbg, log, resolver) // todo: check results
}
