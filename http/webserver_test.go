package http

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mjl-/mox/mox-"
)

func TestWebserver(t *testing.T) {
	os.RemoveAll("../testdata/webserver/data")
	mox.ConfigStaticPath = "../testdata/webserver/mox.conf"
	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	mox.MustLoadConfig()

	srv := &serve{Webserver: true}

	test := func(method, target string, reqhdrs map[string]string, expCode int, expContent string, expHeaders map[string]string) {
		t.Helper()

		req := httptest.NewRequest(method, target, nil)
		for k, v := range reqhdrs {
			req.Header.Add(k, v)
		}
		rw := httptest.NewRecorder()
		rw.Body = &bytes.Buffer{}
		srv.ServeHTTP(rw, req)
		resp := rw.Result()
		if resp.StatusCode != expCode {
			t.Fatalf("got statuscode %d, expected %d", resp.StatusCode, expCode)
		}
		if expContent != "" {
			s := rw.Body.String()
			if s != expContent {
				t.Fatalf("got response data %q, expected %q", s, expContent)
			}
		}
		for k, v := range expHeaders {
			if xv := resp.Header.Get(k); xv != v {
				t.Fatalf("got %q for header %q, expected %q", xv, k, v)
			}
		}
	}

	test("GET", "http://redir.mox.example", nil, http.StatusPermanentRedirect, "", map[string]string{"Location": "https://mox.example/"})

	test("GET", "http://mox.example/static/", nil, http.StatusOK, "", map[string]string{"X-Test": "mox"})                              // index.html
	test("GET", "http://mox.example/static/dir/", nil, http.StatusOK, "", map[string]string{"X-Test": "mox"})                          // listing
	test("GET", "http://mox.example/static/dir", nil, http.StatusTemporaryRedirect, "", map[string]string{"Location": "/static/dir/"}) // redirect to dir
	test("GET", "http://mox.example/static/bogus", nil, http.StatusNotFound, "", nil)

	test("GET", "http://mox.example/nolist/", nil, http.StatusOK, "", nil)            // index.html
	test("GET", "http://mox.example/nolist/dir/", nil, http.StatusForbidden, "", nil) // no listing

	test("GET", "http://mox.example/tls/", nil, http.StatusPermanentRedirect, "", map[string]string{"Location": "https://mox.example/tls/"}) // redirect to tls

	test("GET", "http://mox.example/baseurl/x?y=2", nil, http.StatusPermanentRedirect, "", map[string]string{"Location": "https://tls.mox.example/baseurl/x?q=1&y=2#fragment"})
	test("GET", "http://mox.example/pathonly/old/x?q=2", nil, http.StatusTemporaryRedirect, "", map[string]string{"Location": "http://mox.example/pathonly/new/x?q=2"})
	test("GET", "http://mox.example/baseurlpath/old/x?y=2", nil, http.StatusPermanentRedirect, "", map[string]string{"Location": "//other.mox.example/baseurlpath/new/x?q=1&y=2#fragment"})

	test("GET", "http://mox.example/strip/x", nil, http.StatusBadGateway, "", nil)   // no server yet
	test("GET", "http://mox.example/nostrip/x", nil, http.StatusBadGateway, "", nil) // no server yet

	badForwarded := map[string]string{
		"Forwarded":         "bad",
		"X-Forwarded-For":   "bad",
		"X-Forwarded-Proto": "bad",
		"X-Forwarded-Host":  "bad",
		"X-Forwarded-Ext":   "bad",
	}

	// Server that echoes path, and forwarded request headers.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range badForwarded {
			if r.Header.Get(k) == v {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		for k, vl := range r.Header {
			if k == "Forwarded" || k == "X-Forwarded" || strings.HasPrefix(k, "X-Forwarded-") {
				w.Header()[k] = vl
			}
		}
		w.Write([]byte(r.URL.Path))
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parsing url: %v", err)
	}
	serverURL.Path = "/a"

	// warning: it is not normally allowed to access the dynamic config without lock. don't propagate accesses like this!
	mox.Conf.Dynamic.WebHandlers[len(mox.Conf.Dynamic.WebHandlers)-2].WebForward.TargetURL = serverURL
	mox.Conf.Dynamic.WebHandlers[len(mox.Conf.Dynamic.WebHandlers)-1].WebForward.TargetURL = serverURL

	test("GET", "http://mox.example/strip/x", badForwarded, http.StatusOK, "/a/x", map[string]string{
		"X-Test":            "mox",
		"X-Forwarded-For":   "192.0.2.1", // IP is hardcoded in Go's src/net/http/httptest/httptest.go
		"X-Forwarded-Proto": "http",
		"X-Forwarded-Host":  "mox.example",
		"X-Forwarded-Ext":   "",
	})
	test("GET", "http://mox.example/nostrip/x", map[string]string{"X-OK": "ok"}, http.StatusOK, "/a/nostrip/x", map[string]string{"X-Test": "mox"})

	test("GET", "http://mox.example/bogus", nil, http.StatusNotFound, "", nil)         // path not registered.
	test("GET", "http://bogus.mox.example/static/", nil, http.StatusNotFound, "", nil) // domain not registered.
}
