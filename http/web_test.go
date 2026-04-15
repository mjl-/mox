package http

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mjl-/mox/mox-"
)

func TestServeHTTP(t *testing.T) {
	os.RemoveAll("../testdata/web/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/web/mox.conf")
	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	mox.MustLoadConfig(true, false)

	portSrvs := portServes("local", mox.Conf.Static.Listeners["local"])
	srv := portSrvs[80]

	test := func(method, target string, expCode int, expContent string, expHeaders map[string]string) {
		t.Helper()

		req := httptest.NewRequest(method, target, nil)
		rw := httptest.NewRecorder()
		rw.Body = &bytes.Buffer{}
		srv.ServeHTTP(rw, req)
		resp := rw.Result()
		if resp.StatusCode != expCode {
			t.Errorf("got statuscode %d, expected %d", resp.StatusCode, expCode)
		}
		if expContent != "" {
			s := rw.Body.String()
			if s != expContent {
				t.Errorf("got response data %q, expected %q", s, expContent)
			}
		}
		for k, v := range expHeaders {
			if xv := resp.Header.Get(k); xv != v {
				t.Errorf("got %q for header %q, expected %q", xv, k, v)
			}
		}
	}

	test("GET", "http://mta-sts.mox.example/.well-known/mta-sts.txt", http.StatusOK, "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mox.example\n", nil)
	test("GET", "http://mox.example/.well-known/mta-sts.txt", http.StatusNotFound, "", nil) // mta-sts endpoint not in this domain.
	test("GET", "http://mta-sts.mox.example/static/", http.StatusNotFound, "", nil)         // static not served on this domain.
	test("GET", "http://mta-sts.mox.example/other", http.StatusNotFound, "", nil)
	test("GET", "http://mox.example/static/", http.StatusOK, "html\n", map[string]string{"X-Test": "mox"}) // index.html is served
	test("GET", "http://mox.example/static/index.html", http.StatusOK, "html\n", map[string]string{"X-Test": "mox"})
	test("GET", "http://mox.example/static/dir/", http.StatusOK, "", map[string]string{"X-Test": "mox"}) // Dir listing.
	test("GET", "http://mox.example/other", http.StatusNotFound, "", nil)

	// Webmail on IP, localhost, mail host, clientsettingsdomain, not others.
	test("GET", "http://127.0.0.1/webmail/", http.StatusOK, "", nil)
	test("GET", "http://localhost/webmail/", http.StatusOK, "", nil)
	test("GET", "http://mox.example/webmail/", http.StatusOK, "", nil)
	test("GET", "http://mail.mox.example/webmail/", http.StatusOK, "", nil)
	test("GET", "http://mail.other.example/webmail/", http.StatusNotFound, "", nil)
	test("GET", "http://remotehost/webmail/", http.StatusNotFound, "", nil)

	// admin on IP, localhost, mail host, not clientsettingsdomain.
	test("GET", "http://127.0.0.1/admin/", http.StatusOK, "", nil)
	test("GET", "http://localhost/admin/", http.StatusOK, "", nil)
	test("GET", "http://mox.example/admin/", http.StatusPermanentRedirect, "", nil) // Override by WebHandler.
	test("GET", "http://mail.mox.example/admin/", http.StatusNotFound, "", nil)

	// account is off.
	test("GET", "http://127.0.0.1/", http.StatusNotFound, "", nil)
	test("GET", "http://localhost/", http.StatusNotFound, "", nil)
	test("GET", "http://mox.example/", http.StatusNotFound, "", nil)
	test("GET", "http://mail.mox.example/", http.StatusNotFound, "", nil)
}

func TestHealthz(t *testing.T) {
	os.RemoveAll("../testdata/web/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/web/mox.conf")
	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	mox.MustLoadConfig(true, false)

	portSrvs := portServes("local", mox.Conf.Static.Listeners["local"])
	srv := portSrvs[80]

	// /healthz returns 200 when not shutting down.
	req := httptest.NewRequest("GET", "http://localhost/healthz", nil)
	rw := httptest.NewRecorder()
	rw.Body = &bytes.Buffer{}
	srv.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("healthz: got status %d, expected %d", rw.Code, http.StatusOK)
	}
	if rw.Body.String() != "ok" {
		t.Fatalf("healthz: got body %q, expected %q", rw.Body.String(), "ok")
	}

	// /healthz returns 503 after shutdown is signaled.
	origCtx, origCancel := mox.Shutdown, mox.ShutdownCancel
	mox.Shutdown, mox.ShutdownCancel = context.WithCancel(context.Background())
	mox.ShutdownCancel() // Signal shutdown.
	req = httptest.NewRequest("GET", "http://localhost/healthz", nil)
	rw = httptest.NewRecorder()
	rw.Body = &bytes.Buffer{}
	srv.ServeHTTP(rw, req)
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz during shutdown: got status %d, expected %d", rw.Code, http.StatusServiceUnavailable)
	}
	// Restore original shutdown context.
	mox.Shutdown, mox.ShutdownCancel = origCtx, origCancel

	// POST to /healthz returns 405.
	req = httptest.NewRequest("POST", "http://localhost/healthz", nil)
	rw = httptest.NewRecorder()
	rw.Body = &bytes.Buffer{}
	srv.ServeHTTP(rw, req)
	if rw.Code != http.StatusMethodNotAllowed {
		t.Fatalf("healthz POST: got status %d, expected %d", rw.Code, http.StatusMethodNotAllowed)
	}
}
