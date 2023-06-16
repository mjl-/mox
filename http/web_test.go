package http

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
)

func TestServeHTTP(t *testing.T) {
	os.RemoveAll("../testdata/web/data")
	mox.ConfigStaticPath = "../testdata/web/mox.conf"
	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	mox.MustLoadConfig(true, false)

	srv := &serve{
		PathHandlers: []pathHandler{
			{
				HostMatch: func(dom dns.Domain) bool {
					return strings.HasPrefix(dom.ASCII, "mta-sts.")
				},
				Path: "/.well-known/mta-sts.txt",
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte("mta-sts!"))
				}),
			},
		},
		Webserver: true,
	}

	test := func(method, target string, expCode int, expContent string, expHeaders map[string]string) {
		t.Helper()

		req := httptest.NewRequest(method, target, nil)
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

	test("GET", "http://mta-sts.mox.example/.well-known/mta-sts.txt", http.StatusOK, "mta-sts!", nil)
	test("GET", "http://mox.example/.well-known/mta-sts.txt", http.StatusNotFound, "", nil) // mta-sts endpoint not in this domain.
	test("GET", "http://mta-sts.mox.example/static/", http.StatusNotFound, "", nil)         // static not served on this domain.
	test("GET", "http://mta-sts.mox.example/other", http.StatusNotFound, "", nil)
	test("GET", "http://mox.example/static/", http.StatusOK, "html\n", map[string]string{"X-Test": "mox"}) // index.html is served
	test("GET", "http://mox.example/static/index.html", http.StatusOK, "html\n", map[string]string{"X-Test": "mox"})
	test("GET", "http://mox.example/static/dir/", http.StatusOK, "", map[string]string{"X-Test": "mox"}) // Dir listing.
	test("GET", "http://mox.example/other", http.StatusNotFound, "", nil)
}
