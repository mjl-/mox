package http

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/websocket"

	"github.com/mjl-/mox/mox-"
)

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

func TestWebserver(t *testing.T) {
	os.RemoveAll("../testdata/webserver/data")
	mox.ConfigStaticPath = "../testdata/webserver/mox.conf"
	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	mox.MustLoadConfig(true, false)

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

	// http to https redirect, and stay on https afterwards without redirect loop.
	test("GET", "http://schemeredir.example", nil, http.StatusPermanentRedirect, "", map[string]string{"Location": "https://schemeredir.example/"})
	test("GET", "https://schemeredir.example", nil, http.StatusNotFound, "", nil)

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

func TestWebsocket(t *testing.T) {
	os.RemoveAll("../testdata/websocket/data")
	mox.ConfigStaticPath = "../testdata/websocket/mox.conf"
	mox.ConfigDynamicPath = filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	mox.MustLoadConfig(true, false)

	srv := &serve{Webserver: true}

	var handler http.Handler // Active handler during test.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))

	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parsing backend url: %v", err)
	}
	backendURL.Path = "/"

	// warning: it is not normally allowed to access the dynamic config without lock. don't propagate accesses like this!
	mox.Conf.Dynamic.WebHandlers[len(mox.Conf.Dynamic.WebHandlers)-1].WebForward.TargetURL = backendURL

	server := httptest.NewServer(srv)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	tcheck(t, err, "parsing server url")
	_, port, err := net.SplitHostPort(serverURL.Host)
	tcheck(t, err, "parsing host port in server url")
	wsurl := fmt.Sprintf("ws://%s/ws/", net.JoinHostPort("localhost", port))

	handler = websocket.Handler(func(c *websocket.Conn) {
		io.Copy(c, c)
	})

	// Test a correct websocket connection.
	wsconn, err := websocket.Dial(wsurl, "ignored", "http://ignored.example")
	tcheck(t, err, "websocket dial")
	_, err = fmt.Fprint(wsconn, "test")
	tcheck(t, err, "write to websocket")
	buf := make([]byte, 128)
	n, err := wsconn.Read(buf)
	tcheck(t, err, "read from websocket")
	if string(buf[:n]) != "test" {
		t.Fatalf(`got websocket data %q, expected "test"`, buf[:n])
	}
	err = wsconn.Close()
	tcheck(t, err, "closing websocket connection")

	// Test with server.ServeHTTP directly.
	test := func(method string, reqhdrs map[string]string, expCode int, expHeaders map[string]string) {
		t.Helper()

		req := httptest.NewRequest(method, wsurl, nil)
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
		for k, v := range expHeaders {
			if xv := resp.Header.Get(k); xv != v {
				t.Fatalf("got %q for header %q, expected %q", xv, k, v)
			}
		}
	}

	wsreqhdrs := map[string]string{
		"Upgrade":               "keep-alive, websocket",
		"Connection":            "X, Upgrade",
		"Sec-Websocket-Version": "13",
		"Sec-Websocket-Key":     "AAAAAAAAAAAAAAAAAAAAAA==",
	}

	test("POST", wsreqhdrs, http.StatusBadRequest, nil)

	clone := func(m map[string]string) map[string]string {
		r := map[string]string{}
		for k, v := range m {
			r[k] = v
		}
		return r
	}

	hdrs := clone(wsreqhdrs)
	hdrs["Sec-Websocket-Version"] = "14"
	test("GET", hdrs, http.StatusBadRequest, map[string]string{"Sec-Websocket-Version": "13"})

	httpurl := fmt.Sprintf("http://%s/ws/", net.JoinHostPort("localhost", port))

	// Must now do actual HTTP requests and read the HTTP response. Cannot call
	// ServeHTTP because ResponseRecorder is not a http.Hijacker.
	test = func(method string, reqhdrs map[string]string, expCode int, expHeaders map[string]string) {
		t.Helper()

		req, err := http.NewRequest(method, httpurl, nil)
		tcheck(t, err, "http newrequest")
		for k, v := range reqhdrs {
			req.Header.Add(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		tcheck(t, err, "http transaction")
		if resp.StatusCode != expCode {
			t.Fatalf("got statuscode %d, expected %d", resp.StatusCode, expCode)
		}
		for k, v := range expHeaders {
			if xv := resp.Header.Get(k); xv != v {
				t.Fatalf("got %q for header %q, expected %q", xv, k, v)
			}
		}
	}

	hdrs = clone(wsreqhdrs)
	hdrs["Sec-Websocket-Key"] = "malformed"
	test("GET", hdrs, http.StatusBadRequest, nil)

	hdrs = clone(wsreqhdrs)
	hdrs["Sec-Websocket-Key"] = "c2hvcnQK" // "short"
	test("GET", hdrs, http.StatusBadRequest, nil)

	// Not responding with a 101, but with regular 200 OK response.
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusOK)
	})
	test("GET", wsreqhdrs, http.StatusBadRequest, nil)

	// Respond with 101, but other websocket response headers missing.
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols)
	})
	test("GET", wsreqhdrs, http.StatusBadRequest, nil)

	// With Upgrade: websocket, without Connection: Upgrade
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Upgrade", "websocket")
		w.WriteHeader(http.StatusSwitchingProtocols)
	})
	test("GET", wsreqhdrs, http.StatusBadRequest, nil)

	// With malformed Sec-WebSocket-Accept response header.
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Upgrade", "websocket")
		h.Set("Connection", "Upgrade")
		h.Set("Sec-WebSocket-Accept", "malformed")
		w.WriteHeader(http.StatusSwitchingProtocols)
	})
	test("GET", wsreqhdrs, http.StatusBadRequest, nil)

	// With malformed Sec-WebSocket-Accept response header.
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Upgrade", "websocket")
		h.Set("Connection", "Upgrade")
		h.Set("Sec-WebSocket-Accept", "YmFk") // "bad"
		w.WriteHeader(http.StatusSwitchingProtocols)
	})
	test("GET", wsreqhdrs, http.StatusBadRequest, nil)

	// All good.
	wsresphdrs := map[string]string{
		"Connection":           "Upgrade",
		"Upgrade":              "websocket",
		"Sec-Websocket-Accept": "ICX+Yqv66kxgM0FcWaLWlFLwTAI=",
		"X-Test":               "mox",
	}
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Upgrade", "websocket")
		h.Set("Connection", "Upgrade")
		h.Set("Sec-WebSocket-Accept", "ICX+Yqv66kxgM0FcWaLWlFLwTAI=")
		w.WriteHeader(http.StatusSwitchingProtocols)
	})
	test("GET", wsreqhdrs, http.StatusSwitchingProtocols, wsresphdrs)

}
