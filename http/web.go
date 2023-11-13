// Package http provides HTTP listeners/servers, for
// autoconfiguration/autodiscovery, the account and admin web interface and
// MTA-STS policies.
package http

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	golog "log"
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	_ "net/http/pprof"

	"golang.org/x/exp/maps"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mjl-/mox/autotls"
	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/ratelimit"
	"github.com/mjl-/mox/webaccount"
	"github.com/mjl-/mox/webadmin"
	"github.com/mjl-/mox/webmail"
)

var xlog = mlog.New("http")

var (
	// metricRequest tracks performance (time to write response header) of server.
	metricRequest = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_httpserver_request_duration_seconds",
			Help:    "HTTP(s) server request with handler name, protocol, method, result codes, and duration until response status code is written, in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30, 60, 120},
		},
		[]string{
			"handler", // Name from webhandler, can be empty.
			"proto",   // "http", "https", "ws", "wss"
			"method",  // "(unknown)" and otherwise only common verbs
			"code",
		},
	)
	// metricResponse tracks performance of entire request as experienced by users,
	// which also depends on their connection speed, so not necessarily something you
	// could act on.
	metricResponse = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_httpserver_response_duration_seconds",
			Help:    "HTTP(s) server response with handler name, protocol, method, result codes, and duration of entire response, in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30, 60, 120},
		},
		[]string{
			"handler", // Name from webhandler, can be empty.
			"proto",   // "http", "https", "ws", "wss"
			"method",  // "(unknown)" and otherwise only common verbs
			"code",
		},
	)
)

type responseWriterFlusher interface {
	http.ResponseWriter
	http.Flusher
}

// http.ResponseWriter that writes access log and tracks metrics at end of response.
type loggingWriter struct {
	W                responseWriterFlusher // Calls are forwarded.
	Start            time.Time
	R                *http.Request
	WebsocketRequest bool // Whether request from was websocket.

	// Set by router.
	Handler  string
	Compress bool

	// Set by handlers.
	StatusCode                   int
	Size                         int64        // Of data served to client, for non-websocket responses.
	UncompressedSize             int64        // Can be set by a handler that already serves compressed data, and we update it while compressing.
	Gzip                         *gzip.Writer // Only set if we transparently compress within loggingWriter (static handlers handle compression themselves, with a cache).
	Err                          error
	WebsocketResponse            bool        // If this was a successful websocket connection with backend.
	SizeFromClient, SizeToClient int64       // Websocket data.
	Fields                       []mlog.Pair // Additional fields to log.
}

func (w *loggingWriter) AddField(p mlog.Pair) {
	w.Fields = append(w.Fields, p)
}

func (w *loggingWriter) Flush() {
	w.W.Flush()
}

func (w *loggingWriter) Header() http.Header {
	return w.W.Header()
}

// protocol, for logging.
func (w *loggingWriter) proto(websocket bool) string {
	proto := "http"
	if websocket {
		proto = "ws"
	}
	if w.R.TLS != nil {
		proto += "s"
	}
	return proto
}

func (w *loggingWriter) Write(buf []byte) (int, error) {
	if w.StatusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}

	var n int
	var err error
	if w.Gzip == nil {
		n, err = w.W.Write(buf)
		if n > 0 {
			w.Size += int64(n)
		}
	} else {
		// We flush after each write. Probably takes a few more bytes, but prevents any
		// issues due to buffering.
		// w.Gzip.Write updates w.Size with the compressed byte count.
		n, err = w.Gzip.Write(buf)
		if err == nil {
			err = w.Gzip.Flush()
		}
		if n > 0 {
			w.UncompressedSize += int64(n)
		}
	}
	if err != nil {
		w.error(err)
	}
	return n, err
}

func (w *loggingWriter) setStatusCode(statusCode int) {
	if w.StatusCode != 0 {
		return
	}

	w.StatusCode = statusCode
	method := metricHTTPMethod(w.R.Method)
	metricRequest.WithLabelValues(w.Handler, w.proto(w.WebsocketRequest), method, fmt.Sprintf("%d", w.StatusCode)).Observe(float64(time.Since(w.Start)) / float64(time.Second))
}

// SetUncompressedSize is used through an interface by
// ../webmail/webmail.go:/WriteHeader, preventing an import cycle.
func (w *loggingWriter) SetUncompressedSize(origSize int64) {
	w.UncompressedSize = origSize
}

func (w *loggingWriter) WriteHeader(statusCode int) {
	if w.StatusCode != 0 {
		return
	}

	w.setStatusCode(statusCode)

	// We transparently gzip-compress responses for requests under these conditions, all must apply:
	//
	// - Enabled for handler (static handlers make their own decisions).
	// - Not a websocket request.
	// - Regular success responses (not errors, or partial content or redirects or "not modified", etc).
	// - Not already compressed, or any other Content-Encoding header (including "identity").
	// - Client accepts gzip encoded responses.
	// - The response has a content-type that is compressible (text/*, */*+{json,xml}, and a few common files (e.g. json, xml, javascript).
	if w.Compress && !w.WebsocketRequest && statusCode == http.StatusOK && w.W.Header().Values("Content-Encoding") == nil && acceptsGzip(w.R) && compressibleContentType(w.W.Header().Get("Content-Type")) {
		// todo: we should gather the first kb of data, see if it is compressible. if not, just return original. should set timer so we flush if it takes too long to gather 1kb. for smaller data we shouldn't compress at all.

		// We track the gzipped output for the access log.
		cw := countWriter{Writer: w.W, Size: &w.Size}
		w.Gzip, _ = gzip.NewWriterLevel(cw, gzip.BestSpeed)
		w.W.Header().Set("Content-Encoding", "gzip")
		w.W.Header().Del("Content-Length") // No longer valid, set again for small responses by net/http.
	}
	w.W.WriteHeader(statusCode)
}

func acceptsGzip(r *http.Request) bool {
	s := r.Header.Get("Accept-Encoding")
	t := strings.Split(s, ",")
	for _, e := range t {
		e = strings.TrimSpace(e)
		tt := strings.Split(e, ";")
		if len(tt) > 1 && t[1] == "q=0" {
			continue
		}
		if tt[0] == "gzip" {
			return true
		}
	}
	return false
}

var compressibleTypes = map[string]bool{
	"application/csv":          true,
	"application/javascript":   true,
	"application/json":         true,
	"application/x-javascript": true,
	"application/xml":          true,
	"image/vnd.microsoft.icon": true,
	"image/x-icon":             true,
	"font/ttf":                 true,
	"font/eot":                 true,
	"font/otf":                 true,
	"font/opentype":            true,
}

func compressibleContentType(ct string) bool {
	ct = strings.SplitN(ct, ";", 2)[0]
	ct = strings.TrimSpace(ct)
	ct = strings.ToLower(ct)
	if compressibleTypes[ct] {
		return true
	}
	t, st, _ := strings.Cut(ct, "/")
	return t == "text" || strings.HasSuffix(st, "+json") || strings.HasSuffix(st, "+xml")
}

func compressibleContent(f *os.File) bool {
	// We don't want to store many small files. They take up too much disk overhead.
	if fi, err := f.Stat(); err != nil || fi.Size() < 1024 || fi.Size() > 10*1024*1024 {
		return false
	}

	buf := make([]byte, 512)
	n, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return false
	}
	ct := http.DetectContentType(buf[:n])
	return compressibleContentType(ct)
}

type countWriter struct {
	Writer io.Writer
	Size   *int64
}

func (w countWriter) Write(buf []byte) (int, error) {
	n, err := w.Writer.Write(buf)
	if n > 0 {
		*w.Size += int64(n)
	}
	return n, err
}

var tlsVersions = map[uint16]string{
	tls.VersionTLS10: "tls1.0",
	tls.VersionTLS11: "tls1.1",
	tls.VersionTLS12: "tls1.2",
	tls.VersionTLS13: "tls1.3",
}

func metricHTTPMethod(method string) string {
	// https://www.iana.org/assignments/http-methods/http-methods.xhtml
	method = strings.ToLower(method)
	switch method {
	case "acl", "baseline-control", "bind", "checkin", "checkout", "connect", "copy", "delete", "get", "head", "label", "link", "lock", "merge", "mkactivity", "mkcalendar", "mkcol", "mkredirectref", "mkworkspace", "move", "options", "orderpatch", "patch", "post", "pri", "propfind", "proppatch", "put", "rebind", "report", "search", "trace", "unbind", "uncheckout", "unlink", "unlock", "update", "updateredirectref", "version-control":
		return method
	}
	return "(other)"
}

func (w *loggingWriter) error(err error) {
	if w.Err == nil {
		w.Err = err
	}
}

func (w *loggingWriter) Done() {
	if w.Err == nil && w.Gzip != nil {
		if err := w.Gzip.Close(); err != nil {
			w.error(err)
		}
	}

	method := metricHTTPMethod(w.R.Method)
	metricResponse.WithLabelValues(w.Handler, w.proto(w.WebsocketResponse), method, fmt.Sprintf("%d", w.StatusCode)).Observe(float64(time.Since(w.Start)) / float64(time.Second))

	tlsinfo := "plain"
	if w.R.TLS != nil {
		if v, ok := tlsVersions[w.R.TLS.Version]; ok {
			tlsinfo = v
		} else {
			tlsinfo = "(other)"
		}
	}
	err := w.Err
	if err == nil {
		err = w.R.Context().Err()
	}
	fields := []mlog.Pair{
		mlog.Field("httpaccess", ""),
		mlog.Field("handler", w.Handler),
		mlog.Field("method", method),
		mlog.Field("url", w.R.URL),
		mlog.Field("host", w.R.Host),
		mlog.Field("duration", time.Since(w.Start)),
		mlog.Field("statuscode", w.StatusCode),
		mlog.Field("proto", strings.ToLower(w.R.Proto)),
		mlog.Field("remoteaddr", w.R.RemoteAddr),
		mlog.Field("tlsinfo", tlsinfo),
		mlog.Field("useragent", w.R.Header.Get("User-Agent")),
		mlog.Field("referrr", w.R.Header.Get("Referrer")),
	}
	if w.WebsocketRequest {
		fields = append(fields,
			mlog.Field("websocketrequest", true),
		)
	}
	if w.WebsocketResponse {
		fields = append(fields,
			mlog.Field("websocket", true),
			mlog.Field("sizetoclient", w.SizeToClient),
			mlog.Field("sizefromclient", w.SizeFromClient),
		)
	} else if w.UncompressedSize > 0 {
		fields = append(fields,
			mlog.Field("size", w.Size),
			mlog.Field("uncompressedsize", w.UncompressedSize),
		)
	} else {
		fields = append(fields,
			mlog.Field("size", w.Size),
		)
	}
	fields = append(fields, w.Fields...)
	xlog.WithContext(w.R.Context()).Debugx("http request", err, fields...)
}

// Set some http headers that should prevent potential abuse. Better safe than sorry.
func safeHeaders(fn http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "deny")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:")
		h.Set("Referrer-Policy", "same-origin")
		fn.ServeHTTP(w, r)
	})
}

// Built-in handlers, e.g. mta-sts and autoconfig.
type pathHandler struct {
	Name      string                    // For logging/metrics.
	HostMatch func(dom dns.Domain) bool // If not nil, called to see if domain of requests matches. Only called if requested host is a valid domain.
	Path      string                    // Path to register, like on http.ServeMux.
	Handler   http.Handler
}
type serve struct {
	Kinds        []string // Type of handler and protocol (e.g. acme-tls-alpn-01, account-http, admin-https).
	TLSConfig    *tls.Config
	PathHandlers []pathHandler // Sorted, longest first.
	Webserver    bool          // Whether serving WebHandler. PathHandlers are always evaluated before WebHandlers.
}

// Handle registers a named handler for a path and optional host. If path ends with
// a slash, it is used as prefix match, otherwise a full path match is required. If
// hostOpt is set, only requests to those host are handled by this handler.
func (s *serve) Handle(name string, hostMatch func(dns.Domain) bool, path string, fn http.Handler) {
	s.PathHandlers = append(s.PathHandlers, pathHandler{name, hostMatch, path, fn})
}

var (
	limiterConnectionrate = &ratelimit.Limiter{
		WindowLimits: []ratelimit.WindowLimit{
			{
				Window: time.Minute,
				Limits: [...]int64{1000, 3000, 9000},
			},
			{
				Window: time.Hour,
				Limits: [...]int64{5000, 15000, 45000},
			},
		},
	}
)

// ServeHTTP is the starting point for serving HTTP requests. It dispatches to the
// right pathHandler or WebHandler, and it generates access logs and tracks
// metrics.
func (s *serve) ServeHTTP(xw http.ResponseWriter, r *http.Request) {
	now := time.Now()
	// Rate limiting as early as possible.
	ipstr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		xlog.Debugx("split host:port client remoteaddr", err, mlog.Field("remoteaddr", r.RemoteAddr))
	} else if ip := net.ParseIP(ipstr); ip == nil {
		xlog.Debug("parsing ip for client remoteaddr", mlog.Field("remoteaddr", r.RemoteAddr))
	} else if !limiterConnectionrate.Add(ip, now, 1) {
		method := metricHTTPMethod(r.Method)
		proto := "http"
		if r.TLS != nil {
			proto = "https"
		}
		metricRequest.WithLabelValues("(ratelimited)", proto, method, "429").Observe(0)
		// No logging, that's just noise.

		http.Error(xw, "429 - too many auth attempts", http.StatusTooManyRequests)
		return
	}

	ctx := context.WithValue(r.Context(), mlog.CidKey, mox.Cid())
	r = r.WithContext(ctx)

	wf, ok := xw.(responseWriterFlusher)
	if !ok {
		http.Error(xw, "500 - internal server error - cannot access underlying connection"+recvid(r), http.StatusInternalServerError)
		return
	}

	nw := &loggingWriter{
		W:     wf,
		Start: now,
		R:     r,
	}
	defer nw.Done()

	// Cleanup path, removing ".." and ".". Keep any trailing slash.
	trailingPath := strings.HasSuffix(r.URL.Path, "/")
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}
	r.URL.Path = path.Clean(r.URL.Path)
	if r.URL.Path == "." {
		r.URL.Path = "/"
	}
	if trailingPath && !strings.HasSuffix(r.URL.Path, "/") {
		r.URL.Path += "/"
	}

	var dom dns.Domain
	host := r.Host
	nhost, _, err := net.SplitHostPort(host)
	if err == nil {
		host = nhost
	}
	// host could be an IP, some handles may match, not an error.
	dom, domErr := dns.ParseDomain(host)

	for _, h := range s.PathHandlers {
		if h.HostMatch != nil && (domErr != nil || !h.HostMatch(dom)) {
			continue
		}
		if r.URL.Path == h.Path || strings.HasSuffix(h.Path, "/") && strings.HasPrefix(r.URL.Path, h.Path) {
			nw.Handler = h.Name
			nw.Compress = true
			h.Handler.ServeHTTP(nw, r)
			return
		}
	}
	if s.Webserver && domErr == nil {
		if WebHandle(nw, r, dom) {
			return
		}
	}
	nw.Handler = "(nomatch)"
	http.NotFound(nw, r)
}

// Listen binds to sockets for HTTP listeners, including those required for ACME to
// generate TLS certificates. It stores the listeners so Serve can start serving them.
func Listen() {
	redirectToTrailingSlash := func(srv *serve, name, path string) {
		// Helpfully redirect user to version with ending slash.
		if path != "/" && strings.HasSuffix(path, "/") {
			handler := safeHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, path, http.StatusSeeOther)
			}))
			srv.Handle(name, nil, path[:len(path)-1], handler)
		}
	}

	// Initialize listeners in deterministic order for the same potential error
	// messages.
	names := maps.Keys(mox.Conf.Static.Listeners)
	sort.Strings(names)
	for _, name := range names {
		l := mox.Conf.Static.Listeners[name]

		portServe := map[int]*serve{}

		var ensureServe func(https bool, port int, kind string) *serve
		ensureServe = func(https bool, port int, kind string) *serve {
			s := portServe[port]
			if s == nil {
				s = &serve{nil, nil, nil, false}
				portServe[port] = s
			}
			s.Kinds = append(s.Kinds, kind)
			if https && l.TLS.ACME != "" {
				s.TLSConfig = l.TLS.ACMEConfig
			} else if https {
				s.TLSConfig = l.TLS.Config
				if l.TLS.ACME != "" {
					tlsport := config.Port(mox.Conf.Static.ACME[l.TLS.ACME].Port, 443)
					ensureServe(true, tlsport, "acme-tls-alpn-01")
				}
			}
			return s
		}

		if l.TLS != nil && l.TLS.ACME != "" && (l.SMTP.Enabled && !l.SMTP.NoSTARTTLS || l.Submissions.Enabled || l.IMAPS.Enabled) {
			port := config.Port(mox.Conf.Static.ACME[l.TLS.ACME].Port, 443)
			ensureServe(true, port, "acme-tls-alpn-01")
		}

		if l.AccountHTTP.Enabled {
			port := config.Port(l.AccountHTTP.Port, 80)
			path := "/"
			if l.AccountHTTP.Path != "" {
				path = l.AccountHTTP.Path
			}
			srv := ensureServe(false, port, "account-http at "+path)
			handler := safeHeaders(http.StripPrefix(path[:len(path)-1], http.HandlerFunc(webaccount.Handle)))
			srv.Handle("account", nil, path, handler)
			redirectToTrailingSlash(srv, "account", path)
		}
		if l.AccountHTTPS.Enabled {
			port := config.Port(l.AccountHTTPS.Port, 443)
			path := "/"
			if l.AccountHTTPS.Path != "" {
				path = l.AccountHTTPS.Path
			}
			srv := ensureServe(true, port, "account-https at "+path)
			handler := safeHeaders(http.StripPrefix(path[:len(path)-1], http.HandlerFunc(webaccount.Handle)))
			srv.Handle("account", nil, path, handler)
			redirectToTrailingSlash(srv, "account", path)
		}

		if l.AdminHTTP.Enabled {
			port := config.Port(l.AdminHTTP.Port, 80)
			path := "/admin/"
			if l.AdminHTTP.Path != "" {
				path = l.AdminHTTP.Path
			}
			srv := ensureServe(false, port, "admin-http at "+path)
			handler := safeHeaders(http.StripPrefix(path[:len(path)-1], http.HandlerFunc(webadmin.Handle)))
			srv.Handle("admin", nil, path, handler)
			redirectToTrailingSlash(srv, "admin", path)
		}
		if l.AdminHTTPS.Enabled {
			port := config.Port(l.AdminHTTPS.Port, 443)
			path := "/admin/"
			if l.AdminHTTPS.Path != "" {
				path = l.AdminHTTPS.Path
			}
			srv := ensureServe(true, port, "admin-https at "+path)
			handler := safeHeaders(http.StripPrefix(path[:len(path)-1], http.HandlerFunc(webadmin.Handle)))
			srv.Handle("admin", nil, path, handler)
			redirectToTrailingSlash(srv, "admin", path)
		}

		maxMsgSize := l.SMTPMaxMessageSize
		if maxMsgSize == 0 {
			maxMsgSize = config.DefaultMaxMsgSize
		}
		if l.WebmailHTTP.Enabled {
			port := config.Port(l.WebmailHTTP.Port, 80)
			path := "/webmail/"
			if l.WebmailHTTP.Path != "" {
				path = l.WebmailHTTP.Path
			}
			srv := ensureServe(false, port, "webmail-http at "+path)
			srv.Handle("webmail", nil, path, http.StripPrefix(path[:len(path)-1], http.HandlerFunc(webmail.Handler(maxMsgSize))))
			redirectToTrailingSlash(srv, "webmail", path)
		}
		if l.WebmailHTTPS.Enabled {
			port := config.Port(l.WebmailHTTPS.Port, 443)
			path := "/webmail/"
			if l.WebmailHTTPS.Path != "" {
				path = l.WebmailHTTPS.Path
			}
			srv := ensureServe(true, port, "webmail-https at "+path)
			srv.Handle("webmail", nil, path, http.StripPrefix(path[:len(path)-1], http.HandlerFunc(webmail.Handler(maxMsgSize))))
			redirectToTrailingSlash(srv, "webmail", path)
		}

		if l.MetricsHTTP.Enabled {
			port := config.Port(l.MetricsHTTP.Port, 8010)
			srv := ensureServe(false, port, "metrics-http")
			srv.Handle("metrics", nil, "/metrics", safeHeaders(promhttp.Handler()))
			srv.Handle("metrics", nil, "/", safeHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					http.NotFound(w, r)
					return
				} else if r.Method != "GET" {
					http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<html><body>see <a href="metrics">metrics</a></body></html>`)
			})))
		}
		if l.AutoconfigHTTPS.Enabled {
			port := config.Port(l.AutoconfigHTTPS.Port, 443)
			srv := ensureServe(!l.AutoconfigHTTPS.NonTLS, port, "autoconfig-https")
			autoconfigMatch := func(dom dns.Domain) bool {
				// Thunderbird requests an autodiscovery URL at the email address domain name, so
				// autoconfig prefix is optional.
				if strings.HasPrefix(dom.ASCII, "autoconfig.") {
					dom.ASCII = strings.TrimPrefix(dom.ASCII, "autoconfig.")
					dom.Unicode = strings.TrimPrefix(dom.Unicode, "autoconfig.")
				}
				// Autodiscovery uses a SRV record. It shouldn't point to a CNAME. So we directly
				// use the mail server's host name.
				if dom == mox.Conf.Static.HostnameDomain || dom == mox.Conf.Static.Listeners["public"].HostnameDomain {
					return true
				}
				_, ok := mox.Conf.Domain(dom)
				return ok
			}
			srv.Handle("autoconfig", autoconfigMatch, "/mail/config-v1.1.xml", safeHeaders(http.HandlerFunc(autoconfHandle)))
			srv.Handle("autodiscover", autoconfigMatch, "/autodiscover/autodiscover.xml", safeHeaders(http.HandlerFunc(autodiscoverHandle)))
			srv.Handle("mobileconfig", autoconfigMatch, "/profile.mobileconfig", safeHeaders(http.HandlerFunc(mobileconfigHandle)))
			srv.Handle("mobileconfigqrcodepng", autoconfigMatch, "/profile.mobileconfig.qrcode.png", safeHeaders(http.HandlerFunc(mobileconfigQRCodeHandle)))
		}
		if l.MTASTSHTTPS.Enabled {
			port := config.Port(l.MTASTSHTTPS.Port, 443)
			srv := ensureServe(!l.MTASTSHTTPS.NonTLS, port, "mtasts-https")
			mtastsMatch := func(dom dns.Domain) bool {
				// todo: may want to check this against the configured domains, could in theory be just a webserver.
				return strings.HasPrefix(dom.ASCII, "mta-sts.")
			}
			srv.Handle("mtasts", mtastsMatch, "/.well-known/mta-sts.txt", safeHeaders(http.HandlerFunc(mtastsPolicyHandle)))
		}
		if l.PprofHTTP.Enabled {
			// Importing net/http/pprof registers handlers on the default serve mux.
			port := config.Port(l.PprofHTTP.Port, 8011)
			if _, ok := portServe[port]; ok {
				xlog.Fatal("cannot serve pprof on same endpoint as other http services")
			}
			srv := &serve{[]string{"pprof-http"}, nil, nil, false}
			portServe[port] = srv
			srv.Handle("pprof", nil, "/", http.DefaultServeMux)
		}
		if l.WebserverHTTP.Enabled {
			port := config.Port(l.WebserverHTTP.Port, 80)
			srv := ensureServe(false, port, "webserver-http")
			srv.Webserver = true
		}
		if l.WebserverHTTPS.Enabled {
			port := config.Port(l.WebserverHTTPS.Port, 443)
			srv := ensureServe(true, port, "webserver-https")
			srv.Webserver = true
		}

		if l.TLS != nil && l.TLS.ACME != "" {
			m := mox.Conf.Static.ACME[l.TLS.ACME].Manager

			// If we are listening on port 80 for plain http, also register acme http-01
			// validation handler.
			if srv, ok := portServe[80]; ok && srv.TLSConfig == nil {
				srv.Kinds = append(srv.Kinds, "acme-http-01")
				srv.Handle("acme-http-01", nil, "/.well-known/acme-challenge/", m.Manager.HTTPHandler(nil))
			}

			hosts := map[dns.Domain]struct{}{
				mox.Conf.Static.HostnameDomain: {},
			}
			if l.HostnameDomain.ASCII != "" {
				hosts[l.HostnameDomain] = struct{}{}
			}
			// All domains are served on all listeners. Gather autoconfig hostnames to ensure
			// presence of TLS certificates for.
			for _, name := range mox.Conf.Domains() {
				if dom, err := dns.ParseDomain(name); err != nil {
					xlog.Errorx("parsing domain from config", err)
				} else if d, _ := mox.Conf.Domain(dom); d.DMARC != nil && d.DMARC.Domain != "" && d.DMARC.DNSDomain != dom {
					// Do not gather autoconfig name if this domain is configured to process reports
					// for domains hosted elsewhere.
					continue
				}

				autoconfdom, err := dns.ParseDomain("autoconfig." + name)
				if err != nil {
					xlog.Errorx("parsing domain from config for autoconfig", err)
				} else {
					hosts[autoconfdom] = struct{}{}
				}
			}

			ensureManagerHosts[m] = hosts
		}

		ports := maps.Keys(portServe)
		sort.Ints(ports)
		for _, port := range ports {
			srv := portServe[port]
			sort.Slice(srv.PathHandlers, func(i, j int) bool {
				a := srv.PathHandlers[i].Path
				b := srv.PathHandlers[j].Path
				if len(a) == len(b) {
					// For consistent order.
					return a < b
				}
				// Longest paths first.
				return len(a) > len(b)
			})
			for _, ip := range l.IPs {
				listen1(ip, port, srv.TLSConfig, name, srv.Kinds, srv)
			}
		}
	}
}

// functions to be launched in goroutine that will serve on a listener.
var servers []func()

// We'll explicitly ensure these TLS certs exist (e.g. are created with ACME)
// immediately after startup. We only do so for our explicit listener hostnames,
// not for mta-sts DNS records, it can be requested on demand (perhaps never). We
// do request autoconfig, otherwise clients may run into their timeouts waiting for
// the certificate to be given during the first https connection.
var ensureManagerHosts = map[*autotls.Manager]map[dns.Domain]struct{}{}

// listen prepares a listener, and adds it to "servers", to be launched (if not running as root) through Serve.
func listen1(ip string, port int, tlsConfig *tls.Config, name string, kinds []string, handler http.Handler) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	var protocol string
	var ln net.Listener
	var err error
	if tlsConfig == nil {
		protocol = "http"
		if os.Getuid() == 0 {
			xlog.Print("http listener", mlog.Field("name", name), mlog.Field("kinds", strings.Join(kinds, ",")), mlog.Field("address", addr))
		}
		ln, err = mox.Listen(mox.Network(ip), addr)
		if err != nil {
			xlog.Fatalx("http: listen", err, mlog.Field("addr", addr))
		}
	} else {
		protocol = "https"
		if os.Getuid() == 0 {
			xlog.Print("https listener", mlog.Field("name", name), mlog.Field("kinds", strings.Join(kinds, ",")), mlog.Field("address", addr))
		}
		ln, err = mox.Listen(mox.Network(ip), addr)
		if err != nil {
			xlog.Fatalx("https: listen", err, mlog.Field("addr", addr))
		}
		ln = tls.NewListener(ln, tlsConfig)
	}

	server := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       65 * time.Second, // Chrome closes connections after 60 seconds, firefox after 115 seconds.
		ErrorLog:          golog.New(mlog.ErrWriter(xlog.Fields(mlog.Field("pkg", "net/http")), mlog.LevelInfo, protocol+" error"), "", 0),
	}
	serve := func() {
		err := server.Serve(ln)
		xlog.Fatalx(protocol+": serve", err)
	}
	servers = append(servers, serve)
}

// Serve starts serving on the initialized listeners.
func Serve() {
	loadStaticGzipCache(mox.DataDirPath("tmp/httpstaticcompresscache"), 512*1024*1024)

	go webadmin.ManageAuthCache()
	go webaccount.ImportManage()

	for _, serve := range servers {
		go serve()
	}
	servers = nil

	go func() {
		time.Sleep(1 * time.Second)
		i := 0
		for m, hosts := range ensureManagerHosts {
			for host := range hosts {
				if i >= 10 {
					// Just in case someone adds quite some domains to their config. We don't want to
					// hit any ACME rate limits.
					return
				}
				if i > 0 {
					// Sleep just a little. We don't want to hammer our ACME provider, e.g. Let's Encrypt.
					time.Sleep(10 * time.Second)
				}
				i++

				hello := &tls.ClientHelloInfo{
					ServerName: host.ASCII,

					// Make us fetch an ECDSA P256 cert.
					// We add TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 to get around the ecDSA check in autocert.
					CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256},
					SupportedCurves:   []tls.CurveID{tls.CurveP256},
					SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
					SupportedVersions: []uint16{tls.VersionTLS13},
				}
				xlog.Print("ensuring certificate availability", mlog.Field("hostname", host))
				if _, err := m.Manager.GetCertificate(hello); err != nil {
					xlog.Errorx("requesting automatic certificate", err, mlog.Field("hostname", host))
				}
			}
		}
	}()
}
