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
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	_ "embed"
	_ "net/http/pprof"

	"golang.org/x/net/http2"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mjl-/mox/autotls"
	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/imapserver"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/ratelimit"
	"github.com/mjl-/mox/smtpserver"
	"github.com/mjl-/mox/webaccount"
	"github.com/mjl-/mox/webadmin"
	"github.com/mjl-/mox/webapisrv"
	"github.com/mjl-/mox/webmail"
)

var pkglog = mlog.New("http", nil)

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

// We serve a favicon when webaccount/webmail/webadmin/webapi for account-related
// domains. They are configured as "service handler", which have a lower priority
// than web handler. Admins can configure a custom /favicon.ico route to override
// the builtin favicon. In the future, we may want to make it easier to customize
// the favicon, possibly per client settings domain.
//
//go:embed favicon.ico
var faviconIco string
var faviconModTime = time.Now()

func init() {
	p, err := os.Executable()
	if err == nil {
		if st, err := os.Stat(p); err == nil {
			faviconModTime = st.ModTime()
		}
	}
}

func faviconHandle(w http.ResponseWriter, r *http.Request) {
	http.ServeContent(w, r, "favicon.ico", faviconModTime, strings.NewReader(faviconIco))
}

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
	Attrs                        []slog.Attr // Additional fields to log.
}

func (w *loggingWriter) AddAttr(a slog.Attr) {
	w.Attrs = append(w.Attrs, a)
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
	attrs := []slog.Attr{
		slog.String("httpaccess", ""),
		slog.String("handler", w.Handler),
		slog.String("method", method),
		slog.Any("url", w.R.URL),
		slog.String("host", w.R.Host),
		slog.Duration("duration", time.Since(w.Start)),
		slog.Int("statuscode", w.StatusCode),
		slog.String("proto", strings.ToLower(w.R.Proto)),
		slog.Any("remoteaddr", w.R.RemoteAddr),
		slog.String("tlsinfo", tlsinfo),
		slog.String("useragent", w.R.Header.Get("User-Agent")),
		slog.String("referer", w.R.Header.Get("Referer")),
	}
	if w.WebsocketRequest {
		attrs = append(attrs,
			slog.Bool("websocketrequest", true),
		)
	}
	if w.WebsocketResponse {
		attrs = append(attrs,
			slog.Bool("websocket", true),
			slog.Int64("sizetoclient", w.SizeToClient),
			slog.Int64("sizefromclient", w.SizeFromClient),
		)
	} else if w.UncompressedSize > 0 {
		attrs = append(attrs,
			slog.Int64("size", w.Size),
			slog.Int64("uncompressedsize", w.UncompressedSize),
		)
	} else {
		attrs = append(attrs,
			slog.Int64("size", w.Size),
		)
	}
	attrs = append(attrs, w.Attrs...)
	pkglog.WithContext(w.R.Context()).Debugx("http request", err, attrs...)
}

// Built-in handlers, e.g. mta-sts and autoconfig.
type pathHandler struct {
	Name      string                       // For logging/metrics.
	HostMatch func(host dns.IPDomain) bool // If not nil, called to see if domain of requests matches. Host can be zero value for invalid domain/ip.
	Path      string                       // Path to register, like on http.ServeMux.
	Handler   http.Handler
}

type serve struct {
	Kinds             []string // Type of handler and protocol (e.g. acme-tls-alpn-01, account-http, admin-https, imap-https, smtp-https).
	TLSConfig         *tls.Config
	NextProto         tlsNextProtoMap // For HTTP server, when we do submission/imap with ALPN over the HTTPS port.
	Favicon           bool
	Forwarded         bool // Requests are coming from a reverse proxy, we'll use X-Forwarded-For for the IP address to ratelimit.
	RateLimitDisabled bool // Don't apply ratelimiting.

	// SystemHandlers are for MTA-STS, autoconfig, ACME validation. They can't be
	// overridden by WebHandlers. WebHandlers are evaluated next, and the internal
	// service handlers from Listeners in mox.conf (for admin, account, webmail, webapi
	// interfaces) last. WebHandlers can also pass requests to the internal servers.
	// This order allows admins to serve other content on domains serving the mox.conf
	// internal services.
	SystemHandlers  []pathHandler // Sorted, longest first.
	Webserver       bool
	ServiceHandlers []pathHandler // Sorted, longest first.
}

// SystemHandle registers a named system handler for a path and optional host. If
// path ends with a slash, it is used as prefix match, otherwise a full path match
// is required. If hostOpt is set, only requests to those host are handled by this
// handler.
func (s *serve) SystemHandle(name string, hostMatch func(dns.IPDomain) bool, path string, fn http.Handler) {
	s.SystemHandlers = append(s.SystemHandlers, pathHandler{name, hostMatch, path, fn})
}

// Like SystemHandle, but for internal services "admin", "account", "webmail",
// "webapi" configured in the mox.conf Listener.
func (s *serve) ServiceHandle(name string, hostMatch func(dns.IPDomain) bool, path string, fn http.Handler) {
	s.ServiceHandlers = append(s.ServiceHandlers, pathHandler{name, hostMatch, path, fn})
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

	// Rate limiting as early as possible, if enabled.
	if !s.RateLimitDisabled {
		// If requests are coming from a reverse proxy, use the IP from X-Forwarded-For.
		// Otherwise the remote IP for this connection.
		var ipstr string
		if s.Forwarded {
			s := r.Header.Get("X-Forwarded-For")
			ipstr = strings.TrimSpace(strings.Split(s, ",")[0])
			if ipstr == "" {
				pkglog.Debug("ratelimit: no ip address in X-Forwarded-For header")
			}
		} else {
			var err error
			ipstr, _, err = net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				pkglog.Debugx("ratelimit: parsing remote address", err, slog.String("remoteaddr", r.RemoteAddr))
			}
		}
		ip := net.ParseIP(ipstr)
		if ip == nil && ipstr != "" {
			pkglog.Debug("ratelimit: invalid ip", slog.String("ip", ipstr))
		}
		if ip != nil && !limiterConnectionrate.Add(ip, now, 1) {
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

	host := r.Host
	nhost, _, err := net.SplitHostPort(host)
	if err == nil {
		host = nhost
	}
	ipdom := dns.IPDomain{IP: net.ParseIP(host)}
	if ipdom.IP == nil {
		dom, domErr := dns.ParseDomain(host)
		if domErr == nil {
			ipdom = dns.IPDomain{Domain: dom}
		}
	}

	handle := func(h pathHandler) bool {
		if h.HostMatch != nil && !h.HostMatch(ipdom) {
			return false
		}
		if r.URL.Path == h.Path || strings.HasSuffix(h.Path, "/") && strings.HasPrefix(r.URL.Path, h.Path) {
			nw.Handler = h.Name
			nw.Compress = true
			h.Handler.ServeHTTP(nw, r)
			return true
		}
		return false
	}

	for _, h := range s.SystemHandlers {
		if handle(h) {
			return
		}
	}
	if s.Webserver {
		if WebHandle(nw, r, ipdom) {
			return
		}
	}
	for _, h := range s.ServiceHandlers {
		if handle(h) {
			return
		}
	}
	nw.Handler = "(nomatch)"
	http.NotFound(nw, r)
}

func redirectToTrailingSlash(srv *serve, hostMatch func(dns.IPDomain) bool, name, path string) {
	// Helpfully redirect user to version with ending slash.
	if path != "/" && strings.HasSuffix(path, "/") {
		handler := mox.SafeHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, path, http.StatusSeeOther)
		}))
		srv.ServiceHandle(name, hostMatch, strings.TrimRight(path, "/"), handler)
	}
}

// Listen binds to sockets for HTTP listeners, including those required for ACME to
// generate TLS certificates. It stores the listeners so Serve can start serving them.
func Listen() {
	// Initialize listeners in deterministic order for the same potential error
	// messages.
	names := slices.Sorted(maps.Keys(mox.Conf.Static.Listeners))
	for _, name := range names {
		l := mox.Conf.Static.Listeners[name]
		portServe := portServes(name, l)

		ports := slices.Sorted(maps.Keys(portServe))
		for _, port := range ports {
			srv := portServe[port]
			for _, ip := range l.IPs {
				listen1(ip, port, srv.TLSConfig, name, srv.Kinds, srv, srv.NextProto)
			}
		}
	}
}

func portServes(name string, l config.Listener) map[int]*serve {
	portServe := map[int]*serve{}

	// For system/services, we serve on host localhost too, for ssh tunnel scenario's.
	localhost := dns.Domain{ASCII: "localhost"}

	ldom := l.HostnameDomain
	if l.Hostname == "" {
		ldom = mox.Conf.Static.HostnameDomain
	}
	listenerHostMatch := func(host dns.IPDomain) bool {
		if host.IsIP() {
			return true
		}
		return host.Domain == ldom || host.Domain == localhost
	}
	accountHostMatch := func(host dns.IPDomain) bool {
		if listenerHostMatch(host) {
			return true
		}
		return mox.Conf.IsClientSettingsDomain(host.Domain)
	}

	var ensureServe func(https, forwarded, noRateLimiting bool, port int, kind string, favicon bool) *serve
	ensureServe = func(https, forwarded, rateLimitDisabled bool, port int, kind string, favicon bool) *serve {
		s := portServe[port]
		if s == nil {
			s = &serve{nil, nil, tlsNextProtoMap{}, false, false, false, nil, false, nil}
			portServe[port] = s
		}
		s.Kinds = append(s.Kinds, kind)
		if favicon && !s.Favicon {
			s.ServiceHandle("favicon", accountHostMatch, "/favicon.ico", mox.SafeHeaders(http.HandlerFunc(faviconHandle)))
			s.Favicon = true
		}
		s.Forwarded = s.Forwarded || forwarded
		s.RateLimitDisabled = s.RateLimitDisabled || rateLimitDisabled

		// We clone TLS configs because we may modify it later on for this server, for
		// ALPN. And we need copies because multiple listeners on http.Server where the
		// config is used will try to modify it concurrently.
		if https && l.TLS.ACME != "" {
			s.TLSConfig = l.TLS.ACMEConfig.Clone()

			tlsport := config.Port(mox.Conf.Static.ACME[l.TLS.ACME].Port, 443)
			if portServe[tlsport] == nil || !slices.Contains(portServe[tlsport].Kinds, "acme-tls-alpn-01") {
				ensureServe(true, false, false, tlsport, "acme-tls-alpn-01", false)
			}
		} else if https {
			s.TLSConfig = l.TLS.Config.Clone()
		}
		return s
	}

	// If TLS with ACME is enabled on this plain HTTP port, and it hasn't been enabled
	// yet, add http-01 validation mechanism handler to server.
	ensureACMEHTTP01 := func(srv *serve) {
		if l.TLS != nil && l.TLS.ACME != "" && !slices.Contains(srv.Kinds, "acme-http-01") {
			m := mox.Conf.Static.ACME[l.TLS.ACME].Manager
			srv.Kinds = append(srv.Kinds, "acme-http-01")
			srv.SystemHandle("acme-http-01", nil, "/.well-known/acme-challenge/", m.Manager.HTTPHandler(nil))
		}
	}

	if l.TLS != nil && l.TLS.ACME != "" && (l.SMTP.Enabled && !l.SMTP.NoSTARTTLS || l.Submissions.Enabled || l.IMAPS.Enabled) {
		port := config.Port(mox.Conf.Static.ACME[l.TLS.ACME].Port, 443)
		ensureServe(true, false, false, port, "acme-tls-alpn-01", false)
	}
	if l.Submissions.Enabled && l.Submissions.EnabledOnHTTPS {
		s := ensureServe(true, false, false, 443, "smtp-https", false)
		hostname := mox.Conf.Static.HostnameDomain
		if l.Hostname != "" {
			hostname = l.HostnameDomain
		}

		maxMsgSize := l.SMTPMaxMessageSize
		if maxMsgSize == 0 {
			maxMsgSize = config.DefaultMaxMsgSize
		}
		requireTLS := !l.SMTP.NoRequireTLS

		s.NextProto["smtp"] = func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
			smtpserver.ServeTLSConn(name, hostname, conn, s.TLSConfig, true, true, maxMsgSize, requireTLS)
		}
	}
	if l.IMAPS.Enabled && l.IMAPS.EnabledOnHTTPS {
		s := ensureServe(true, false, false, 443, "imap-https", false)
		s.NextProto["imap"] = func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
			imapserver.ServeTLSConn(name, conn, s.TLSConfig)
		}
	}
	if l.AccountHTTP.Enabled {
		port := config.Port(l.AccountHTTP.Port, 80)
		path := "/"
		if l.AccountHTTP.Path != "" {
			path = l.AccountHTTP.Path
		}
		srv := ensureServe(false, l.AccountHTTP.Forwarded, false, port, "account-http at "+path, true)
		handler := mox.SafeHeaders(http.StripPrefix(strings.TrimRight(path, "/"), http.HandlerFunc(webaccount.Handler(path, l.AccountHTTP.Forwarded))))
		srv.ServiceHandle("account", accountHostMatch, path, handler)
		redirectToTrailingSlash(srv, accountHostMatch, "account", path)
		ensureACMEHTTP01(srv)
	}
	if l.AccountHTTPS.Enabled {
		port := config.Port(l.AccountHTTPS.Port, 443)
		path := "/"
		if l.AccountHTTPS.Path != "" {
			path = l.AccountHTTPS.Path
		}
		srv := ensureServe(true, l.AccountHTTPS.Forwarded, false, port, "account-https at "+path, true)
		handler := mox.SafeHeaders(http.StripPrefix(strings.TrimRight(path, "/"), http.HandlerFunc(webaccount.Handler(path, l.AccountHTTPS.Forwarded))))
		srv.ServiceHandle("account", accountHostMatch, path, handler)
		redirectToTrailingSlash(srv, accountHostMatch, "account", path)
	}

	if l.AdminHTTP.Enabled {
		port := config.Port(l.AdminHTTP.Port, 80)
		path := "/admin/"
		if l.AdminHTTP.Path != "" {
			path = l.AdminHTTP.Path
		}
		srv := ensureServe(false, l.AdminHTTP.Forwarded, false, port, "admin-http at "+path, true)
		handler := mox.SafeHeaders(http.StripPrefix(strings.TrimRight(path, "/"), http.HandlerFunc(webadmin.Handler(path, l.AdminHTTP.Forwarded))))
		srv.ServiceHandle("admin", listenerHostMatch, path, handler)
		redirectToTrailingSlash(srv, listenerHostMatch, "admin", path)
		ensureACMEHTTP01(srv)
	}
	if l.AdminHTTPS.Enabled {
		port := config.Port(l.AdminHTTPS.Port, 443)
		path := "/admin/"
		if l.AdminHTTPS.Path != "" {
			path = l.AdminHTTPS.Path
		}
		srv := ensureServe(true, l.AdminHTTPS.Forwarded, false, port, "admin-https at "+path, true)
		handler := mox.SafeHeaders(http.StripPrefix(strings.TrimRight(path, "/"), http.HandlerFunc(webadmin.Handler(path, l.AdminHTTPS.Forwarded))))
		srv.ServiceHandle("admin", listenerHostMatch, path, handler)
		redirectToTrailingSlash(srv, listenerHostMatch, "admin", path)
	}

	maxMsgSize := l.SMTPMaxMessageSize
	if maxMsgSize == 0 {
		maxMsgSize = config.DefaultMaxMsgSize
	}

	if l.WebAPIHTTP.Enabled {
		port := config.Port(l.WebAPIHTTP.Port, 80)
		path := "/webapi/"
		if l.WebAPIHTTP.Path != "" {
			path = l.WebAPIHTTP.Path
		}
		srv := ensureServe(false, l.WebAPIHTTP.Forwarded, false, port, "webapi-http at "+path, true)
		handler := mox.SafeHeaders(http.StripPrefix(strings.TrimRight(path, "/"), webapisrv.NewServer(maxMsgSize, path, l.WebAPIHTTP.Forwarded)))
		srv.ServiceHandle("webapi", accountHostMatch, path, handler)
		redirectToTrailingSlash(srv, accountHostMatch, "webapi", path)
		ensureACMEHTTP01(srv)
	}
	if l.WebAPIHTTPS.Enabled {
		port := config.Port(l.WebAPIHTTPS.Port, 443)
		path := "/webapi/"
		if l.WebAPIHTTPS.Path != "" {
			path = l.WebAPIHTTPS.Path
		}
		srv := ensureServe(true, l.WebAPIHTTPS.Forwarded, false, port, "webapi-https at "+path, true)
		handler := mox.SafeHeaders(http.StripPrefix(strings.TrimRight(path, "/"), webapisrv.NewServer(maxMsgSize, path, l.WebAPIHTTPS.Forwarded)))
		srv.ServiceHandle("webapi", accountHostMatch, path, handler)
		redirectToTrailingSlash(srv, accountHostMatch, "webapi", path)
	}

	if l.WebmailHTTP.Enabled {
		port := config.Port(l.WebmailHTTP.Port, 80)
		path := "/webmail/"
		if l.WebmailHTTP.Path != "" {
			path = l.WebmailHTTP.Path
		}
		srv := ensureServe(false, l.WebmailHTTP.Forwarded, false, port, "webmail-http at "+path, true)
		var accountPath string
		if l.AccountHTTP.Enabled {
			accountPath = "/"
			if l.AccountHTTP.Path != "" {
				accountPath = l.AccountHTTP.Path
			}
		}
		handler := http.StripPrefix(strings.TrimRight(path, "/"), http.HandlerFunc(webmail.Handler(maxMsgSize, path, l.WebmailHTTP.Forwarded, accountPath)))
		srv.ServiceHandle("webmail", accountHostMatch, path, handler)
		redirectToTrailingSlash(srv, accountHostMatch, "webmail", path)
		ensureACMEHTTP01(srv)
	}
	if l.WebmailHTTPS.Enabled {
		port := config.Port(l.WebmailHTTPS.Port, 443)
		path := "/webmail/"
		if l.WebmailHTTPS.Path != "" {
			path = l.WebmailHTTPS.Path
		}
		srv := ensureServe(true, l.WebmailHTTPS.Forwarded, false, port, "webmail-https at "+path, true)
		var accountPath string
		if l.AccountHTTPS.Enabled {
			accountPath = "/"
			if l.AccountHTTPS.Path != "" {
				accountPath = l.AccountHTTPS.Path
			}
		}
		handler := http.StripPrefix(strings.TrimRight(path, "/"), http.HandlerFunc(webmail.Handler(maxMsgSize, path, l.WebmailHTTPS.Forwarded, accountPath)))
		srv.ServiceHandle("webmail", accountHostMatch, path, handler)
		redirectToTrailingSlash(srv, accountHostMatch, "webmail", path)
	}

	if l.MetricsHTTP.Enabled {
		port := config.Port(l.MetricsHTTP.Port, 8010)
		srv := ensureServe(false, false, false, port, "metrics-http", false)
		srv.SystemHandle("metrics", nil, "/metrics", mox.SafeHeaders(promhttp.Handler()))
		srv.SystemHandle("metrics", nil, "/", mox.SafeHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		srv := ensureServe(!l.AutoconfigHTTPS.NonTLS, false, false, port, "autoconfig-https", false)
		if l.AutoconfigHTTPS.NonTLS {
			ensureACMEHTTP01(srv)
		}
		autoconfigMatch := func(ipdom dns.IPDomain) bool {
			dom := ipdom.Domain
			if dom.IsZero() {
				return false
			}
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
			dc, ok := mox.Conf.Domain(dom)
			return ok && !dc.ReportsOnly
		}
		srv.SystemHandle("autoconfig", autoconfigMatch, "/mail/config-v1.1.xml", mox.SafeHeaders(http.HandlerFunc(autoconfHandle)))
		srv.SystemHandle("autodiscover", autoconfigMatch, "/autodiscover/autodiscover.xml", mox.SafeHeaders(http.HandlerFunc(autodiscoverHandle)))
		srv.SystemHandle("mobileconfig", autoconfigMatch, "/profile.mobileconfig", mox.SafeHeaders(http.HandlerFunc(mobileconfigHandle)))
		srv.SystemHandle("mobileconfigqrcodepng", autoconfigMatch, "/profile.mobileconfig.qrcode.png", mox.SafeHeaders(http.HandlerFunc(mobileconfigQRCodeHandle)))
	}
	if l.MTASTSHTTPS.Enabled {
		port := config.Port(l.MTASTSHTTPS.Port, 443)
		srv := ensureServe(!l.MTASTSHTTPS.NonTLS, false, false, port, "mtasts-https", false)
		if l.MTASTSHTTPS.NonTLS {
			ensureACMEHTTP01(srv)
		}
		mtastsMatch := func(ipdom dns.IPDomain) bool {
			// todo: may want to check this against the configured domains, could in theory be just a webserver.
			dom := ipdom.Domain
			if dom.IsZero() {
				return false
			}
			return strings.HasPrefix(dom.ASCII, "mta-sts.")
		}
		srv.SystemHandle("mtasts", mtastsMatch, "/.well-known/mta-sts.txt", mox.SafeHeaders(http.HandlerFunc(mtastsPolicyHandle)))
	}
	if l.PprofHTTP.Enabled {
		// Importing net/http/pprof registers handlers on the default serve mux.
		port := config.Port(l.PprofHTTP.Port, 8011)
		if _, ok := portServe[port]; ok {
			pkglog.Fatal("cannot serve pprof on same endpoint as other http services")
		}
		srv := &serve{[]string{"pprof-http"}, nil, nil, false, false, false, nil, false, nil}
		portServe[port] = srv
		srv.SystemHandle("pprof", nil, "/", http.DefaultServeMux)
	}
	if l.WebserverHTTP.Enabled {
		port := config.Port(l.WebserverHTTP.Port, 80)
		srv := ensureServe(false, false, l.WebserverHTTP.RateLimitDisabled, port, "webserver-http", false)
		srv.Webserver = true
		ensureACMEHTTP01(srv)
	}
	if l.WebserverHTTPS.Enabled {
		port := config.Port(l.WebserverHTTPS.Port, 443)
		srv := ensureServe(true, false, l.WebserverHTTPS.RateLimitDisabled, port, "webserver-https", false)
		srv.Webserver = true
	}

	if l.TLS != nil && l.TLS.ACME != "" {
		m := mox.Conf.Static.ACME[l.TLS.ACME].Manager
		if ensureManagerHosts[m] == nil {
			ensureManagerHosts[m] = map[dns.Domain]struct{}{}
		}
		hosts := ensureManagerHosts[m]
		hosts[mox.Conf.Static.HostnameDomain] = struct{}{}

		if l.HostnameDomain.ASCII != "" {
			hosts[l.HostnameDomain] = struct{}{}
		}

		// All domains are served on all listeners. Gather autoconfig hostnames to ensure
		// presence of TLS certificates. Fetching a certificate on-demand may be too slow
		// for the timeouts of clients doing autoconfig.

		if l.AutoconfigHTTPS.Enabled && !l.AutoconfigHTTPS.NonTLS {
			for _, name := range mox.Conf.Domains() {
				if dom, err := dns.ParseDomain(name); err != nil {
					pkglog.Errorx("parsing domain from config", err)
				} else if d, _ := mox.Conf.Domain(dom); d.ReportsOnly || d.Disabled {
					// Do not gather autoconfig name if we aren't accepting email for this domain or when it is disabled.
					continue
				}

				autoconfdom, err := dns.ParseDomain("autoconfig." + name)
				if err != nil {
					pkglog.Errorx("parsing domain from config for autoconfig", err)
				} else {
					hosts[autoconfdom] = struct{}{}
				}
			}
		}
	}

	if s := portServe[443]; s != nil && s.TLSConfig != nil && len(s.NextProto) > 0 {
		s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, slices.Collect(maps.Keys(s.NextProto))...)
	}

	for _, srv := range portServe {
		sortPathHandlers(srv.SystemHandlers)
		sortPathHandlers(srv.ServiceHandlers)
	}

	return portServe
}

func sortPathHandlers(l []pathHandler) {
	sort.Slice(l, func(i, j int) bool {
		a := l[i].Path
		b := l[j].Path
		if len(a) == len(b) {
			// For consistent order.
			return a < b
		}
		// Longest paths first.
		return len(a) > len(b)
	})
}

// functions to be launched in goroutine that will serve on a listener.
var servers []func()

// We'll explicitly ensure these TLS certs exist (e.g. are created with ACME)
// immediately after startup. We only do so for our explicit listener hostnames,
// not for mta-sts DNS records, it can be requested on demand (perhaps never). We
// do request autoconfig, otherwise clients may run into their timeouts waiting for
// the certificate to be given during the first https connection.
var ensureManagerHosts = map[*autotls.Manager]map[dns.Domain]struct{}{}

type tlsNextProtoMap = map[string]func(*http.Server, *tls.Conn, http.Handler)

// listen prepares a listener, and adds it to "servers", to be launched (if not running as root) through Serve.
func listen1(ip string, port int, tlsConfig *tls.Config, name string, kinds []string, handler http.Handler, nextProto tlsNextProtoMap) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	var protocol string
	var ln net.Listener
	var err error
	if tlsConfig == nil {
		protocol = "http"
		if os.Getuid() == 0 {
			pkglog.Print("http listener",
				slog.String("name", name),
				slog.String("kinds", strings.Join(kinds, ",")),
				slog.String("address", addr))
		}
		ln, err = mox.Listen(mox.Network(ip), addr)
		if err != nil {
			pkglog.Fatalx("http: listen", err, slog.Any("addr", addr))
		}
	} else {
		protocol = "https"
		if os.Getuid() == 0 {
			pkglog.Print("https listener",
				slog.String("name", name),
				slog.String("kinds", strings.Join(kinds, ",")),
				slog.String("address", addr))
		}
		ln, err = mox.Listen(mox.Network(ip), addr)
		if err != nil {
			pkglog.Fatalx("https: listen", err, slog.String("addr", addr))
		}
		ln = tls.NewListener(ln, tlsConfig)
	}

	server := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       65 * time.Second, // Chrome closes connections after 60 seconds, firefox after 115 seconds.
		ErrorLog:          golog.New(mlog.LogWriter(pkglog.With(slog.String("pkg", "net/http")), slog.LevelInfo, protocol+" error"), "", 0),
		TLSNextProto:      nextProto,
	}
	// By default, the Go 1.6 and above http.Server includes support for HTTP2.
	// However, HTTP2 is negotiated via ALPN. Because we are configuring
	// TLSNextProto above, we have to explicitly enable HTTP2 by importing http2
	// and calling ConfigureServer.
	err = http2.ConfigureServer(server, nil)
	if err != nil {
		pkglog.Fatalx("https: unable to configure http2", err)
	}
	serve := func() {
		err := server.Serve(ln)
		pkglog.Fatalx(protocol+": serve", err)
	}
	servers = append(servers, serve)
}

// Serve starts serving on the initialized listeners.
func Serve() {
	loadStaticGzipCache(mox.DataDirPath("tmp/httpstaticcompresscache"), 512*1024*1024)

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
				// Check if certificate is already available. If so, we don't print as much after a
				// restart, and finish more quickly if only a few certificates are missing/old.
				if avail, err := m.CertAvailable(mox.Shutdown, pkglog, host); err != nil {
					pkglog.Errorx("checking acme certificate availability", err, slog.Any("host", host))
				} else if avail {
					continue
				}

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
				pkglog.Print("ensuring certificate availability", slog.Any("hostname", host))
				if _, err := m.Manager.GetCertificate(hello); err != nil {
					pkglog.Errorx("requesting automatic certificate", err, slog.Any("hostname", host))
				}
			}
		}
	}()
}
