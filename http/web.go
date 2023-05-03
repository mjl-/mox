// Package http provides HTTP listeners/servers, for
// autoconfiguration/autodiscovery, the account and admin web interface and
// MTA-STS policies.
package http

import (
	"context"
	"crypto/tls"
	"fmt"
	golog "log"
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	_ "net/http/pprof"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mjl-/mox/autotls"
	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/ratelimit"
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
			"proto",   // "http" or "https"
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
			"proto",   // "http" or "https"
			"method",  // "(unknown)" and otherwise only common verbs
			"code",
		},
	)
)

// todo: automatic gzip on responses, if client supports it, content is not already compressed. in case of static file only if it isn't too large. skip for certain response content-types (image/*, video/*), or file extensions if there is no identifying content-type. if cpu load isn't too high. if first N kb look compressible and come in quickly enough after first byte (e.g. within 100ms). always flush after 100ms to prevent stalled real-time connections.

// http.ResponseWriter that writes access log and tracks metrics at end of response.
type loggingWriter struct {
	W     http.ResponseWriter // Calls are forwarded.
	Start time.Time
	R     *http.Request

	Handler string // Set by router.

	// Set by handlers.
	StatusCode int
	Size       int64
	WriteErr   error
}

func (w *loggingWriter) Header() http.Header {
	return w.W.Header()
}

func (w *loggingWriter) setStatusCode(statusCode int) {
	if w.StatusCode != 0 {
		return
	}

	w.StatusCode = statusCode
	method := metricHTTPMethod(w.R.Method)
	proto := "http"
	if w.R.TLS != nil {
		proto = "https"
	}
	metricRequest.WithLabelValues(w.Handler, proto, method, fmt.Sprintf("%d", w.StatusCode)).Observe(float64(time.Since(w.Start)) / float64(time.Second))
}

func (w *loggingWriter) Write(buf []byte) (int, error) {
	if w.Size == 0 {
		w.setStatusCode(http.StatusOK)
	}

	n, err := w.W.Write(buf)
	if n > 0 {
		w.Size += int64(n)
	}
	if err != nil && w.WriteErr == nil {
		w.WriteErr = err
	}
	return n, err
}

func (w *loggingWriter) WriteHeader(statusCode int) {
	w.setStatusCode(statusCode)
	w.W.WriteHeader(statusCode)
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

func (w *loggingWriter) Done() {
	method := metricHTTPMethod(w.R.Method)
	proto := "http"
	if w.R.TLS != nil {
		proto = "https"
	}
	metricResponse.WithLabelValues(w.Handler, proto, method, fmt.Sprintf("%d", w.StatusCode)).Observe(float64(time.Since(w.Start)) / float64(time.Second))

	tlsinfo := "plain"
	if w.R.TLS != nil {
		if v, ok := tlsVersions[w.R.TLS.Version]; ok {
			tlsinfo = v
		} else {
			tlsinfo = "(other)"
		}
	}
	err := w.WriteErr
	if err == nil {
		err = w.R.Context().Err()
	}
	xlog.WithContext(w.R.Context()).Debugx("http request", err,
		mlog.Field("httpaccess", ""),
		mlog.Field("handler", w.Handler),
		mlog.Field("method", method),
		mlog.Field("url", w.R.URL),
		mlog.Field("host", w.R.Host),
		mlog.Field("duration", time.Since(w.Start)),
		mlog.Field("size", w.Size),
		mlog.Field("statuscode", w.StatusCode),
		mlog.Field("proto", strings.ToLower(w.R.Proto)),
		mlog.Field("remoteaddr", w.R.RemoteAddr),
		mlog.Field("tlsinfo", tlsinfo),
		mlog.Field("useragent", w.R.Header.Get("User-Agent")),
		mlog.Field("referrr", w.R.Header.Get("Referrer")),
	)
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

	nw := &loggingWriter{
		W:     xw,
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
	for name, l := range mox.Conf.Static.Listeners {
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
			handler := safeHeaders(http.StripPrefix(path[:len(path)-1], http.HandlerFunc(accountHandle)))
			srv.Handle("account", nil, path, handler)
		}
		if l.AccountHTTPS.Enabled {
			port := config.Port(l.AccountHTTPS.Port, 443)
			path := "/"
			if l.AccountHTTPS.Path != "" {
				path = l.AccountHTTPS.Path
			}
			srv := ensureServe(true, port, "account-https at "+path)
			handler := safeHeaders(http.StripPrefix(path[:len(path)-1], http.HandlerFunc(accountHandle)))
			srv.Handle("account", nil, path, handler)
		}

		if l.AdminHTTP.Enabled {
			port := config.Port(l.AdminHTTP.Port, 80)
			path := "/admin/"
			if l.AdminHTTP.Path != "" {
				path = l.AdminHTTP.Path
			}
			srv := ensureServe(false, port, "admin-http at "+path)
			handler := safeHeaders(http.StripPrefix(path[:len(path)-1], http.HandlerFunc(adminHandle)))
			srv.Handle("admin", nil, path, handler)
		}
		if l.AdminHTTPS.Enabled {
			port := config.Port(l.AdminHTTPS.Port, 443)
			path := "/admin/"
			if l.AdminHTTPS.Path != "" {
				path = l.AdminHTTPS.Path
			}
			srv := ensureServe(true, port, "admin-https at "+path)
			handler := safeHeaders(http.StripPrefix(path[:len(path)-1], http.HandlerFunc(adminHandle)))
			srv.Handle("admin", nil, path, handler)
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
				fmt.Fprint(w, `<html><body>see <a href="/metrics">/metrics</a></body></html>`)
			})))
		}
		if l.AutoconfigHTTPS.Enabled {
			port := config.Port(l.AutoconfigHTTPS.Port, 443)
			srv := ensureServe(!l.AutoconfigHTTPS.NonTLS, port, "autoconfig-https")
			autoconfigMatch := func(dom dns.Domain) bool {
				// todo: may want to check this against the configured domains, could in theory be just a webserver.
				return strings.HasPrefix(dom.ASCII, "autoconfig.")
			}
			srv.Handle("autoconfig", autoconfigMatch, "/mail/config-v1.1.xml", safeHeaders(http.HandlerFunc(autoconfHandle)))
			srv.Handle("autodiscover", autoconfigMatch, "/autodiscover/autodiscover.xml", safeHeaders(http.HandlerFunc(autodiscoverHandle)))
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
			// All domains are served on all listeners.
			for _, name := range mox.Conf.Domains() {
				dom, err := dns.ParseDomain("autoconfig." + name)
				if err != nil {
					xlog.Errorx("parsing domain from config for autoconfig", err)
				} else {
					hosts[dom] = struct{}{}
				}
			}

			ensureManagerHosts[m] = hosts
		}

		for port, srv := range portServe {
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
	go manageAuthCache()
	go importManage()

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
