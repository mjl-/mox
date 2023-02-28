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

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/ratelimit"
)

var xlog = mlog.New("http")

var metricHTTPServer = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "mox_httpserver_request_duration_seconds",
		Help:    "HTTP(s) server request with handler name, protocol, method, result codes, and duration in seconds.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30, 60, 120},
	},
	[]string{
		"handler", // Name from webhandler, can be empty.
		"proto",   // "http" or "https"
		"method",  // "(unknown)" and otherwise only common verbs
		"code",
	},
)

// http.ResponseWriter that writes access log and tracks metrics at end of response.
type loggingWriter struct {
	W     http.ResponseWriter // Calls are forwarded.
	Start time.Time
	R     *http.Request

	Handler string // Set by router.

	// Set by handlers.
	Code     int
	Size     int64
	WriteErr error
}

func (w *loggingWriter) Header() http.Header {
	return w.W.Header()
}

func (w *loggingWriter) Write(buf []byte) (int, error) {
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
	if w.Code == 0 {
		w.Code = statusCode
	}
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
	metricHTTPServer.WithLabelValues(w.Handler, proto, method, fmt.Sprintf("%d", w.Code)).Observe(float64(time.Since(w.Start)) / float64(time.Second))

	tlsinfo := "plain"
	if w.R.TLS != nil {
		if v, ok := tlsVersions[w.R.TLS.Version]; ok {
			tlsinfo = v
		} else {
			tlsinfo = "(other)"
		}
	}
	xlog.WithContext(w.R.Context()).Debugx("http request", w.WriteErr, mlog.Field("httpaccess", ""), mlog.Field("handler", w.Handler), mlog.Field("url", w.R.URL), mlog.Field("host", w.R.Host), mlog.Field("duration", time.Since(w.Start)), mlog.Field("size", w.Size), mlog.Field("statuscode", w.Code), mlog.Field("proto", strings.ToLower(w.R.Proto)), mlog.Field("remoteaddr", w.R.RemoteAddr), mlog.Field("tlsinfo", tlsinfo))
}

// Set some http headers that should prevent potential abuse. Better safe than sorry.
func safeHeaders(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "deny")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:")
		h.Set("Referrer-Policy", "same-origin")
		fn(w, r)
	}
}

// Built-in handlers, e.g. mta-sts and autoconfig.
type pathHandler struct {
	Name string // For logging/metrics.
	Path string // Path to register, like on http.ServeMux.
	Fn   http.HandlerFunc
}
type serve struct {
	Kinds        []string // Type of handler and protocol (http/https).
	TLSConfig    *tls.Config
	PathHandlers []pathHandler // Sorted, longest first.
	Webserver    bool          // Whether serving WebHandler. PathHandlers are always evaluated before WebHandlers.
}

// HandleFunc registers a named handler for a path. If path ends with a slash, it
// is used as prefix match, otherwise a full path match is required.
func (s *serve) HandleFunc(name, path string, fn http.HandlerFunc) {
	s.PathHandlers = append(s.PathHandlers, pathHandler{name, path, fn})
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
		metricHTTPServer.WithLabelValues("(ratelimited)", proto, method, "429").Observe(0)
		// No logging, that's just noise.

		http.Error(xw, "http 429 - too many auth attempts", http.StatusTooManyRequests)
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

	for _, h := range s.PathHandlers {
		if r.URL.Path == h.Path || strings.HasSuffix(h.Path, "/") && strings.HasPrefix(r.URL.Path, h.Path) {
			nw.Handler = h.Name
			h.Fn(nw, r)
			return
		}
	}
	if s.Webserver {
		if WebHandle(nw, r) {
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
			ensureServe(true, port, "acme-tls-alpn01")
		}

		if l.AccountHTTP.Enabled {
			port := config.Port(l.AccountHTTP.Port, 80)
			srv := ensureServe(false, port, "account-http")
			srv.HandleFunc("account", "/", safeHeaders(accountHandle))
		}
		if l.AccountHTTPS.Enabled {
			port := config.Port(l.AccountHTTPS.Port, 443)
			srv := ensureServe(true, port, "account-https")
			srv.HandleFunc("account", "/", safeHeaders(accountHandle))
		}

		if l.AdminHTTP.Enabled {
			port := config.Port(l.AdminHTTP.Port, 80)
			srv := ensureServe(false, port, "admin-http")
			if !l.AccountHTTP.Enabled {
				srv.HandleFunc("admin", "/", safeHeaders(adminIndex))
			}
			srv.HandleFunc("admin", "/admin/", safeHeaders(adminHandle))
		}
		if l.AdminHTTPS.Enabled {
			port := config.Port(l.AdminHTTPS.Port, 443)
			srv := ensureServe(true, port, "admin-https")
			if !l.AccountHTTPS.Enabled {
				srv.HandleFunc("admin", "/", safeHeaders(adminIndex))
			}
			srv.HandleFunc("admin", "/admin/", safeHeaders(adminHandle))
		}
		if l.MetricsHTTP.Enabled {
			port := config.Port(l.MetricsHTTP.Port, 8010)
			srv := ensureServe(false, port, "metrics-http")
			srv.HandleFunc("metrics", "/metrics", safeHeaders(promhttp.Handler().ServeHTTP))
			srv.HandleFunc("metrics", "/", safeHeaders(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					http.NotFound(w, r)
					return
				} else if r.Method != "GET" {
					http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<html><body>see <a href="/metrics">/metrics</a></body></html>`)
			}))
		}
		if l.AutoconfigHTTPS.Enabled {
			port := config.Port(l.AutoconfigHTTPS.Port, 443)
			srv := ensureServe(!l.AutoconfigHTTPS.NonTLS, port, "autoconfig-https")
			srv.HandleFunc("autoconfig", "/mail/config-v1.1.xml", safeHeaders(autoconfHandle(l)))
			srv.HandleFunc("autodiscover", "/autodiscover/autodiscover.xml", safeHeaders(autodiscoverHandle(l)))
		}
		if l.MTASTSHTTPS.Enabled {
			port := config.Port(l.MTASTSHTTPS.Port, 443)
			srv := ensureServe(!l.AutoconfigHTTPS.NonTLS, port, "mtasts-https")
			srv.HandleFunc("mtasts", "/.well-known/mta-sts.txt", safeHeaders(mtastsPolicyHandle))
		}
		if l.PprofHTTP.Enabled {
			// Importing net/http/pprof registers handlers on the default serve mux.
			port := config.Port(l.PprofHTTP.Port, 8011)
			if _, ok := portServe[port]; ok {
				xlog.Fatal("cannot serve pprof on same endpoint as other http services")
			}
			srv := &serve{[]string{"pprof-http"}, nil, nil, false}
			portServe[port] = srv
			srv.HandleFunc("pprof", "/", http.DefaultServeMux.ServeHTTP)
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

		// We'll explicitly ensure these TLS certs exist (e.g. are created with ACME)
		// immediately after startup. We only do so for our explicitly hostnames, not for
		// autoconfig or mta-sts DNS records, they can be requested on demand (perhaps
		// never).
		ensureHosts := map[dns.Domain]struct{}{}

		if l.TLS != nil && l.TLS.ACME != "" {
			m := mox.Conf.Static.ACME[l.TLS.ACME].Manager

			ensureHosts[mox.Conf.Static.HostnameDomain] = struct{}{}
			if l.HostnameDomain.ASCII != "" {
				ensureHosts[l.HostnameDomain] = struct{}{}
			}

			go func() {
				// Just in case someone adds quite some domains to their config. We don't want to
				// hit any ACME rate limits.
				if len(ensureHosts) > 10 {
					return
				}

				time.Sleep(1 * time.Second)
				i := 0
				for hostname := range ensureHosts {
					if i > 0 {
						// Sleep just a little. We don't want to hammer our ACME provider, e.g. Let's Encrypt.
						time.Sleep(10 * time.Second)
					}
					i++

					hello := &tls.ClientHelloInfo{
						ServerName: hostname.ASCII,

						// Make us fetch an ECDSA P256 cert.
						// We add TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 to get around the ecDSA check in autocert.
						CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256},
						SupportedCurves:   []tls.CurveID{tls.CurveP256},
						SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
						SupportedVersions: []uint16{tls.VersionTLS13},
					}
					xlog.Print("ensuring certificate availability", mlog.Field("hostname", hostname))
					if _, err := m.Manager.GetCertificate(hello); err != nil {
						xlog.Errorx("requesting automatic certificate", err, mlog.Field("hostname", hostname))
					}
				}
			}()
		}

		for port, srv := range portServe {
			for _, ip := range l.IPs {
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
				listen1(ip, port, srv.TLSConfig, name, srv.Kinds, srv)
			}
		}
	}
}

// Only used when the account page is not active on the same listener.
func adminIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// functions to be launched in goroutine that will serve on a listener.
var servers []func()

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
		Handler:   handler,
		TLSConfig: tlsConfig,
		ErrorLog:  golog.New(mlog.ErrWriter(xlog.Fields(mlog.Field("pkg", "net/http")), mlog.LevelInfo, protocol+" error"), "", 0),
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
}
