// Package http provides HTTP listeners/servers, for
// autoconfiguration/autodiscovery, the account and admin web interface and
// MTA-STS policies.
package http

import (
	"crypto/tls"
	"fmt"
	golog "log"
	"net"
	"net/http"
	"strings"
	"time"

	_ "net/http/pprof"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

var xlog = mlog.New("http")

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

// ListenAndServe starts listeners for HTTP, including those required for ACME to
// generate TLS certificates.
func ListenAndServe() {
	type serve struct {
		kinds     []string
		tlsConfig *tls.Config
		mux       *http.ServeMux
	}

	for name, l := range mox.Conf.Static.Listeners {
		portServe := map[int]serve{}

		var ensureServe func(https bool, port int, kind string) serve
		ensureServe = func(https bool, port int, kind string) serve {
			s, ok := portServe[port]
			if !ok {
				s = serve{nil, nil, &http.ServeMux{}}
			}
			s.kinds = append(s.kinds, kind)
			if https && port == 443 && l.TLS.ACME != "" {
				s.tlsConfig = l.TLS.ACMEConfig
			} else if https {
				s.tlsConfig = l.TLS.Config
				if l.TLS.ACME != "" {
					ensureServe(true, 443, "acme-tls-alpn-01")
				}
			}
			portServe[port] = s
			return s
		}

		if l.SMTP.Enabled && !l.SMTP.NoSTARTTLS || l.Submissions.Enabled || l.IMAPS.Enabled {
			ensureServe(true, 443, "acme-tls-alpn01")
		}

		if l.AccountHTTP.Enabled {
			srv := ensureServe(false, config.Port(l.AccountHTTP.Port, 80), "account-http")
			srv.mux.HandleFunc("/", safeHeaders(accountHandle))
		}
		if l.AccountHTTPS.Enabled {
			srv := ensureServe(true, config.Port(l.AccountHTTP.Port, 443), "account-https")
			srv.mux.HandleFunc("/", safeHeaders(accountHandle))
		}

		if l.AdminHTTP.Enabled {
			srv := ensureServe(false, config.Port(l.AdminHTTP.Port, 80), "admin-http")
			if !l.AccountHTTP.Enabled {
				srv.mux.HandleFunc("/", safeHeaders(adminIndex))
			}
			srv.mux.HandleFunc("/admin/", safeHeaders(adminHandle))
		}
		if l.AdminHTTPS.Enabled {
			srv := ensureServe(true, config.Port(l.AdminHTTPS.Port, 443), "admin-https")
			if !l.AccountHTTP.Enabled {
				srv.mux.HandleFunc("/", safeHeaders(adminIndex))
			}
			srv.mux.HandleFunc("/admin/", safeHeaders(adminHandle))
		}
		if l.MetricsHTTP.Enabled {
			srv := ensureServe(false, config.Port(l.MetricsHTTP.Port, 8010), "metrics-http")
			srv.mux.Handle("/metrics", safeHeaders(promhttp.Handler().ServeHTTP))
			srv.mux.HandleFunc("/", safeHeaders(func(w http.ResponseWriter, r *http.Request) {
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
			srv := ensureServe(true, 443, "autoconfig-https")
			srv.mux.HandleFunc("/mail/config-v1.1.xml", safeHeaders(autoconfHandle(l)))
			srv.mux.HandleFunc("/autodiscover/autodiscover.xml", safeHeaders(autodiscoverHandle(l)))
		}
		if l.MTASTSHTTPS.Enabled {
			srv := ensureServe(true, 443, "mtasts-https")
			srv.mux.HandleFunc("/.well-known/mta-sts.txt", safeHeaders(mtastsPolicyHandle))
		}
		if l.PprofHTTP.Enabled {
			// Importing net/http/pprof registers handlers on the default serve mux.
			port := config.Port(l.PprofHTTP.Port, 8011)
			if _, ok := portServe[port]; ok {
				xlog.Fatal("cannot serve pprof on same endpoint as other http services")
			}
			portServe[port] = serve{[]string{"pprof-http"}, nil, http.DefaultServeMux}
		}

		// We'll explicitly ensure these TLS certs exist (e.g. are created with ACME)
		// immediately after startup. We only do so for our explicitly hostnames, not for
		// autoconfig or mta-sts DNS records, they can be requested on demand (perhaps
		// never).
		ensureHosts := map[dns.Domain]struct{}{}

		if l.TLS != nil && l.TLS.ACME != "" {
			m := mox.Conf.Static.ACME[l.TLS.ACME].Manager

			m.AllowHostname(mox.Conf.Static.HostnameDomain)
			ensureHosts[mox.Conf.Static.HostnameDomain] = struct{}{}
			if l.HostnameDomain.ASCII != "" {
				m.AllowHostname(l.HostnameDomain)
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
				listenAndServe(ip, port, srv.tlsConfig, name, srv.kinds, srv.mux)
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

func listenAndServe(ip string, port int, tlsConfig *tls.Config, name string, kinds []string, mux *http.ServeMux) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	var protocol string
	var ln net.Listener
	var err error
	if tlsConfig == nil {
		protocol = "http"
		xlog.Print("http listener", mlog.Field("name", name), mlog.Field("kinds", strings.Join(kinds, ",")), mlog.Field("address", addr))
		ln, err = net.Listen(mox.Network(ip), addr)
		if err != nil {
			xlog.Fatalx("http: listen"+mox.LinuxSetcapHint(err), err, mlog.Field("addr", addr))
		}
	} else {
		protocol = "https"
		xlog.Print("https listener", mlog.Field("name", name), mlog.Field("kinds", strings.Join(kinds, ",")), mlog.Field("address", addr))
		ln, err = tls.Listen(mox.Network(ip), addr, tlsConfig)
		if err != nil {
			xlog.Fatalx("https: listen"+mox.LinuxSetcapHint(err), err, mlog.Field("addr", addr))
		}
	}

	server := &http.Server{
		Handler:   mux,
		TLSConfig: tlsConfig,
		ErrorLog:  golog.New(mlog.ErrWriter(xlog.Fields(mlog.Field("pkg", "net/http")), mlog.LevelInfo, protocol+" error"), "", 0),
	}
	go func() {
		err := server.Serve(ln)
		xlog.Fatalx(protocol+": serve", err)
	}()
}
