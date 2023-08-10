package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/mox/mlog"
)

// todo future: replace with a dnssec capable resolver
// todo future: change to interface that is closer to DNS. 1. expose nxdomain vs success with zero entries: nxdomain means the name does not exist for any dns resource record type, success with zero records means the name exists for other types than the requested type; 2. add ability to not follow cname records when resolving. the net resolver automatically follows cnames for LookupHost, LookupIP, LookupIPAddr. when resolving names found in mx records, we explicitly must not follow cnames. that seems impossible at the moment. 3. when looking up a cname, actually lookup the record? "net" LookupCNAME will return the requested name with no error if there is no CNAME record. because it returns the canonical name.
// todo future: add option to not use anything in the cache, for the admin pages where you check the latest DNS settings, ignoring old cached info.

var xlog = mlog.New("dns")

var (
	metricLookup = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_dns_lookup_duration_seconds",
			Help:    "DNS lookups.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30},
		},
		[]string{
			"pkg",
			"type",   // Lower-case Resolver method name without leading Lookup.
			"result", // ok, nxdomain, temporary, timeout, canceled, error
		},
	)
)

// Resolver is the interface strict resolver implements.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error) // Always returns absolute names, with trailing dot.
	LookupCNAME(ctx context.Context, host string) (string, error)  // NOTE: returns an error if no CNAME record is present.
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupPort(ctx context.Context, network, service string) (port int, err error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// WithPackage sets Pkg on resolver if it is a StrictResolve and does not have a package set yet.
func WithPackage(resolver Resolver, name string) Resolver {
	r, ok := resolver.(StrictResolver)
	if ok && r.Pkg == "" {
		nr := r
		r.Pkg = name
		return nr
	}
	return resolver
}

// StrictResolver is a net.Resolver that enforces that DNS names end with a dot,
// preventing "search"-relative lookups.
type StrictResolver struct {
	Pkg      string        // Name of subsystem that is making DNS requests, for metrics.
	Resolver *net.Resolver // Where the actual lookups are done. If nil, net.DefaultResolver is used for lookups.
}

var _ Resolver = StrictResolver{}

var ErrRelativeDNSName = errors.New("dns: host to lookup must be absolute, ending with a dot")

func metricLookupObserve(pkg, typ string, err error, start time.Time) {
	var result string
	var dnsErr *net.DNSError
	switch {
	case err == nil:
		result = "ok"
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		result = "nxdomain"
	case errors.As(err, &dnsErr) && dnsErr.IsTemporary:
		result = "temporary"
	case errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &dnsErr) && dnsErr.IsTimeout:
		result = "timeout"
	case errors.Is(err, context.Canceled):
		result = "canceled"
	default:
		result = "error"
	}
	metricLookup.WithLabelValues(pkg, typ, result).Observe(float64(time.Since(start)) / float64(time.Second))
}

func (r StrictResolver) WithPackage(name string) Resolver {
	nr := r
	nr.Pkg = name
	return nr
}

func (r StrictResolver) resolver() Resolver {
	if r.Resolver == nil {
		return net.DefaultResolver
	}
	return r.Resolver
}

func resolveErrorHint(err *error) {
	e := *err
	if e == nil {
		return
	}
	dnserr, ok := e.(*net.DNSError)
	if !ok {
		return
	}
	// If the dns server is not running, and it is one of the default/fallback IPs,
	// hint at where to look.
	if dnserr.IsTemporary && runtime.GOOS == "linux" && (dnserr.Server == "127.0.0.1:53" || dnserr.Server == "[::1]:53") && strings.HasSuffix(dnserr.Err, "connection refused") {
		*err = fmt.Errorf("%w (hint: does /etc/resolv.conf point to a running nameserver? in case of systemd-resolved, see systemd-resolved.service(8))", *err)
	}
}

func (r StrictResolver) LookupAddr(ctx context.Context, addr string) (resp []string, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "addr", err, start)
		xlog.WithContext(ctx).Debugx("dns lookup result", err, mlog.Field("pkg", r.Pkg), mlog.Field("type", "addr"), mlog.Field("addr", addr), mlog.Field("resp", resp), mlog.Field("duration", time.Since(start)))
	}()
	defer resolveErrorHint(&err)

	resp, err = r.resolver().LookupAddr(ctx, addr)
	// For addresses from /etc/hosts without dot, we add the missing trailing dot.
	for i, s := range resp {
		if !strings.HasSuffix(s, ".") {
			resp[i] = s + "."
		}
	}
	return
}

// LookupCNAME looks up a CNAME. Unlike "net" LookupCNAME, it returns a "not found"
// error if there is no CNAME record.
func (r StrictResolver) LookupCNAME(ctx context.Context, host string) (resp string, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "cname", err, start)
		xlog.WithContext(ctx).Debugx("dns lookup result", err, mlog.Field("pkg", r.Pkg), mlog.Field("type", "cname"), mlog.Field("host", host), mlog.Field("resp", resp), mlog.Field("duration", time.Since(start)))
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(host, ".") {
		return "", ErrRelativeDNSName
	}
	resp, err = r.resolver().LookupCNAME(ctx, host)
	if err == nil && resp == host {
		return "", &net.DNSError{
			Err:        "no cname record",
			Name:       host,
			Server:     "",
			IsNotFound: true,
		}
	}
	return
}
func (r StrictResolver) LookupHost(ctx context.Context, host string) (resp []string, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "host", err, start)
		xlog.WithContext(ctx).Debugx("dns lookup result", err, mlog.Field("pkg", r.Pkg), mlog.Field("type", "host"), mlog.Field("host", host), mlog.Field("resp", resp), mlog.Field("duration", time.Since(start)))
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(host, ".") {
		return nil, ErrRelativeDNSName
	}
	resp, err = r.resolver().LookupHost(ctx, host)
	return
}

func (r StrictResolver) LookupIP(ctx context.Context, network, host string) (resp []net.IP, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "ip", err, start)
		xlog.WithContext(ctx).Debugx("dns lookup result", err, mlog.Field("pkg", r.Pkg), mlog.Field("type", "ip"), mlog.Field("network", network), mlog.Field("host", host), mlog.Field("resp", resp), mlog.Field("duration", time.Since(start)))
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(host, ".") {
		return nil, ErrRelativeDNSName
	}
	resp, err = r.resolver().LookupIP(ctx, network, host)
	return
}

func (r StrictResolver) LookupIPAddr(ctx context.Context, host string) (resp []net.IPAddr, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "ipaddr", err, start)
		xlog.WithContext(ctx).Debugx("dns lookup result", err, mlog.Field("pkg", r.Pkg), mlog.Field("type", "ipaddr"), mlog.Field("host", host), mlog.Field("resp", resp), mlog.Field("duration", time.Since(start)))
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(host, ".") {
		return nil, ErrRelativeDNSName
	}
	resp, err = r.resolver().LookupIPAddr(ctx, host)
	return
}

func (r StrictResolver) LookupMX(ctx context.Context, name string) (resp []*net.MX, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "mx", err, start)
		xlog.WithContext(ctx).Debugx("dns lookup result", err, mlog.Field("pkg", r.Pkg), mlog.Field("type", "mx"), mlog.Field("name", name), mlog.Field("resp", resp), mlog.Field("duration", time.Since(start)))
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(name, ".") {
		return nil, ErrRelativeDNSName
	}
	resp, err = r.resolver().LookupMX(ctx, name)
	return
}

func (r StrictResolver) LookupNS(ctx context.Context, name string) (resp []*net.NS, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "ns", err, start)
		xlog.WithContext(ctx).Debugx("dns lookup result", err, mlog.Field("pkg", r.Pkg), mlog.Field("type", "ns"), mlog.Field("name", name), mlog.Field("resp", resp), mlog.Field("duration", time.Since(start)))
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(name, ".") {
		return nil, ErrRelativeDNSName
	}
	resp, err = r.resolver().LookupNS(ctx, name)
	return
}

func (r StrictResolver) LookupPort(ctx context.Context, network, service string) (resp int, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "port", err, start)
		xlog.WithContext(ctx).Debugx("dns lookup result", err, mlog.Field("pkg", r.Pkg), mlog.Field("type", "port"), mlog.Field("network", network), mlog.Field("service", service), mlog.Field("resp", resp), mlog.Field("duration", time.Since(start)))
	}()
	defer resolveErrorHint(&err)

	resp, err = r.resolver().LookupPort(ctx, network, service)
	return
}

func (r StrictResolver) LookupSRV(ctx context.Context, service, proto, name string) (resp0 string, resp1 []*net.SRV, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "srv", err, start)
		xlog.WithContext(ctx).Debugx("dns lookup result", err, mlog.Field("pkg", r.Pkg), mlog.Field("type", "srv"), mlog.Field("service", service), mlog.Field("proto", proto), mlog.Field("name", name), mlog.Field("resp0", resp0), mlog.Field("resp1", resp1), mlog.Field("duration", time.Since(start)))
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(name, ".") {
		return "", nil, ErrRelativeDNSName
	}
	resp0, resp1, err = r.resolver().LookupSRV(ctx, service, proto, name)
	return
}

func (r StrictResolver) LookupTXT(ctx context.Context, name string) (resp []string, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "txt", err, start)
		xlog.WithContext(ctx).Debugx("dns lookup result", err, mlog.Field("pkg", r.Pkg), mlog.Field("type", "txt"), mlog.Field("name", name), mlog.Field("resp", resp), mlog.Field("duration", time.Since(start)))
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(name, ".") {
		return nil, ErrRelativeDNSName
	}
	resp, err = r.resolver().LookupTXT(ctx, name)
	return
}
