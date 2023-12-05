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

	"golang.org/x/exp/slog"

	"github.com/mjl-/adns"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/stub"
)

// todo future: replace with a dnssec capable resolver
// todo future: change to interface that is closer to DNS. 1. expose nxdomain vs success with zero entries: nxdomain means the name does not exist for any dns resource record type, success with zero records means the name exists for other types than the requested type; 2. add ability to not follow cname records when resolving. the net resolver automatically follows cnames for LookupHost, LookupIP, LookupIPAddr. when resolving names found in mx records, we explicitly must not follow cnames. that seems impossible at the moment. 3. when looking up a cname, actually lookup the record? "net" LookupCNAME will return the requested name with no error if there is no CNAME record. because it returns the canonical name.
// todo future: add option to not use anything in the cache, for the admin pages where you check the latest DNS settings, ignoring old cached info.

func init() {
	net.DefaultResolver.StrictErrors = true
}

var (
	MetricLookup stub.HistogramVec = stub.HistogramVecIgnore{}
)

// Resolver is the interface strict resolver implements.
type Resolver interface {
	LookupPort(ctx context.Context, network, service string) (port int, err error)
	LookupAddr(ctx context.Context, addr string) ([]string, adns.Result, error) // Always returns absolute names, with trailing dot.
	LookupCNAME(ctx context.Context, host string) (string, adns.Result, error)  // NOTE: returns an error if no CNAME record is present.
	LookupHost(ctx context.Context, host string) ([]string, adns.Result, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, adns.Result, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, adns.Result, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, adns.Result, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, adns.Result, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, adns.Result, error)
	LookupTXT(ctx context.Context, name string) ([]string, adns.Result, error)
	LookupTLSA(ctx context.Context, port int, protocol, host string) ([]adns.TLSA, adns.Result, error)
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
	Pkg      string         // Name of subsystem that is making DNS requests, for metrics.
	Resolver *adns.Resolver // Where the actual lookups are done. If nil, adns.DefaultResolver is used for lookups.
	Log      *slog.Logger
}

func (r StrictResolver) log() mlog.Log {
	pkg := r.Pkg
	if pkg == "" {
		pkg = "dns"
	}
	return mlog.New(pkg, r.Log)
}

var _ Resolver = StrictResolver{}

var ErrRelativeDNSName = errors.New("dns: host to lookup must be absolute, ending with a dot")

func metricLookupObserve(pkg, typ string, err error, start time.Time) {
	var result string
	var dnsErr *adns.DNSError
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
	MetricLookup.ObserveLabels(float64(time.Since(start))/float64(time.Second), pkg, typ, result)
}

func (r StrictResolver) WithPackage(name string) Resolver {
	nr := r
	nr.Pkg = name
	return nr
}

func (r StrictResolver) resolver() Resolver {
	if r.Resolver == nil {
		return adns.DefaultResolver
	}
	return r.Resolver
}

func resolveErrorHint(err *error) {
	e := *err
	if e == nil {
		return
	}
	dnserr, ok := e.(*adns.DNSError)
	if !ok {
		return
	}
	// If the dns server is not running, and it is one of the default/fallback IPs,
	// hint at where to look.
	if dnserr.IsTemporary && runtime.GOOS == "linux" && (dnserr.Server == "127.0.0.1:53" || dnserr.Server == "[::1]:53") && strings.HasSuffix(dnserr.Err, "connection refused") {
		*err = fmt.Errorf("%w (hint: does /etc/resolv.conf point to a running nameserver? in case of systemd-resolved, see systemd-resolved.service(8); better yet, install a proper dnssec-verifying recursive resolver like unbound)", *err)
	}
}

func (r StrictResolver) LookupPort(ctx context.Context, network, service string) (resp int, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "port", err, start)
		r.log().WithContext(ctx).Debugx("dns lookup result", err,
			slog.String("type", "port"),
			slog.String("network", network),
			slog.String("service", service),
			slog.Int("resp", resp),
			slog.Duration("duration", time.Since(start)),
		)
	}()
	defer resolveErrorHint(&err)

	resp, err = r.resolver().LookupPort(ctx, network, service)
	return
}

func (r StrictResolver) LookupAddr(ctx context.Context, addr string) (resp []string, result adns.Result, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "addr", err, start)
		r.log().WithContext(ctx).Debugx("dns lookup result", err,
			slog.String("type", "addr"),
			slog.String("addr", addr),
			slog.Any("resp", resp),
			slog.Bool("authentic", result.Authentic),
			slog.Duration("duration", time.Since(start)),
		)
	}()
	defer resolveErrorHint(&err)

	resp, result, err = r.resolver().LookupAddr(ctx, addr)
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
func (r StrictResolver) LookupCNAME(ctx context.Context, host string) (resp string, result adns.Result, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "cname", err, start)
		r.log().WithContext(ctx).Debugx("dns lookup result", err,
			slog.String("type", "cname"),
			slog.String("host", host),
			slog.String("resp", resp),
			slog.Bool("authentic", result.Authentic),
			slog.Duration("duration", time.Since(start)),
		)
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(host, ".") {
		return "", result, ErrRelativeDNSName
	}
	resp, result, err = r.resolver().LookupCNAME(ctx, host)
	if err == nil && resp == host {
		return "", result, &adns.DNSError{
			Err:        "no cname record",
			Name:       host,
			Server:     "",
			IsNotFound: true,
		}
	}
	return
}

func (r StrictResolver) LookupHost(ctx context.Context, host string) (resp []string, result adns.Result, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "host", err, start)
		r.log().WithContext(ctx).Debugx("dns lookup result", err,
			slog.String("type", "host"),
			slog.String("host", host),
			slog.Any("resp", resp),
			slog.Bool("authentic", result.Authentic),
			slog.Duration("duration", time.Since(start)),
		)
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(host, ".") {
		return nil, result, ErrRelativeDNSName
	}
	resp, result, err = r.resolver().LookupHost(ctx, host)
	return
}

func (r StrictResolver) LookupIP(ctx context.Context, network, host string) (resp []net.IP, result adns.Result, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "ip", err, start)
		r.log().WithContext(ctx).Debugx("dns lookup result", err,
			slog.String("type", "ip"),
			slog.String("network", network),
			slog.String("host", host),
			slog.Any("resp", resp),
			slog.Bool("authentic", result.Authentic),
			slog.Duration("duration", time.Since(start)),
		)
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(host, ".") {
		return nil, result, ErrRelativeDNSName
	}
	resp, result, err = r.resolver().LookupIP(ctx, network, host)
	return
}

func (r StrictResolver) LookupIPAddr(ctx context.Context, host string) (resp []net.IPAddr, result adns.Result, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "ipaddr", err, start)
		r.log().WithContext(ctx).Debugx("dns lookup result", err,
			slog.String("type", "ipaddr"),
			slog.String("host", host),
			slog.Any("resp", resp),
			slog.Bool("authentic", result.Authentic),
			slog.Duration("duration", time.Since(start)),
		)
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(host, ".") {
		return nil, result, ErrRelativeDNSName
	}
	resp, result, err = r.resolver().LookupIPAddr(ctx, host)
	return
}

func (r StrictResolver) LookupMX(ctx context.Context, name string) (resp []*net.MX, result adns.Result, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "mx", err, start)
		r.log().WithContext(ctx).Debugx("dns lookup result", err,
			slog.String("type", "mx"),
			slog.String("name", name),
			slog.Any("resp", resp),
			slog.Bool("authentic", result.Authentic),
			slog.Duration("duration", time.Since(start)),
		)
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(name, ".") {
		return nil, result, ErrRelativeDNSName
	}
	resp, result, err = r.resolver().LookupMX(ctx, name)
	return
}

func (r StrictResolver) LookupNS(ctx context.Context, name string) (resp []*net.NS, result adns.Result, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "ns", err, start)
		r.log().WithContext(ctx).Debugx("dns lookup result", err,
			slog.String("type", "ns"),
			slog.String("name", name),
			slog.Any("resp", resp),
			slog.Bool("authentic", result.Authentic),
			slog.Duration("duration", time.Since(start)),
		)
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(name, ".") {
		return nil, result, ErrRelativeDNSName
	}
	resp, result, err = r.resolver().LookupNS(ctx, name)
	return
}

func (r StrictResolver) LookupSRV(ctx context.Context, service, proto, name string) (resp0 string, resp1 []*net.SRV, result adns.Result, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "srv", err, start)
		r.log().WithContext(ctx).Debugx("dns lookup result", err,
			slog.String("type", "srv"),
			slog.String("service", service),
			slog.String("proto", proto),
			slog.String("name", name),
			slog.String("resp0", resp0),
			slog.Any("resp1", resp1),
			slog.Bool("authentic", result.Authentic),
			slog.Duration("duration", time.Since(start)),
		)
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(name, ".") {
		return "", nil, result, ErrRelativeDNSName
	}
	resp0, resp1, result, err = r.resolver().LookupSRV(ctx, service, proto, name)
	return
}

func (r StrictResolver) LookupTXT(ctx context.Context, name string) (resp []string, result adns.Result, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "txt", err, start)
		r.log().WithContext(ctx).Debugx("dns lookup result", err,
			slog.String("type", "txt"),
			slog.String("name", name),
			slog.Any("resp", resp),
			slog.Bool("authentic", result.Authentic),
			slog.Duration("duration", time.Since(start)),
		)
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(name, ".") {
		return nil, result, ErrRelativeDNSName
	}
	resp, result, err = r.resolver().LookupTXT(ctx, name)
	return
}

func (r StrictResolver) LookupTLSA(ctx context.Context, port int, protocol, host string) (resp []adns.TLSA, result adns.Result, err error) {
	start := time.Now()
	defer func() {
		metricLookupObserve(r.Pkg, "tlsa", err, start)
		r.log().WithContext(ctx).Debugx("dns lookup result", err,
			slog.String("type", "tlsa"),
			slog.Int("port", port),
			slog.String("protocol", protocol),
			slog.String("host", host),
			slog.Any("resp", resp),
			slog.Bool("authentic", result.Authentic),
			slog.Duration("duration", time.Since(start)),
		)
	}()
	defer resolveErrorHint(&err)

	if !strings.HasSuffix(host, ".") {
		return nil, result, ErrRelativeDNSName
	}
	resp, result, err = r.resolver().LookupTLSA(ctx, port, protocol, host)
	return
}
