package dns

import (
	"context"
	"fmt"
	"net"
)

// MockResolver is a Resolver used for testing.
// Set DNS records in the fields, which map FQDNs (with trailing dot) to values.
type MockResolver struct {
	PTR   map[string][]string
	A     map[string][]string
	AAAA  map[string][]string
	TXT   map[string][]string
	MX    map[string][]*net.MX
	CNAME map[string]string
	Fail  map[Mockreq]struct{}
}

type Mockreq struct {
	Type string // E.g. "cname", "txt", "mx", "ptr", etc.
	Name string
}

var _ Resolver = MockResolver{}

func (r MockResolver) nxdomain(s string) *net.DNSError {
	return &net.DNSError{
		Err:        "no record",
		Name:       s,
		Server:     "localhost",
		IsNotFound: true,
	}
}

func (r MockResolver) servfail(s string) *net.DNSError {
	return &net.DNSError{
		Err:         "temp error",
		Name:        s,
		Server:      "localhost",
		IsTemporary: true,
	}
}

func (r MockResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	if _, ok := r.Fail[Mockreq{"cname", name}]; ok {
		return "", r.servfail(name)
	}
	if cname, ok := r.CNAME[name]; ok {
		return cname, nil
	}
	return "", r.nxdomain(name)
}

func (r MockResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	if _, ok := r.Fail[Mockreq{"ptr", ip}]; ok {
		return nil, r.servfail(ip)
	}
	l, ok := r.PTR[ip]
	if !ok {
		return nil, r.nxdomain(ip)
	}
	return l, nil
}

func (r MockResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return nil, r.servfail("ns not implemented")
}

func (r MockResolver) LookupPort(ctx context.Context, network, service string) (port int, err error) {
	return 0, r.servfail("port not implemented")
}

func (r MockResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	return "", nil, r.servfail("srv not implemented")
}

func (r MockResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if _, ok := r.Fail[Mockreq{"ipaddr", host}]; ok {
		return nil, r.servfail(host)
	}
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IPAddr, len(addrs))
	for i, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			return nil, fmt.Errorf("malformed ip %q", a)
		}
		ips[i] = net.IPAddr{IP: ip}
	}
	return ips, nil
}

func (r MockResolver) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	if _, ok := r.Fail[Mockreq{"host", host}]; ok {
		return nil, r.servfail(host)
	}
	addrs = append(addrs, r.A[host]...)
	addrs = append(addrs, r.AAAA[host]...)
	if len(addrs) > 0 {
		return addrs, nil
	}
	if cname, ok := r.CNAME[host]; ok {
		return []string{cname}, nil
	}
	return nil, r.nxdomain(host)
}

func (r MockResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if _, ok := r.Fail[Mockreq{"ip", host}]; ok {
		return nil, r.servfail(host)
	}
	var ips []net.IP
	switch network {
	case "ip", "ip4":
		for _, ip := range r.A[host] {
			ips = append(ips, net.ParseIP(ip))
		}
	}
	switch network {
	case "ip", "ip6":
		for _, ip := range r.AAAA[host] {
			ips = append(ips, net.ParseIP(ip))
		}
	}
	if len(ips) == 0 {
		return nil, r.nxdomain(host)
	}
	return ips, nil
}

func (r MockResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if _, ok := r.Fail[Mockreq{"mx", name}]; ok {
		return nil, r.servfail(name)
	}
	l, ok := r.MX[name]
	if !ok {
		return nil, r.nxdomain(name)
	}
	return l, nil
}

func (r MockResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if _, ok := r.Fail[Mockreq{"txt", name}]; ok {
		return nil, r.servfail(name)
	}
	l, ok := r.TXT[name]
	if !ok {
		return nil, r.nxdomain(name)
	}
	return l, nil
}
