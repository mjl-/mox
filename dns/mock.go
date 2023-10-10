package dns

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/exp/slices"

	"github.com/mjl-/adns"
)

// MockResolver is a Resolver used for testing.
// Set DNS records in the fields, which map FQDNs (with trailing dot) to values.
type MockResolver struct {
	PTR          map[string][]string
	A            map[string][]string
	AAAA         map[string][]string
	TXT          map[string][]string
	MX           map[string][]*net.MX
	TLSA         map[string][]adns.TLSA // Keys are e.g. _25._tcp.<host>.
	CNAME        map[string]string
	Fail         map[Mockreq]struct{}
	AllAuthentic bool     // Default value for authentic in responses. Overridden with Authentic and Inauthentic
	Authentic    []string // Records of the form "type name", e.g. "cname localhost."
	Inauthentic  []string
}

type Mockreq struct {
	Type string // E.g. "cname", "txt", "mx", "ptr", etc.
	Name string // Name of request. For TLSA, the full requested DNS name, e.g. _25._tcp.<host>.
}

var _ Resolver = MockResolver{}

func (r MockResolver) result(ctx context.Context, mr Mockreq) (string, adns.Result, error) {
	result := adns.Result{Authentic: r.AllAuthentic}

	if err := ctx.Err(); err != nil {
		return "", result, err
	}

	updateAuthentic := func(mock string) {
		if slices.Contains(r.Authentic, mock) {
			result.Authentic = true
		}
		if slices.Contains(r.Inauthentic, mock) {
			result.Authentic = false
		}
	}

	for {
		if _, ok := r.Fail[mr]; ok {
			updateAuthentic(mr.Type + " " + mr.Name)
			return mr.Name, adns.Result{}, r.servfail(mr.Name)
		}

		cname, ok := r.CNAME[mr.Name]
		if !ok {
			updateAuthentic(mr.Type + " " + mr.Name)
			break
		}
		updateAuthentic("cname " + mr.Name)
		if mr.Type == "cname" {
			return mr.Name, result, nil
		}
		mr.Name = cname
	}
	return mr.Name, result, nil
}

func (r MockResolver) nxdomain(s string) error {
	return &adns.DNSError{
		Err:        "no record",
		Name:       s,
		Server:     "mock",
		IsNotFound: true,
	}
}

func (r MockResolver) servfail(s string) error {
	return &adns.DNSError{
		Err:         "temp error",
		Name:        s,
		Server:      "mock",
		IsTemporary: true,
	}
}

func (r MockResolver) LookupPort(ctx context.Context, network, service string) (port int, err error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return net.LookupPort(network, service)
}

func (r MockResolver) LookupCNAME(ctx context.Context, name string) (string, adns.Result, error) {
	mr := Mockreq{"cname", name}
	name, result, err := r.result(ctx, mr)
	if err != nil {
		return name, result, err
	}
	cname, ok := r.CNAME[name]
	if !ok {
		return cname, result, r.nxdomain(name)
	}
	return cname, result, nil
}

func (r MockResolver) LookupAddr(ctx context.Context, ip string) ([]string, adns.Result, error) {
	mr := Mockreq{"ptr", ip}
	_, result, err := r.result(ctx, mr)
	if err != nil {
		return nil, result, err
	}
	l, ok := r.PTR[ip]
	if !ok {
		return nil, result, r.nxdomain(ip)
	}
	return l, result, nil
}

func (r MockResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, adns.Result, error) {
	mr := Mockreq{"ns", name}
	_, result, err := r.result(ctx, mr)
	if err != nil {
		return nil, result, err
	}
	return nil, result, r.servfail("ns not implemented")
}

func (r MockResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, adns.Result, error) {
	xname := fmt.Sprintf("_%s._%s.%s", service, proto, name)
	mr := Mockreq{"srv", xname}
	name, result, err := r.result(ctx, mr)
	if err != nil {
		return name, nil, result, err
	}
	return name, nil, result, r.servfail("srv not implemented")
}

func (r MockResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, adns.Result, error) {
	// todo: make closer to resolver, doing a & aaaa lookups, including their error/(in)secure status.
	mr := Mockreq{"ipaddr", host}
	_, result, err := r.result(ctx, mr)
	if err != nil {
		return nil, result, err
	}
	addrs, result1, err := r.LookupHost(ctx, host)
	result.Authentic = result.Authentic && result1.Authentic
	if err != nil {
		return nil, result, err
	}
	ips := make([]net.IPAddr, len(addrs))
	for i, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			return nil, result, fmt.Errorf("malformed ip %q", a)
		}
		ips[i] = net.IPAddr{IP: ip}
	}
	return ips, result, nil
}

func (r MockResolver) LookupHost(ctx context.Context, host string) ([]string, adns.Result, error) {
	// todo: make closer to resolver, doing a & aaaa lookups, including their error/(in)secure status.
	mr := Mockreq{"host", host}
	_, result, err := r.result(ctx, mr)
	if err != nil {
		return nil, result, err
	}
	var addrs []string
	addrs = append(addrs, r.A[host]...)
	addrs = append(addrs, r.AAAA[host]...)
	if len(addrs) == 0 {
		return nil, result, r.nxdomain(host)
	}
	return addrs, result, nil
}

func (r MockResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, adns.Result, error) {
	mr := Mockreq{"ip", host}
	_, result, err := r.result(ctx, mr)
	if err != nil {
		return nil, result, err
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
		return nil, result, r.nxdomain(host)
	}
	return ips, result, nil
}

func (r MockResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, adns.Result, error) {
	mr := Mockreq{"mx", name}
	_, result, err := r.result(ctx, mr)
	if err != nil {
		return nil, result, err
	}
	l, ok := r.MX[name]
	if !ok {
		return nil, result, r.nxdomain(name)
	}
	return l, result, nil
}

func (r MockResolver) LookupTXT(ctx context.Context, name string) ([]string, adns.Result, error) {
	mr := Mockreq{"txt", name}
	_, result, err := r.result(ctx, mr)
	if err != nil {
		return nil, result, err
	}
	l, ok := r.TXT[name]
	if !ok {
		return nil, result, r.nxdomain(name)
	}
	return l, result, nil
}

func (r MockResolver) LookupTLSA(ctx context.Context, port int, protocol string, host string) ([]adns.TLSA, adns.Result, error) {
	var name string
	if port == 0 && protocol == "" {
		name = host
	} else {
		name = fmt.Sprintf("_%d._%s.%s", port, protocol, host)
	}
	mr := Mockreq{"tlsa", name}
	_, result, err := r.result(ctx, mr)
	if err != nil {
		return nil, result, err
	}
	l, ok := r.TLSA[name]
	if !ok {
		return nil, result, r.nxdomain(name)
	}
	return l, result, nil
}
