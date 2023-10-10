// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package adns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/mjl-/adns/internal/singleflight"
)

// protocols contains minimal mappings between internet protocol
// names and numbers for platforms that don't have a complete list of
// protocol numbers.
//
// See https://www.iana.org/assignments/protocol-numbers
//
// On Unix, this map is augmented by readProtocols via lookupProtocol.
var protocols = map[string]int{
	"icmp":      1,
	"igmp":      2,
	"tcp":       6,
	"udp":       17,
	"ipv6-icmp": 58,
}

// services contains minimal mappings between services names and port
// numbers for platforms that don't have a complete list of port numbers.
//
// See https://www.iana.org/assignments/service-names-port-numbers
//
// On Unix, this map is augmented by readServices via goLookupPort.
var services = map[string]map[string]int{
	"udp": {
		"domain": 53,
	},
	"tcp": {
		"ftp":    21,
		"ftps":   990,
		"gopher": 70, // ʕ◔ϖ◔ʔ
		"http":   80,
		"https":  443,
		"imap2":  143,
		"imap3":  220,
		"imaps":  993,
		"pop3":   110,
		"pop3s":  995,
		"smtp":   25,
		"ssh":    22,
		"telnet": 23,
	},
}

// dnsWaitGroup can be used by tests to wait for all DNS goroutines to
// complete. This avoids races on the test hooks.
var dnsWaitGroup sync.WaitGroup

const maxProtoLength = len("RSVP-E2E-IGNORE") + 10 // with room to grow

func lookupProtocolMap(name string) (int, error) {
	var lowerProtocol [maxProtoLength]byte
	n := copy(lowerProtocol[:], name)
	lowerASCIIBytes(lowerProtocol[:n])
	proto, found := protocols[string(lowerProtocol[:n])]
	if !found || n != len(name) {
		return 0, &net.AddrError{Err: "unknown IP protocol specified", Addr: name}
	}
	return proto, nil
}

// maxPortBufSize is the longest reasonable name of a service
// (non-numeric port).
// Currently the longest known IANA-unregistered name is
// "mobility-header", so we use that length, plus some slop in case
// something longer is added in the future.
const maxPortBufSize = len("mobility-header") + 10

func lookupPortMap(network, service string) (port int, error error) {
	switch network {
	case "tcp4", "tcp6":
		network = "tcp"
	case "udp4", "udp6":
		network = "udp"
	}

	if m, ok := services[network]; ok {
		var lowerService [maxPortBufSize]byte
		n := copy(lowerService[:], service)
		lowerASCIIBytes(lowerService[:n])
		if port, ok := m[string(lowerService[:n])]; ok && n == len(service) {
			return port, nil
		}
	}
	return 0, &net.AddrError{Err: "unknown port", Addr: network + "/" + service}
}

// ipVersion returns the provided network's IP version: '4', '6' or 0
// if network does not end in a '4' or '6' byte.
func ipVersion(network string) byte {
	if network == "" {
		return 0
	}
	n := network[len(network)-1]
	if n != '4' && n != '6' {
		n = 0
	}
	return n
}

// DefaultResolver is the resolver used by the package-level Lookup
// functions and by Dialers without a specified Resolver.
var DefaultResolver = &Resolver{}

// A Resolver looks up names and numbers.
//
// A nil *Resolver is equivalent to a zero Resolver.
type Resolver struct {
	// PreferGo controls whether Go's built-in DNS resolver is preferred
	// on platforms where it's available. It is equivalent to setting
	// GODEBUG=netdns=go, but scoped to just this resolver.
	PreferGo bool

	// StrictErrors controls the behavior of temporary errors
	// (including timeout, socket errors, and SERVFAIL) when using
	// Go's built-in resolver. For a query composed of multiple
	// sub-queries (such as an A+AAAA address lookup, or walking the
	// DNS search list), this option causes such errors to abort the
	// whole query instead of returning a partial result. This is
	// not enabled by default because it may affect compatibility
	// with resolvers that process AAAA queries incorrectly.
	StrictErrors bool

	// Dial optionally specifies an alternate dialer for use by
	// Go's built-in DNS resolver to make TCP and UDP connections
	// to DNS services. The host in the address parameter will
	// always be a literal IP address and not a host name, and the
	// port in the address parameter will be a literal port number
	// and not a service name.
	// If the Conn returned is also a PacketConn, sent and received DNS
	// messages must adhere to RFC 1035 section 4.2.1, "UDP usage".
	// Otherwise, DNS messages transmitted over Conn must adhere
	// to RFC 7766 section 5, "Transport Protocol Selection".
	// If nil, the default dialer is used.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// lookupGroup merges LookupIPAddr calls together for lookups for the same
	// host. The lookupGroup key is the LookupIPAddr.host argument.
	// The return values are ([]IPAddr, error).
	lookupGroup singleflight.Group

	// TODO(bradfitz): optional interface impl override hook
	// TODO(bradfitz): Timeout time.Duration?
}

func (r *Resolver) preferGo() bool     { return r != nil && r.PreferGo }
func (r *Resolver) strictErrors() bool { return r != nil && r.StrictErrors }

func (r *Resolver) getLookupGroup() *singleflight.Group {
	if r == nil {
		return &DefaultResolver.lookupGroup
	}
	return &r.lookupGroup
}

// LookupHost looks up the given host using the local resolver.
// It returns a slice of that host's addresses.
//
// LookupHost uses context.Background internally; to specify the context, use
// Resolver.LookupHost.
func LookupHost(host string) (addrs []string, result Result, err error) {
	return DefaultResolver.LookupHost(context.Background(), host)
}

// LookupHost looks up the given host using the local resolver.
// It returns a slice of that host's addresses.
func (r *Resolver) LookupHost(ctx context.Context, host string) (addrs []string, result Result, err error) {
	// Make sure that no matter what we do later, host=="" is rejected.
	if host == "" {
		return nil, result, &DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return []string{host}, result, nil
	}
	return r.lookupHost(ctx, host)
}

// LookupIP looks up host using the local resolver.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func LookupIP(host string) ([]net.IP, Result, error) {
	addrs, result, err := DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, result, err
	}
	ips := make([]net.IP, len(addrs))
	for i, ia := range addrs {
		ips[i] = ia.IP
	}
	return ips, result, nil
}

// LookupIPAddr looks up host using the local resolver.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, Result, error) {
	return r.lookupIPAddr(ctx, "ip", host)
}

// LookupIP looks up host for the given network using the local resolver.
// It returns a slice of that host's IP addresses of the type specified by
// network.
// network must be one of "ip", "ip4" or "ip6".
func (r *Resolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, Result, error) {
	afnet, _, err := parseNetwork(ctx, network, false)
	if err != nil {
		return nil, Result{}, err
	}
	switch afnet {
	case "ip", "ip4", "ip6":
	default:
		return nil, Result{}, net.UnknownNetworkError(network)
	}

	if host == "" {
		return nil, Result{}, &DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	addrs, result, err := r.internetAddrList(ctx, afnet, host)
	if err != nil {
		return nil, result, err
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.(*net.IPAddr).IP)
	}
	return ips, result, nil
}

// LookupNetIP looks up host using the local resolver.
// It returns a slice of that host's IP addresses of the type specified by
// network.
// The network must be one of "ip", "ip4" or "ip6".
func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, Result, error) {
	// TODO(bradfitz): make this efficient, making the internal net package
	// type throughout be netip.Addr and only converting to the net.IP slice
	// version at the edge. But for now (2021-10-20), this is a wrapper around
	// the old way.
	ips, result, err := r.LookupIP(ctx, network, host)
	if err != nil {
		return nil, result, err
	}
	ret := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			ret = append(ret, a)
		}
	}
	return ret, result, nil
}

// onlyValuesCtx is a context that uses an underlying context
// for value lookup if the underlying context hasn't yet expired.
type onlyValuesCtx struct {
	context.Context
	lookupValues context.Context
}

var _ context.Context = (*onlyValuesCtx)(nil)

// Value performs a lookup if the original context hasn't expired.
func (ovc *onlyValuesCtx) Value(key any) any {
	select {
	case <-ovc.lookupValues.Done():
		return nil
	default:
		return ovc.lookupValues.Value(key)
	}
}

// withUnexpiredValuesPreserved returns a context.Context that only uses lookupCtx
// for its values, otherwise it is never canceled and has no deadline.
// If the lookup context expires, any looked up values will return nil.
// See Issue 28600.
func withUnexpiredValuesPreserved(lookupCtx context.Context) context.Context {
	return &onlyValuesCtx{Context: context.Background(), lookupValues: lookupCtx}
}

// lookupIPAddr looks up host using the local resolver and particular network.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func (r *Resolver) lookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, Result, error) {
	// Make sure that no matter what we do later, host=="" is rejected.
	if host == "" {
		return nil, Result{}, &DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []net.IPAddr{{IP: net.IP(ip.AsSlice()).To16(), Zone: ip.Zone()}}, Result{}, nil
	}
	// The underlying resolver func is lookupIP by default but it
	// can be overridden by tests. This is needed by net/http, so it
	// uses a context key instead of unexported variables.
	resolverFunc := r.lookupIP

	// We don't want a cancellation of ctx to affect the
	// lookupGroup operation. Otherwise if our context gets
	// canceled it might cause an error to be returned to a lookup
	// using a completely different context. However we need to preserve
	// only the values in context. See Issue 28600.
	lookupGroupCtx, lookupGroupCancel := context.WithCancel(withUnexpiredValuesPreserved(ctx))

	type Tuple struct {
		ips    []net.IPAddr
		result Result
	}

	lookupKey := network + "\000" + host
	dnsWaitGroup.Add(1)
	ch := r.getLookupGroup().DoChan(lookupKey, func() (any, error) {
		ips, result, err := testHookLookupIP(lookupGroupCtx, resolverFunc, network, host)
		return Tuple{ips, result}, err
	})

	dnsWaitGroupDone := func(ch <-chan singleflight.Result, cancelFn context.CancelFunc) {
		<-ch
		dnsWaitGroup.Done()
		cancelFn()
	}
	select {
	case <-ctx.Done():
		// Our context was canceled. If we are the only
		// goroutine looking up this key, then drop the key
		// from the lookupGroup and cancel the lookup.
		// If there are other goroutines looking up this key,
		// let the lookup continue uncanceled, and let later
		// lookups with the same key share the result.
		// See issues 8602, 20703, 22724.
		if r.getLookupGroup().ForgetUnshared(lookupKey) {
			lookupGroupCancel()
			go dnsWaitGroupDone(ch, func() {})
		} else {
			go dnsWaitGroupDone(ch, lookupGroupCancel)
		}
		ctxErr := ctx.Err()
		err := &DNSError{
			Err:       mapErr(ctxErr).Error(),
			Name:      host,
			IsTimeout: ctxErr == context.DeadlineExceeded,
		}
		return nil, Result{}, err
	case r := <-ch:
		dnsWaitGroup.Done()
		lookupGroupCancel()
		err := r.Err
		if err != nil {
			if _, ok := err.(*DNSError); !ok {
				isTimeout := false
				if err == context.DeadlineExceeded {
					isTimeout = true
				} else if terr, ok := err.(timeout); ok {
					isTimeout = terr.Timeout()
				}
				err = &DNSError{
					Err:       err.Error(),
					Name:      host,
					IsTimeout: isTimeout,
				}
			}
		}
		tuple := r.Val.(Tuple)
		if err != nil {
			return nil, tuple.result, err
		}
		ips := lookupIPReturn(tuple.ips, r.Shared)
		return ips, tuple.result, nil
	}
}

// lookupIPReturn turns the return values from singleflight.Do into
// the return values from LookupIP.
func lookupIPReturn(addrs []net.IPAddr, shared bool) []net.IPAddr {
	if shared {
		clone := make([]net.IPAddr, len(addrs))
		copy(clone, addrs)
		addrs = clone
	}
	return addrs
}

// LookupPort looks up the port for the given network and service.
//
// LookupPort uses context.Background internally; to specify the context, use
// Resolver.LookupPort.
func LookupPort(network, service string) (port int, err error) {
	return DefaultResolver.LookupPort(context.Background(), network, service)
}

// LookupPort looks up the port for the given network and service.
func (r *Resolver) LookupPort(ctx context.Context, network, service string) (port int, err error) {
	port, needsLookup := parsePort(service)
	if needsLookup {
		switch network {
		case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		case "": // a hint wildcard for Go 1.0 undocumented behavior
			network = "ip"
		default:
			return 0, &net.AddrError{Err: "unknown network", Addr: network}
		}
		port, err = r.lookupPort(ctx, network, service)
		if err != nil {
			return 0, err
		}
	}
	if 0 > port || port > 65535 {
		return 0, &net.AddrError{Err: "invalid port", Addr: service}
	}
	return port, nil
}

// LookupCNAME returns the canonical name for the given host.
// Callers that do not care about the canonical name can call
// LookupHost or LookupIP directly; both take care of resolving
// the canonical name as part of the lookup.
//
// A canonical name is the final name after following zero
// or more CNAME records.
// LookupCNAME does not return an error if host does not
// contain DNS "CNAME" records, as long as host resolves to
// address records.
//
// The returned canonical name is validated to be a properly
// formatted presentation-format domain name.
//
// LookupCNAME uses context.Background internally; to specify the context, use
// Resolver.LookupCNAME.
func LookupCNAME(host string) (cname string, result Result, err error) {
	return DefaultResolver.LookupCNAME(context.Background(), host)
}

// LookupCNAME returns the canonical name for the given host.
// Callers that do not care about the canonical name can call
// LookupHost or LookupIP directly; both take care of resolving
// the canonical name as part of the lookup.
//
// A canonical name is the final name after following zero
// or more CNAME records.
// LookupCNAME does not return an error if host does not
// contain DNS "CNAME" records, as long as host resolves to
// address records.
//
// The returned canonical name is validated to be a properly
// formatted presentation-format domain name.
func (r *Resolver) LookupCNAME(ctx context.Context, host string) (string, Result, error) {
	cname, result, err := r.lookupCNAME(ctx, host)
	if err != nil {
		return "", result, err
	}
	if !isDomainName(cname) {
		return "", result, &DNSError{Err: errMalformedDNSRecordsDetail, Name: host}
	}
	return cname, result, nil
}

// LookupSRV tries to resolve an SRV query of the given service,
// protocol, and domain name. The proto is "tcp" or "udp".
// The returned records are sorted by priority and randomized
// by weight within a priority.
//
// LookupSRV constructs the DNS name to look up following RFC 2782.
// That is, it looks up _service._proto.name. To accommodate services
// publishing SRV records under non-standard names, if both service
// and proto are empty strings, LookupSRV looks up name directly.
//
// The returned service names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
func LookupSRV(service, proto, name string) (cname string, addrs []*net.SRV, result Result, err error) {
	return DefaultResolver.LookupSRV(context.Background(), service, proto, name)
}

// LookupSRV tries to resolve an SRV query of the given service,
// protocol, and domain name. The proto is "tcp" or "udp".
// The returned records are sorted by priority and randomized
// by weight within a priority.
//
// LookupSRV constructs the DNS name to look up following RFC 2782.
// That is, it looks up _service._proto.name. To accommodate services
// publishing SRV records under non-standard names, if both service
// and proto are empty strings, LookupSRV looks up name directly.
//
// The returned service names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
func (r *Resolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, Result, error) {
	cname, addrs, result, err := r.lookupSRV(ctx, service, proto, name)
	if err != nil {
		return "", nil, result, err
	}
	if cname != "" && !isDomainName(cname) {
		return "", nil, result, &DNSError{Err: "SRV header name is invalid", Name: name}
	}
	filteredAddrs := make([]*net.SRV, 0, len(addrs))
	for _, addr := range addrs {
		if addr == nil {
			continue
		}
		if !isDomainName(addr.Target) {
			continue
		}
		filteredAddrs = append(filteredAddrs, addr)
	}
	if len(addrs) != len(filteredAddrs) {
		return cname, filteredAddrs, result, &DNSError{Err: errMalformedDNSRecordsDetail, Name: name}
	}
	return cname, filteredAddrs, result, nil
}

// LookupMX returns the DNS MX records for the given domain name sorted by preference.
//
// The returned mail server names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
//
// LookupMX uses context.Background internally; to specify the context, use
// Resolver.LookupMX.
func LookupMX(name string) ([]*net.MX, Result, error) {
	return DefaultResolver.LookupMX(context.Background(), name)
}

// LookupMX returns the DNS MX records for the given domain name sorted by preference.
//
// The returned mail server names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
func (r *Resolver) LookupMX(ctx context.Context, name string) ([]*net.MX, Result, error) {
	records, result, err := r.lookupMX(ctx, name)
	if err != nil {
		return nil, result, err
	}
	filteredMX := make([]*net.MX, 0, len(records))
	for _, mx := range records {
		if mx == nil {
			continue
		}
		if !isDomainName(mx.Host) {
			continue
		}
		filteredMX = append(filteredMX, mx)
	}
	if len(records) != len(filteredMX) {
		return filteredMX, result, &DNSError{Err: errMalformedDNSRecordsDetail, Name: name}
	}
	return filteredMX, result, nil
}

// LookupNS returns the DNS NS records for the given domain name.
//
// The returned name server names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
//
// LookupNS uses context.Background internally; to specify the context, use
// Resolver.LookupNS.
func LookupNS(name string) ([]*net.NS, Result, error) {
	return DefaultResolver.LookupNS(context.Background(), name)
}

// LookupNS returns the DNS NS records for the given domain name.
//
// The returned name server names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
func (r *Resolver) LookupNS(ctx context.Context, name string) ([]*net.NS, Result, error) {
	records, result, err := r.lookupNS(ctx, name)
	if err != nil {
		return nil, result, err
	}
	filteredNS := make([]*net.NS, 0, len(records))
	for _, ns := range records {
		if ns == nil {
			continue
		}
		if !isDomainName(ns.Host) {
			continue
		}
		filteredNS = append(filteredNS, ns)
	}
	if len(records) != len(filteredNS) {
		return filteredNS, result, &DNSError{Err: errMalformedDNSRecordsDetail, Name: name}
	}
	return filteredNS, result, nil
}

// LookupTXT returns the DNS TXT records for the given domain name.
//
// LookupTXT uses context.Background internally; to specify the context, use
// Resolver.LookupTXT.
func LookupTXT(name string) ([]string, Result, error) {
	return DefaultResolver.lookupTXT(context.Background(), name)
}

// LookupTXT returns the DNS TXT records for the given domain name.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, Result, error) {
	return r.lookupTXT(ctx, name)
}

// LookupAddr performs a reverse lookup for the given address, returning a list
// of names mapping to that address.
//
// The returned names are validated to be properly formatted presentation-format
// domain names. If the response contains invalid names, those records are filtered
// out and an error will be returned alongside the remaining results, if any.
//
// When using the host C library resolver, at most one result will be
// returned. To bypass the host resolver, use a custom Resolver.
//
// LookupAddr uses context.Background internally; to specify the context, use
// Resolver.LookupAddr.
func LookupAddr(addr string) (names []string, result Result, err error) {
	return DefaultResolver.LookupAddr(context.Background(), addr)
}

// LookupAddr performs a reverse lookup for the given address, returning a list
// of names mapping to that address.
//
// The returned names are validated to be properly formatted presentation-format
// domain names. If the response contains invalid names, those records are filtered
// out and an error will be returned alongside the remaining results, if any.
func (r *Resolver) LookupAddr(ctx context.Context, addr string) ([]string, Result, error) {
	names, result, err := r.lookupAddr(ctx, addr)
	if err != nil {
		return nil, result, err
	}
	filteredNames := make([]string, 0, len(names))
	for _, name := range names {
		if isDomainName(name) {
			filteredNames = append(filteredNames, name)
		}
	}
	if len(names) != len(filteredNames) {
		return filteredNames, result, &DNSError{Err: errMalformedDNSRecordsDetail, Name: addr}
	}
	return filteredNames, result, nil
}

// LookupTLSA calls LookupTLSA on the DefaultResolver.
func LookupTLSA(port int, protocol, host string) ([]TLSA, Result, error) {
	return DefaultResolver.LookupTLSA(context.Background(), port, protocol, host)
}

// LookupTLSA looks up a TLSA (TLS association) record for the port (service)
// and protocol (e.g. tcp, udp) at the host.
//
// LookupTLSA looks up DNS name "_<port>._<protocol>.host". Except when port is 0
// and protocol the empty string, then host is directly used to look up the TLSA
// record.
//
// Callers must check the Authentic field of the Result before using a TLSA
// record.
//
// Callers may want to handle DNSError with NotFound set to true (i.e. "nxdomain")
// differently from other errors. DANE support is often optional, with
// protocol-specific fallback behaviour.
//
// LookupTLSA follows CNAME records. For DANE, the secure/insecure DNSSEC
// response must be taken into account when following CNAMEs to determine the
// TLSA base domains. Callers should probably first resolve CNAMEs explicitly
// for their (in)secure status.
func (r *Resolver) LookupTLSA(ctx context.Context, port int, protocol, host string) (records []TLSA, result Result, err error) {
	return r.lookupTLSA(ctx, port, protocol, host)
}

// errMalformedDNSRecordsDetail is the DNSError detail which is returned when a Resolver.Lookup...
// method receives DNS records which contain invalid DNS names. This may be returned alongside
// results which have had the malformed records filtered out.
var errMalformedDNSRecordsDetail = "DNS response contained records which contain invalid names"

// dial makes a new connection to the provided server (which must be
// an IP address) with the provided network type, using either r.Dial
// (if both r and r.Dial are non-nil) or else Dialer.DialContext.
func (r *Resolver) dial(ctx context.Context, network, server string) (net.Conn, error) {
	// Calling Dial here is scary -- we have to be sure not to
	// dial a name that will require a DNS lookup, or Dial will
	// call back here to translate it. The DNS config parser has
	// already checked that all the cfg.servers are IP
	// addresses, which Dial will use without a DNS lookup.
	var c net.Conn
	var err error
	if r != nil && r.Dial != nil {
		c, err = r.Dial(ctx, network, server)
	} else {
		var d net.Dialer
		c, err = d.DialContext(ctx, network, server)
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return c, nil
}

// goLookupSRV returns the SRV records for a target name, built either
// from its component service ("sip"), protocol ("tcp"), and name
// ("example.com."), or from name directly (if service and proto are
// both empty).
//
// In either case, the returned target name ("_sip._tcp.example.com.")
// is also returned on success.
//
// The records are sorted by weight.
func (r *Resolver) goLookupSRV(ctx context.Context, service, proto, name string) (target string, srvs []*net.SRV, result Result, err error) {
	if service == "" && proto == "" {
		target = name
	} else {
		target = "_" + service + "._" + proto + "." + name
	}
	p, server, result, err := r.lookup(ctx, target, dnsmessage.TypeSRV, nil)
	if err != nil {
		return "", nil, result, err
	}
	var cname dnsmessage.Name
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return "", nil, result, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeSRV {
			if err := p.SkipAnswer(); err != nil {
				return "", nil, result, &DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		if cname.Length == 0 && h.Name.Length != 0 {
			cname = h.Name
		}
		srv, err := p.SRVResource()
		if err != nil {
			return "", nil, result, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		srvs = append(srvs, &net.SRV{Target: srv.Target.String(), Port: srv.Port, Priority: srv.Priority, Weight: srv.Weight})
	}
	byPriorityWeight(srvs).sort()
	return cname.String(), srvs, result, nil
}

// goLookupMX returns the MX records for name.
func (r *Resolver) goLookupMX(ctx context.Context, name string) ([]*net.MX, Result, error) {
	p, server, result, err := r.lookup(ctx, name, dnsmessage.TypeMX, nil)
	if err != nil {
		return nil, result, err
	}
	var mxs []*net.MX
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, result, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeMX {
			if err := p.SkipAnswer(); err != nil {
				return nil, result, &DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		mx, err := p.MXResource()
		if err != nil {
			return nil, result, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		mxs = append(mxs, &net.MX{Host: mx.MX.String(), Pref: mx.Pref})

	}
	byPref(mxs).sort()
	return mxs, result, nil
}

// goLookupNS returns the NS records for name.
func (r *Resolver) goLookupNS(ctx context.Context, name string) ([]*net.NS, Result, error) {
	p, server, result, err := r.lookup(ctx, name, dnsmessage.TypeNS, nil)
	if err != nil {
		return nil, result, err
	}
	var nss []*net.NS
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, result, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeNS {
			if err := p.SkipAnswer(); err != nil {
				return nil, result, &DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		ns, err := p.NSResource()
		if err != nil {
			return nil, result, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		nss = append(nss, &net.NS{Host: ns.NS.String()})
	}
	return nss, result, nil
}

// goLookupTXT returns the TXT records from name.
func (r *Resolver) goLookupTXT(ctx context.Context, name string) ([]string, Result, error) {
	p, server, result, err := r.lookup(ctx, name, dnsmessage.TypeTXT, nil)
	if err != nil {
		return nil, result, err
	}
	var txts []string
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, result, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeTXT {
			if err := p.SkipAnswer(); err != nil {
				return nil, result, &DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		txt, err := p.TXTResource()
		if err != nil {
			return nil, result, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		// Multiple strings in one TXT record need to be
		// concatenated without separator to be consistent
		// with previous Go resolver.
		n := 0
		for _, s := range txt.TXT {
			n += len(s)
		}
		txtJoin := make([]byte, 0, n)
		for _, s := range txt.TXT {
			txtJoin = append(txtJoin, s...)
		}
		if len(txts) == 0 {
			txts = make([]string, 0, 1)
		}
		txts = append(txts, string(txtJoin))
	}
	return txts, result, nil
}

const typeTLSA = dnsmessage.Type(52)

// goLookupTLSA is the native Go implementation of LookupTLSA.
func (r *Resolver) goLookupTLSA(ctx context.Context, port int, protocol, host string) ([]TLSA, Result, error) {
	var name string
	if port == 0 && protocol == "" {
		name = host
	} else {
		name = fmt.Sprintf("_%d._%s.%s", port, protocol, host)
	}
	p, server, result, err := r.lookup(ctx, name, typeTLSA, nil)
	if err != nil {
		return nil, result, err
	}
	var l []TLSA
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, result, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != typeTLSA {
			if err := p.SkipAnswer(); err != nil {
				return nil, result, &DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}

		r, err := p.UnknownResource()
		if err != nil || len(r.Data) < 3 {
			return nil, result, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		record := TLSA{
			TLSAUsage(r.Data[0]),
			TLSASelector(r.Data[1]),
			TLSAMatchType(r.Data[2]),
			nil,
		}
		// We do not verify the contents/size of the data. We don't want to filter out
		// values we don't understand. We'll leave it to the callers to see if a record is
		// usable. Also because special behaviour may be required if records were found but
		// all unusable.
		buf := make([]byte, len(r.Data)-3)
		copy(buf, r.Data[3:])
		record.CertAssoc = buf
		l = append(l, record)
	}
	return l, result, nil
}
