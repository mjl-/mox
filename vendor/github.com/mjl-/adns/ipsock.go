// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package adns

import (
	"context"
	"net"

	"github.com/mjl-/adns/internal/bytealg"
)

// BUG(rsc,mikio): On DragonFly BSD and OpenBSD, listening on the
// "tcp" and "udp" networks does not listen for both IPv4 and IPv6
// connections. This is due to the fact that IPv4 traffic will not be
// routed to an IPv6 socket - two separate sockets are required if
// both address families are to be supported.
// See inet6(4) for details.

// An addrList represents a list of network endpoint addresses.
type addrList []net.Addr

// filterAddrList applies a filter to a list of IP addresses,
// yielding a list of Addr objects. Known filters are nil, ipv4only,
// and ipv6only. It returns every address when the filter is nil.
// The result contains at least one address when error is nil.
func filterAddrList(filter func(net.IPAddr) bool, ips []net.IPAddr, inetaddr func(net.IPAddr) net.Addr, originalAddr string) (addrList, error) {
	var addrs addrList
	for _, ip := range ips {
		if filter == nil || filter(ip) {
			addrs = append(addrs, inetaddr(ip))
		}
	}
	if len(addrs) == 0 {
		return nil, &net.AddrError{Err: errNoSuitableAddress.Error(), Addr: originalAddr}
	}
	return addrs, nil
}

// ipv4only reports whether addr is an IPv4 address.
func ipv4only(addr net.IPAddr) bool {
	return addr.IP.To4() != nil
}

// ipv6only reports whether addr is an IPv6 address except IPv4-mapped IPv6 address.
func ipv6only(addr net.IPAddr) bool {
	return len(addr.IP) == net.IPv6len && addr.IP.To4() == nil
}

// SplitHostPort splits a network address of the form "host:port",
// "host%zone:port", "[host]:port" or "[host%zone]:port" into host or
// host%zone and port.
//
// A literal IPv6 address in hostport must be enclosed in square
// brackets, as in "[::1]:80", "[::1%lo0]:80".
//
// See func Dial for a description of the hostport parameter, and host
// and port results.
func SplitHostPort(hostport string) (host, port string, err error) {
	const (
		missingPort   = "missing port in address"
		tooManyColons = "too many colons in address"
	)
	addrErr := func(addr, why string) (host, port string, err error) {
		return "", "", &net.AddrError{Err: why, Addr: addr}
	}
	j, k := 0, 0

	// The port starts after the last colon.
	i := last(hostport, ':')
	if i < 0 {
		return addrErr(hostport, missingPort)
	}

	if hostport[0] == '[' {
		// Expect the first ']' just before the last ':'.
		end := bytealg.IndexByteString(hostport, ']')
		if end < 0 {
			return addrErr(hostport, "missing ']' in address")
		}
		switch end + 1 {
		case len(hostport):
			// There can't be a ':' behind the ']' now.
			return addrErr(hostport, missingPort)
		case i:
			// The expected result.
		default:
			// Either ']' isn't followed by a colon, or it is
			// followed by a colon that is not the last one.
			if hostport[end+1] == ':' {
				return addrErr(hostport, tooManyColons)
			}
			return addrErr(hostport, missingPort)
		}
		host = hostport[1:end]
		j, k = 1, end+1 // there can't be a '[' resp. ']' before these positions
	} else {
		host = hostport[:i]
		if bytealg.IndexByteString(host, ':') >= 0 {
			return addrErr(hostport, tooManyColons)
		}
	}
	if bytealg.IndexByteString(hostport[j:], '[') >= 0 {
		return addrErr(hostport, "unexpected '[' in address")
	}
	if bytealg.IndexByteString(hostport[k:], ']') >= 0 {
		return addrErr(hostport, "unexpected ']' in address")
	}

	port = hostport[i+1:]
	return host, port, nil
}

func splitHostZone(s string) (host, zone string) {
	// The IPv6 scoped addressing zone identifier starts after the
	// last percent sign.
	if i := last(s, '%'); i > 0 {
		host, zone = s[:i], s[i+1:]
	} else {
		host = s
	}
	return
}

// JoinHostPort combines host and port into a network address of the
// form "host:port". If host contains a colon, as found in literal
// IPv6 addresses, then JoinHostPort returns "[host]:port".
//
// See func Dial for a description of the host and port parameters.
func JoinHostPort(host, port string) string {
	// We assume that host is a literal IPv6 address if host has
	// colons.
	if bytealg.IndexByteString(host, ':') >= 0 {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// internetAddrList resolves addr, which may be a literal IP
// address or a DNS name, and returns a list of internet protocol
// family addresses. The result contains at least one address when
// error is nil.
func (r *Resolver) internetAddrList(ctx context.Context, network, addr string) (addrList, Result, error) {
	var (
		err        error
		host, port string
		portnum    int
	)
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		if addr != "" {
			if host, port, err = SplitHostPort(addr); err != nil {
				return nil, Result{}, err
			}
			if portnum, err = r.LookupPort(ctx, network, port); err != nil {
				return nil, Result{}, err
			}
		}
	case "ip", "ip4", "ip6":
		if addr != "" {
			host = addr
		}
	default:
		return nil, Result{}, net.UnknownNetworkError(network)
	}
	inetaddr := func(ip net.IPAddr) net.Addr {
		switch network {
		case "tcp", "tcp4", "tcp6":
			return &net.TCPAddr{IP: ip.IP, Port: portnum, Zone: ip.Zone}
		case "udp", "udp4", "udp6":
			return &net.UDPAddr{IP: ip.IP, Port: portnum, Zone: ip.Zone}
		case "ip", "ip4", "ip6":
			return &net.IPAddr{IP: ip.IP, Zone: ip.Zone}
		default:
			panic("unexpected network: " + network)
		}
	}
	if host == "" {
		return addrList{inetaddr(net.IPAddr{})}, Result{}, nil
	}

	// Try as a literal IP address, then as a DNS name.
	ips, result, err := r.lookupIPAddr(ctx, network, host)
	if err != nil {
		return nil, result, err
	}
	// Issue 18806: if the machine has halfway configured
	// IPv6 such that it can bind on "::" (IPv6unspecified)
	// but not connect back to that same address, fall
	// back to dialing 0.0.0.0.
	if len(ips) == 1 && ips[0].IP.Equal(net.IPv6unspecified) {
		ips = append(ips, net.IPAddr{IP: net.IPv4zero})
	}

	var filter func(net.IPAddr) bool
	if network != "" && network[len(network)-1] == '4' {
		filter = ipv4only
	}
	if network != "" && network[len(network)-1] == '6' {
		filter = ipv6only
	}
	addrs, err := filterAddrList(filter, ips, inetaddr, host)
	return addrs, result, err
}
