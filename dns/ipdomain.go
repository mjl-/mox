package dns

import (
	"net"
)

// IPDomain is an ip address, a domain, or empty.
type IPDomain struct {
	IP     net.IP
	Domain Domain
}

// IsZero returns if both IP and Domain are zero.
func (d IPDomain) IsZero() bool {
	return d.IP == nil && d.Domain == Domain{}
}

// String returns a string representation of either the IP or domain (with
// UTF-8).
func (d IPDomain) String() string {
	if len(d.IP) > 0 {
		return d.IP.String()
	}
	return d.Domain.Name()
}

// LogString returns a string with both ASCII-only and optional UTF-8
// representation.
func (d IPDomain) LogString() string {
	if len(d.IP) > 0 {
		return d.IP.String()
	}
	return d.Domain.LogString()
}

// XString is like String, but only returns UTF-8 domains if utf8 is true.
func (d IPDomain) XString(utf8 bool) string {
	if d.IsIP() {
		// todo: check callers if this is valid syntax for them. should we add [] for ipv6? perhaps also ipv4? probably depends on context. in smtp, the syntax is [<ipv4>] and [IPv6:<ipv6>].
		return d.IP.String()
	}
	return d.Domain.XName(utf8)
}

func (d IPDomain) IsIP() bool {
	return len(d.IP) > 0
}

func (d IPDomain) IsDomain() bool {
	return !d.Domain.IsZero()
}
