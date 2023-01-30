package smtp

import (
	"net"
)

// AddressLiteral returns an IPv4 or IPv6 address literal for use in SMTP.
func AddressLiteral(ip net.IP) string {
	// ../rfc/5321:2309
	s := "["
	if ip.To4() == nil {
		s += "IPv6:"
	}
	s += ip.String() + "]"
	return s
}
