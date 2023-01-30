package mox

import (
	"net"
)

// Network returns tcp4 or tcp6, depending on the ip.
// This network can be passed to Listen instead of "tcp", which may start listening
// on both ipv4 and ipv6 for addresses 0.0.0.0 and ::, which can lead to errors
// about the port already being in use.
// For invalid IPs, "tcp" is returned.
func Network(ip string) string {
	v := net.ParseIP(ip)
	if v == nil {
		return "tcp"
	}
	if v.To4() != nil {
		return "tcp4"
	}
	return "tcp6"
}
