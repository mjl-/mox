package mox

import (
	"context"
	"fmt"
	"log/slog"
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

// DomainSPFIPs returns IPs to include in SPF records for domains. It includes the
// IPs on listeners that have SMTP enabled, and includes IPs configured for SOCKS
// transports.
func DomainSPFIPs() (ips []net.IP) {
	for _, l := range Conf.Static.Listeners {
		if !l.SMTP.Enabled || l.IPsNATed {
			continue
		}
		ipstrs := l.IPs
		if len(l.NATIPs) > 0 {
			ipstrs = l.NATIPs
		}
		for _, ipstr := range ipstrs {
			ip := net.ParseIP(ipstr)
			if ip.IsUnspecified() {
				continue
			}
			ips = append(ips, ip)
		}
	}
	for _, t := range Conf.Static.Transports {
		if t.Socks != nil {
			ips = append(ips, t.Socks.IPs...)
		}
	}
	return ips
}

// IPs returns ip addresses we may be listening/receiving mail on or
// connecting/sending from to the outside.
func IPs(ctx context.Context, receiveOnly bool) ([]net.IP, error) {
	log := pkglog.WithContext(ctx)

	// Try to gather all IPs we are listening on by going through the config.
	// If we encounter 0.0.0.0 or ::, we'll gather all local IPs afterwards.
	var ips []net.IP
	var ipv4all, ipv6all bool
	for _, l := range Conf.Static.Listeners {
		// If NATed, we don't know our external IPs.
		if l.IPsNATed {
			return nil, nil
		}
		check := l.IPs
		if len(l.NATIPs) > 0 {
			check = l.NATIPs
		}
		for _, s := range check {
			ip := net.ParseIP(s)
			if ip.IsUnspecified() {
				if ip.To4() != nil {
					ipv4all = true
				} else {
					ipv6all = true
				}
				continue
			}
			ips = append(ips, ip)
		}
	}

	// We'll list the IPs on the interfaces. How useful is this? There is a good chance
	// we're listening on all addresses because of a load balancer/firewall.
	if ipv4all || ipv6all {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("listing network interfaces: %v", err)
		}
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, fmt.Errorf("listing addresses for network interface: %v", err)
			}
			if len(addrs) == 0 {
				continue
			}

			for _, addr := range addrs {
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					log.Errorx("bad interface addr", err, slog.Any("address", addr))
					continue
				}
				v4 := ip.To4() != nil
				if ipv4all && v4 || ipv6all && !v4 {
					ips = append(ips, ip)
				}
			}
		}
	}

	if receiveOnly {
		return ips, nil
	}

	for _, t := range Conf.Static.Transports {
		if t.Socks != nil {
			ips = append(ips, t.Socks.IPs...)
		}
	}

	return ips, nil
}
