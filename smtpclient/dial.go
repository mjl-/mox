package smtpclient

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

// DialHook can be used during tests to override the regular dialer from being used.
var DialHook func(ctx context.Context, dialer Dialer, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error)

func dial(ctx context.Context, dialer Dialer, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
	// todo: see if we can remove this function and DialHook in favor of the Dialer interface.

	if DialHook != nil {
		return DialHook(ctx, dialer, timeout, addr, laddr)
	}

	// If this is a net.Dialer, use its settings and add the timeout and localaddr.
	// This is the typical case, but SOCKS5 support can use a different dialer.
	if d, ok := dialer.(*net.Dialer); ok {
		nd := *d
		nd.Timeout = timeout
		nd.LocalAddr = laddr
		return nd.DialContext(ctx, "tcp", addr)
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

// Dialer is used to dial mail servers, an interface to facilitate testing.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (c net.Conn, err error)
}

// Dial connects to host by dialing ips, taking previous attempts in dialedIPs into
// accounts (for greylisting, blocklisting and ipv4/ipv6).
//
// If the previous attempt used IPv4, this attempt will use IPv6 (in case one of
// the IPs is in a DNSBL).
// The second attempt for an address family we prefer the same IP as earlier, to
// increase our chances if remote is doing greylisting.
//
// Dial updates dialedIPs, callers may want to save it so it can be taken into
// account for future delivery attempts.
//
// If we have fully specified local SMTP listener IPs, we set those for the
// outgoing connection. The admin probably configured these same IPs in SPF, but
// others possibly not.
func Dial(ctx context.Context, log *mlog.Log, dialer Dialer, host dns.IPDomain, ips []net.IP, port int, dialedIPs map[string][]net.IP) (conn net.Conn, ip net.IP, rerr error) {
	timeout := 30 * time.Second
	if deadline, ok := ctx.Deadline(); ok && len(ips) > 0 {
		timeout = time.Until(deadline) / time.Duration(len(ips))
	}

	var lastErr error
	var lastIP net.IP
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		log.Debug("dialing host", mlog.Field("addr", addr))
		var laddr net.Addr
		for _, lip := range mox.Conf.Static.SpecifiedSMTPListenIPs {
			ipIs4 := ip.To4() != nil
			lipIs4 := lip.To4() != nil
			if ipIs4 == lipIs4 {
				laddr = &net.TCPAddr{IP: lip}
				break
			}
		}
		conn, err := dial(ctx, dialer, timeout, addr, laddr)
		if err == nil {
			log.Debug("connected to host", mlog.Field("host", host), mlog.Field("addr", addr), mlog.Field("laddr", laddr))
			name := host.String()
			dialedIPs[name] = append(dialedIPs[name], ip)
			return conn, ip, nil
		}
		log.Debugx("connection attempt", err, mlog.Field("host", host), mlog.Field("addr", addr), mlog.Field("laddr", laddr))
		lastErr = err
		lastIP = ip
	}
	// todo: possibly return all errors joined?
	return nil, lastIP, lastErr
}
