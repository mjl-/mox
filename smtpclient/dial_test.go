package smtpclient

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

func TestDialHost(t *testing.T) {
	// We mostly want to test that dialing a second time switches to the other address family.
	ctxbg := context.Background()
	log := mlog.New("smtpclient")

	resolver := dns.MockResolver{
		A: map[string][]string{
			"dualstack.example.": {"10.0.0.1"},
		},
		AAAA: map[string][]string{
			"dualstack.example.": {"2001:db8::1"},
		},
	}

	DialHook = func(ctx context.Context, dialer Dialer, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
		return nil, nil // No error, nil connection isn't used.
	}
	defer func() {
		DialHook = nil
	}()

	ipdomain := func(s string) dns.IPDomain {
		return dns.IPDomain{Domain: dns.Domain{ASCII: s}}
	}

	dialedIPs := map[string][]net.IP{}
	_, _, _, ips, dualstack, err := GatherIPs(ctxbg, log, resolver, ipdomain("dualstack.example"), dialedIPs)
	if err != nil || !reflect.DeepEqual(ips, []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("2001:db8::1")}) || !dualstack {
		t.Fatalf("expected err nil, address 10.0.0.1,2001:db8::1, dualstack true, got %v %v %v", err, ips, dualstack)
	}
	_, ip, err := Dial(ctxbg, log, nil, ipdomain("dualstack.example"), ips, 25, dialedIPs)
	if err != nil || ip.String() != "10.0.0.1" {
		t.Fatalf("expected err nil, address 10.0.0.1, dualstack true, got %v %v %v", err, ip, dualstack)
	}

	_, _, _, ips, dualstack, err = GatherIPs(ctxbg, log, resolver, ipdomain("dualstack.example"), dialedIPs)
	if err != nil || !reflect.DeepEqual(ips, []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("10.0.0.1")}) || !dualstack {
		t.Fatalf("expected err nil, address 2001:db8::1,10.0.0.1, dualstack true, got %v %v %v", err, ips, dualstack)
	}
	_, ip, err = Dial(ctxbg, log, nil, ipdomain("dualstack.example"), ips, 25, dialedIPs)
	if err != nil || ip.String() != "2001:db8::1" {
		t.Fatalf("expected err nil, address 2001:db8::1, dualstack true, got %v %v %v", err, ip, dualstack)
	}
}
