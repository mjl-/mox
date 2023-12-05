package dnsbl

import (
	"context"
	"net"
	"testing"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

func TestDNSBL(t *testing.T) {
	ctx := context.Background()
	log := mlog.New("dnsbl", nil)

	resolver := dns.MockResolver{
		A: map[string][]string{
			"2.0.0.127.example.com.": {"127.0.0.2"}, // required for health
			"1.0.0.10.example.com.":  {"127.0.0.2"},
			"b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.example.com.": {"127.0.0.2"},
		},
		TXT: map[string][]string{
			"1.0.0.10.example.com.": {"listed!"},
			"b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.example.com.": {"listed!"},
		},
	}

	if status, expl, err := Lookup(ctx, log.Logger, resolver, dns.Domain{ASCII: "example.com"}, net.ParseIP("10.0.0.1")); err != nil {
		t.Fatalf("lookup: %v", err)
	} else if status != StatusFail {
		t.Fatalf("lookup, got status %v, expected fail", status)
	} else if expl != "listed!" {
		t.Fatalf("lookup, got explanation %q", expl)
	}

	if status, expl, err := Lookup(ctx, log.Logger, resolver, dns.Domain{ASCII: "example.com"}, net.ParseIP("2001:db8:1:2:3:4:567:89ab")); err != nil {
		t.Fatalf("lookup: %v", err)
	} else if status != StatusFail {
		t.Fatalf("lookup, got status %v, expected fail", status)
	} else if expl != "listed!" {
		t.Fatalf("lookup, got explanation %q", expl)
	}

	if status, _, err := Lookup(ctx, log.Logger, resolver, dns.Domain{ASCII: "example.com"}, net.ParseIP("10.0.0.2")); err != nil {
		t.Fatalf("lookup: %v", err)
	} else if status != StatusPass {
		t.Fatalf("lookup, got status %v, expected pass", status)
	}

	// ../rfc/5782:357
	if err := CheckHealth(ctx, log.Logger, resolver, dns.Domain{ASCII: "example.com"}); err != nil {
		t.Fatalf("dnsbl not healthy: %v", err)
	}
	if err := CheckHealth(ctx, log.Logger, resolver, dns.Domain{ASCII: "example.org"}); err == nil {
		t.Fatalf("bad dnsbl is healthy")
	}

	unhealthyResolver := dns.MockResolver{
		A: map[string][]string{
			"1.0.0.127.example.com.": {"127.0.0.2"}, // Should not be present in healthy dnsbl.
		},
	}
	if err := CheckHealth(ctx, log.Logger, unhealthyResolver, dns.Domain{ASCII: "example.com"}); err == nil {
		t.Fatalf("bad dnsbl is healthy")
	}
}
