package dnsbl_test

import (
	"context"
	"log"
	"net"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dnsbl"
)

func ExampleLookup() {
	ctx := context.Background()
	resolver := dns.StrictResolver{}

	// Lookup if ip 127.0.0.2 is in spamhaus blocklist at zone sbl.spamhaus.org.
	status, explanation, err := dnsbl.Lookup(ctx, slog.Default(), resolver, dns.Domain{ASCII: "sbl.spamhaus.org"}, net.ParseIP("127.0.0.2"))
	if err != nil {
		log.Fatalf("dnsbl lookup: %v", err)
	}
	switch status {
	case dnsbl.StatusTemperr:
		log.Printf("dnsbl lookup, temporary dns error: %v", err)
	case dnsbl.StatusPass:
		log.Printf("dnsbl lookup, ip not listed")
	case dnsbl.StatusFail:
		log.Printf("dnsbl lookup, ip listed: %s", explanation)
	}
}
