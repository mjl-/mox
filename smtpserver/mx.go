package smtpserver

import (
	"context"
	"net"

	"github.com/mjl-/mox/dns"
)

// checks if domain can accept email.
// i.e. if it has no null mx record, regular mx records or resolve to an address.
func checkMXRecords(ctx context.Context, resolver dns.Resolver, d dns.Domain) (bool, error) {
	// Note: LookupMX can return an error and still return records.
	mx, _, err := resolver.LookupMX(ctx, d.ASCII+".")
	if err == nil && len(mx) == 1 && mx[0].Host == "." {
		// Null MX record, explicit signal that remote does not accept email.
		return false, nil
	}
	// Treat all errors that are not "no mx record" as temporary. E.g. timeout, malformed record, remote server error.
	if err != nil && !dns.IsNotFound(err) {
		return false, err
	}
	if len(mx) == 0 {
		mx = []*net.MX{{Host: d.ASCII + "."}}
	}
	var lastErr error
	for _, x := range mx {
		ips, _, err := resolver.LookupIPAddr(ctx, x.Host)
		if len(ips) > 0 {
			return true, nil
		}
		if err != nil && !dns.IsNotFound(err) {
			lastErr = err
		}
	}
	return false, lastErr
}
