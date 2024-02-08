package spf_test

import (
	"context"
	"log"
	"log/slog"
	"net"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/spf"
)

func ExampleVerify() {
	ctx := context.Background()
	resolver := dns.StrictResolver{}

	args := spf.Args{
		// IP from SMTP session.
		RemoteIP: net.ParseIP("1.2.3.4"),

		// Based on "MAIL FROM" in SMTP session.
		MailFromLocalpart: smtp.Localpart("user"),
		MailFromDomain:    dns.Domain{ASCII: "sendingdomain.example.com"},

		// From HELO/EHLO in SMTP session.
		HelloDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mx.example.com"}},

		// LocalIP and LocalHostname should be set, they may be used when evaluating macro's.
	}

	// Lookup SPF record and evaluate against IP and domain in args.
	received, domain, explanation, authentic, err := spf.Verify(ctx, slog.Default(), resolver, args)

	// received.Result is always set, regardless of err.
	switch received.Result {
	case spf.StatusNone:
		log.Printf("no useful spf result, domain probably has no spf record")
	case spf.StatusNeutral:
		log.Printf("spf has no statement on ip, with \"?\" qualifier")
	case spf.StatusPass:
		log.Printf("ip is authorized")
	case spf.StatusFail:
		log.Printf("ip is not authorized, with \"-\" qualifier")
	case spf.StatusSoftfail:
		log.Printf("ip is probably not authorized, with \"~\" qualifier, softfail")
	case spf.StatusTemperror:
		log.Printf("temporary error, possibly dns lookup failure, try again soon")
	case spf.StatusPermerror:
		log.Printf("permanent error, possibly invalid spf records, later attempts likely have the same result")
	}
	if err != nil {
		log.Printf("error: %v", err)
	}
	if explanation != "" {
		log.Printf("explanation from remote about spf result: %s", explanation)
	}
	log.Printf("result is for domain %s", domain) // mailfrom or ehlo/ehlo.
	log.Printf("dns lookups dnssec-protected: %v", authentic)
}
