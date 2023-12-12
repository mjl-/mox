package mtasts_test

import (
	"context"
	"errors"
	"log"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mtasts"
)

func ExampleGet() {
	ctx := context.Background()
	resolver := dns.StrictResolver{}

	// Get for example.org does a DNS TXT lookup at _mta-sts.example.org.
	// If the record exists, the policy is fetched from https://mta-sts.<domain>/.well-known/mta-sts.txt, and parsed.
	record, policy, policyText, err := mtasts.Get(ctx, slog.Default(), resolver, dns.Domain{ASCII: "example.org"})
	if err != nil {
		log.Printf("looking up mta-sts record and fetching policy: %v", err)
		if !errors.Is(err, mtasts.ErrDNS) {
			log.Printf("domain does not implement mta-sts")
		}
		// Continuing, we may have a record but not a policy.
	} else {
		log.Printf("domain implements mta-sts")
	}
	if record != nil {
		log.Printf("mta-sts DNS record: %#v", record)
	}
	if policy != nil {
		log.Printf("mta-sts policy: %#v", policy)
		log.Printf("mta-sts policy text:\n%s", policyText)
	}
}
