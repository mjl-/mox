package dmarc_test

import (
	"context"
	"log"
	"log/slog"
	"net"
	"strings"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/spf"
)

func ExampleLookup() {
	ctx := context.Background()
	resolver := dns.StrictResolver{}
	msgFrom, err := dns.ParseDomain("sub.example.com")
	if err != nil {
		log.Fatalf("parsing from domain: %v", err)
	}

	// Lookup DMARC DNS record for domain.
	status, domain, record, txt, authentic, err := dmarc.Lookup(ctx, slog.Default(), resolver, msgFrom)
	if err != nil {
		log.Fatalf("dmarc lookup: %v", err)
	}

	log.Printf("status %s, domain %s, record %v, txt %q, dnssec %v", status, domain, record, txt, authentic)
}

func ExampleVerify() {
	ctx := context.Background()
	resolver := dns.StrictResolver{}

	// Message to verify.
	msg := strings.NewReader("From: <sender@example.com>\r\nMore: headers\r\n\r\nBody\r\n")
	msgFrom, _, _, err := message.From(slog.Default(), true, msg)
	if err != nil {
		log.Fatalf("parsing message for from header: %v", err)
	}

	// Verify SPF, for use with DMARC.
	args := spf.Args{
		RemoteIP:       net.ParseIP("10.11.12.13"),
		MailFromDomain: dns.Domain{ASCII: "sub.example.com"},
	}
	spfReceived, spfDomain, _, _, err := spf.Verify(ctx, slog.Default(), resolver, args)
	if err != nil {
		log.Printf("verifying spf: %v", err)
	}

	// Verify DKIM-Signature headers, for use with DMARC.
	smtputf8 := false
	ignoreTestMode := false
	dkimResults, err := dkim.Verify(ctx, slog.Default(), resolver, smtputf8, dkim.DefaultPolicy, msg, ignoreTestMode)
	if err != nil {
		log.Printf("verifying dkim: %v", err)
	}

	// Verify DMARC, based on DKIM and SPF results.
	applyRandomPercentage := true
	useResult, result := dmarc.Verify(ctx, slog.Default(), resolver, msgFrom.Domain, dkimResults, spfReceived.Result, &spfDomain, applyRandomPercentage)

	// Print results.
	log.Printf("dmarc status: %s", result.Status)
	log.Printf("use result: %v", useResult)
	if useResult && result.Reject {
		log.Printf("should reject message")
	}
	log.Printf("result: %#v", result)
}

func ExampleParseRecord() {
	txt := "v=DMARC1; p=reject; rua=mailto:postmaster@mox.example"

	record, isdmarc, err := dmarc.ParseRecord(txt)
	if err != nil {
		log.Fatalf("parsing dmarc record: %v (isdmarc: %v)", err, isdmarc)
	}

	log.Printf("parsed record: %v", record)
}
