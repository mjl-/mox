package dane_test

import (
	"context"
	"crypto/x509"
	"log"

	"golang.org/x/exp/slog"

	"github.com/mjl-/adns"

	"github.com/mjl-/mox/dane"
	"github.com/mjl-/mox/dns"
)

func ExampleDial() {
	ctx := context.Background()
	resolver := dns.StrictResolver{}
	usages := []adns.TLSAUsage{adns.TLSAUsageDANETA, adns.TLSAUsageDANEEE}
	pkixRoots, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("system pkix roots: %v", err)
	}

	// Connect to SMTP server, use STARTTLS, and verify TLS certificate with DANE.
	conn, verifiedRecord, err := dane.Dial(ctx, slog.Default(), resolver, "tcp", "mx.example.com", usages, pkixRoots)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	log.Printf("connected, conn %v, verified record %s", conn, verifiedRecord)
}
