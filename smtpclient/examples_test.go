package smtpclient_test

import (
	"context"
	"crypto/tls"
	"log"
	"log/slog"
	"net"
	"slices"
	"strings"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtpclient"
)

func ExampleClient() {
	// Submit a message to an SMTP server, with authentication. The SMTP server is
	// responsible for getting the message delivered.

	// Make TCP connection to submission server.
	conn, err := net.Dial("tcp", "submit.example.org:465")
	if err != nil {
		log.Fatalf("dial submission server: %v", err)
	}
	defer conn.Close()

	// Initialize the SMTP session, with a EHLO, STARTTLS and authentication.
	// Verify the server TLS certificate with PKIX/WebPKI.
	ctx := context.Background()
	tlsVerifyPKIX := true
	opts := smtpclient.Opts{
		Auth: func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error) {
			// If the server is known to support a SCRAM PLUS variant, you should only use
			// that, detecting and preventing authentication mechanism downgrade attacks
			// through TLS channel binding.
			username := "mjl"
			password := "test1234"

			// Prefer strongest authentication mechanism, allow up to older CRAM-MD5.
			if cs != nil && slices.Contains(mechanisms, "SCRAM-SHA-256-PLUS") {
				return sasl.NewClientSCRAMSHA256PLUS(username, password, *cs), nil
			}
			if slices.Contains(mechanisms, "SCRAM-SHA-256") {
				return sasl.NewClientSCRAMSHA256(username, password, true), nil
			}
			if cs != nil && slices.Contains(mechanisms, "SCRAM-SHA-1-PLUS") {
				return sasl.NewClientSCRAMSHA1PLUS(username, password, *cs), nil
			}
			if slices.Contains(mechanisms, "SCRAM-SHA-1") {
				return sasl.NewClientSCRAMSHA1(username, password, true), nil
			}
			if slices.Contains(mechanisms, "CRAM-MD5") {
				return sasl.NewClientCRAMMD5(username, password), nil
			}
			// No mutually supported mechanism found, connection will fail.
			return nil, nil
		},
	}
	localname := dns.Domain{ASCII: "localhost"}
	remotename := dns.Domain{ASCII: "submit.example.org"}
	client, err := smtpclient.New(ctx, slog.Default(), conn, smtpclient.TLSImmediate, tlsVerifyPKIX, localname, remotename, opts)
	if err != nil {
		log.Fatalf("initialize smtp to submission server: %v", err)
	}
	defer client.Close()

	// Send the message to the server, which will add it to its queue.
	req8bitmime := false // ASCII-only, so 8bitmime not required.
	reqSMTPUTF8 := false // No UTF-8 headers, so smtputf8 not required.
	requireTLS := false  // Not supported by most servers at the time of writing.
	msg := "From: <mjl@example.org>\r\nTo: <other@example.org>\r\nSubject: hi\r\n\r\nnice to test you.\r\n"
	err = client.Deliver(ctx, "mjl@example.org", "other@example.com", int64(len(msg)), strings.NewReader(msg), req8bitmime, reqSMTPUTF8, requireTLS)
	if err != nil {
		log.Fatalf("submit message to smtp server: %v", err)
	}

	// Message has been submitted.
}
