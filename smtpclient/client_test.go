package smtpclient

import (
	"bufio"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math/big"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/scram"
	"github.com/mjl-/mox/smtp"
)

var zerohost dns.Domain
var localhost = dns.Domain{ASCII: "localhost"}

func TestClient(t *testing.T) {
	ctx := context.Background()
	log := mlog.New("smtpclient", nil)

	mlog.SetConfig(map[string]slog.Level{"": mlog.LevelTrace})
	defer mlog.SetConfig(map[string]slog.Level{"": mlog.LevelDebug})

	type options struct {
		// Server behaviour.
		pipelining   bool
		ecodes       bool
		maxSize      int
		starttls     bool
		eightbitmime bool
		smtputf8     bool
		requiretls   bool
		ehlo         bool
		auths        []string // Allowed mechanisms.

		nodeliver bool // For server, whether client will attempt a delivery.

		// Client behaviour.
		tlsMode         TLSMode
		tlsPKIX         bool
		roots           *x509.CertPool
		tlsHostname     dns.Domain
		need8bitmime    bool
		needsmtputf8    bool
		needsrequiretls bool
		recipients      []string   // If nil, mjl@mox.example is used.
		resps           []Response // Checked only if non-nil.
	}

	// Make fake cert, and make it trusted.
	cert := fakeCert(t, false)
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	cleanupResp := func(resps []Response) []Response {
		for i, r := range resps {
			resps[i] = Response{Code: r.Code, Secode: r.Secode}
		}
		return resps
	}

	test := func(msg string, opts options, auth func(l []string, cs *tls.ConnectionState) (sasl.Client, error), expClientErr, expDeliverErr, expServerErr error) {
		t.Helper()

		if opts.tlsMode == "" {
			opts.tlsMode = TLSOpportunistic
		}

		clientConn, serverConn := net.Pipe()
		defer serverConn.Close()

		result := make(chan error, 2)

		go func() {
			defer func() {
				x := recover()
				if x != nil && x != "stop" {
					panic(x)
				}
			}()
			fail := func(format string, args ...any) {
				err := fmt.Errorf("server: %w", fmt.Errorf(format, args...))
				log.Errorx("failure", err)
				if err != nil && expServerErr != nil && (errors.Is(err, expServerErr) || errors.As(err, reflect.New(reflect.ValueOf(expServerErr).Type()).Interface())) {
					err = nil
				}
				result <- err
				panic("stop")
			}

			br := bufio.NewReader(serverConn)
			readline := func(prefix string) string {
				s, err := br.ReadString('\n')
				if err != nil {
					fail("expected command: %v", err)
				}
				if !strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix)) {
					fail("expected command %q, got: %s", prefix, s)
				}
				s = s[len(prefix):]
				return strings.TrimSuffix(s, "\r\n")
			}
			writeline := func(s string) {
				fmt.Fprintf(serverConn, "%s\r\n", s)
			}

			haveTLS := false

			ehlo := true // Initially we expect EHLO.
			var hello func()
			hello = func() {
				if !ehlo {
					readline("HELO")
					writeline("250 mox.example")
					return
				}

				readline("EHLO")

				if !opts.ehlo {
					// Client will try again with HELO.
					writeline("500 bad syntax")
					ehlo = false
					hello()
					return
				}

				writeline("250-mox.example")
				if opts.pipelining {
					writeline("250-PIPELINING")
				}
				if opts.maxSize > 0 {
					writeline(fmt.Sprintf("250-SIZE %d", opts.maxSize))
				}
				if opts.ecodes {
					writeline("250-ENHANCEDSTATUSCODES")
				}
				if opts.starttls && !haveTLS {
					writeline("250-STARTTLS")
				}
				if opts.eightbitmime {
					writeline("250-8BITMIME")
				}
				if opts.smtputf8 {
					writeline("250-SMTPUTF8")
				}
				if opts.requiretls && haveTLS {
					writeline("250-REQUIRETLS")
				}
				if opts.auths != nil {
					writeline("250-AUTH " + strings.Join(opts.auths, " "))
				}
				writeline("250-LIMITS MAILMAX=10 RCPTMAX=100 RCPTDOMAINMAX=1")
				writeline("250 UNKNOWN") // To be ignored.
			}

			writeline("220 mox.example ESMTP test")

			hello()

			if opts.starttls {
				readline("STARTTLS")
				writeline("220 go")
				tlsConn := tls.Server(serverConn, &tlsConfig)
				nctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				err := tlsConn.HandshakeContext(nctx)
				if err != nil {
					fail("tls handshake: %w", err)
				}
				serverConn = tlsConn
				br = bufio.NewReader(serverConn)

				haveTLS = true
				hello()
			}

			if opts.auths != nil {
				more := readline("AUTH ")
				t := strings.SplitN(more, " ", 2)
				switch t[0] {
				case "PLAIN":
					writeline("235 2.7.0 auth ok")
				case "CRAM-MD5":
					writeline("334 " + base64.StdEncoding.EncodeToString([]byte("<123.1234@host>")))
					readline("") // Proof
					writeline("235 2.7.0 auth ok")
				case "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256", "SCRAM-SHA-1-PLUS", "SCRAM-SHA-1":
					// Cannot fake/hardcode scram interactions.
					var h func() hash.Hash
					salt := scram.MakeRandom()
					var iterations int
					switch t[0] {
					case "SCRAM-SHA-1-PLUS", "SCRAM-SHA-1":
						h = sha1.New
						iterations = 2 * 4096
					case "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256":
						h = sha256.New
						iterations = 4096
					default:
						panic("missing case for scram")
					}
					var cs *tls.ConnectionState
					if strings.HasSuffix(t[0], "-PLUS") {
						if !haveTLS {
							writeline("501 scram plus without tls not possible")
							readline("QUIT")
							writeline("221 ok")
							result <- nil
							return
						}
						xcs := serverConn.(*tls.Conn).ConnectionState()
						cs = &xcs
					}
					saltedPassword := scram.SaltPassword(h, "test", salt, iterations)

					clientFirst, err := base64.StdEncoding.DecodeString(t[1])
					if err != nil {
						fail("bad base64: %w", err)
					}
					s, err := scram.NewServer(h, clientFirst, cs, cs != nil)
					if err != nil {
						fail("scram new server: %w", err)
					}
					serverFirst, err := s.ServerFirst(iterations, salt)
					if err != nil {
						fail("scram server first: %w", err)
					}
					writeline("334 " + base64.StdEncoding.EncodeToString([]byte(serverFirst)))

					xclientFinal := readline("")
					clientFinal, err := base64.StdEncoding.DecodeString(xclientFinal)
					if err != nil {
						fail("bad base64: %w", err)
					}
					serverFinal, err := s.Finish([]byte(clientFinal), saltedPassword)
					if err != nil {
						fail("scram finish: %w", err)
					}
					writeline("334 " + base64.StdEncoding.EncodeToString([]byte(serverFinal)))
					readline("")
					writeline("235 2.7.0 auth ok")
				default:
					writeline("501 unknown mechanism")
				}
			}

			if expClientErr == nil && !opts.nodeliver {
				readline("MAIL FROM:")
				writeline("250 ok")
				n := len(opts.recipients)
				if n == 0 {
					n = 1
				}
				for i := 0; i < n; i++ {
					readline("RCPT TO:")
					resp := "250 ok"
					if i < len(opts.resps) {
						resp = fmt.Sprintf("%d maybe", opts.resps[i].Code)
					}
					writeline(resp)
				}
				readline("DATA")
				writeline("354 continue")
				reader := smtp.NewDataReader(br)
				io.Copy(io.Discard, reader)
				writeline("250 ok")

				if expDeliverErr == nil {
					readline("RSET")
					writeline("250 ok")

					readline("MAIL FROM:")
					writeline("250 ok")
					for i := 0; i < n; i++ {
						readline("RCPT TO:")
						resp := "250 ok"
						if i < len(opts.resps) {
							resp = fmt.Sprintf("%d maybe", opts.resps[i].Code)
						}
						writeline(resp)
					}
					readline("DATA")
					writeline("354 continue")
					reader = smtp.NewDataReader(br)
					io.Copy(io.Discard, reader)
					writeline("250 ok")
				}
			}

			readline("QUIT")
			writeline("221 ok")
			result <- nil
		}()

		// todo: should abort tests more properly. on client failures, we may be left with hanging test.
		go func() {
			defer func() {
				x := recover()
				if x != nil && x != "stop" {
					panic(x)
				}
			}()
			fail := func(format string, args ...any) {
				err := fmt.Errorf("client: %w", fmt.Errorf(format, args...))
				log.Errorx("failure", err)
				result <- err
				panic("stop")
			}
			client, err := New(ctx, log.Logger, clientConn, opts.tlsMode, opts.tlsPKIX, localhost, opts.tlsHostname, Opts{Auth: auth, RootCAs: opts.roots})
			if (err == nil) != (expClientErr == nil) || err != nil && !errors.As(err, reflect.New(reflect.ValueOf(expClientErr).Type()).Interface()) && !errors.Is(err, expClientErr) {
				fail("new client: got err %v, expected %#v", err, expClientErr)
			}
			if err != nil {
				result <- nil
				return
			}
			rcptTo := opts.recipients
			if len(rcptTo) == 0 {
				rcptTo = []string{"mjl@mox.example"}
			}
			resps, err := client.DeliverMultiple(ctx, "postmaster@mox.example", rcptTo, int64(len(msg)), strings.NewReader(msg), opts.need8bitmime, opts.needsmtputf8, opts.needsrequiretls)
			if (err == nil) != (expDeliverErr == nil) || err != nil && !errors.Is(err, expDeliverErr) && !reflect.DeepEqual(err, expDeliverErr) {
				fail("first deliver: got err %#v (%s), expected %#v (%s)", err, err, expDeliverErr, expDeliverErr)
			} else if opts.resps != nil && !reflect.DeepEqual(cleanupResp(resps), opts.resps) {
				fail("first deliver: got resps %v, expected %v", resps, opts.resps)
			}
			if err == nil {
				err = client.Reset()
				if err != nil {
					fail("reset: %v", err)
				}
				resps, err = client.DeliverMultiple(ctx, "postmaster@mox.example", rcptTo, int64(len(msg)), strings.NewReader(msg), opts.need8bitmime, opts.needsmtputf8, opts.needsrequiretls)
				if (err == nil) != (expDeliverErr == nil) || err != nil && !errors.Is(err, expDeliverErr) && !reflect.DeepEqual(err, expDeliverErr) {
					fail("second deliver: got err %#v (%s), expected %#v (%s)", err, err, expDeliverErr, expDeliverErr)
				} else if opts.resps != nil && !reflect.DeepEqual(cleanupResp(resps), opts.resps) {
					fail("second: got resps %v, expected %v", resps, opts.resps)
				}
			}
			err = client.Close()
			if err != nil {
				fail("close client: %v", err)
			}
			result <- nil
		}()

		var errs []error
		for i := 0; i < 2; i++ {
			err := <-result
			if err != nil {
				errs = append(errs, err)
			}
		}
		if errs != nil {
			t.Fatalf("%v", errs)
		}
	}

	msg := strings.ReplaceAll(`From: <postmaster@mox.example>
To: <mjl@mox.example>
Subject: test

test
`, "\n", "\r\n")

	allopts := options{
		pipelining:   true,
		ecodes:       true,
		maxSize:      512,
		eightbitmime: true,
		smtputf8:     true,
		starttls:     true,
		ehlo:         true,
		requiretls:   true,

		tlsMode:         TLSRequiredStartTLS,
		tlsPKIX:         true,
		roots:           roots,
		tlsHostname:     dns.Domain{ASCII: "mox.example"},
		need8bitmime:    true,
		needsmtputf8:    true,
		needsrequiretls: true,
	}

	test(msg, options{}, nil, nil, nil, nil)
	test(msg, allopts, nil, nil, nil, nil)
	test(msg, options{ehlo: true, eightbitmime: true}, nil, nil, nil, nil)
	test(msg, options{ehlo: true, eightbitmime: false, need8bitmime: true, nodeliver: true}, nil, nil, Err8bitmimeUnsupported, nil)
	test(msg, options{ehlo: true, smtputf8: false, needsmtputf8: true, nodeliver: true}, nil, nil, ErrSMTPUTF8Unsupported, nil)

	// Server TLS handshake is a net.OpError with "remote error" as text.
	test(msg, options{ehlo: true, starttls: true, tlsMode: TLSRequiredStartTLS, tlsPKIX: true, tlsHostname: dns.Domain{ASCII: "mismatch.example"}, nodeliver: true}, nil, ErrTLS, nil, &net.OpError{})

	test(msg, options{ehlo: true, maxSize: len(msg) - 1, nodeliver: true}, nil, nil, ErrSize, nil)

	// Multiple recipients, not pipelined.
	multi1 := options{
		ehlo:       true,
		pipelining: true,
		ecodes:     true,
		recipients: []string{"mjl@mox.example", "mjl2@mox.example", "mjl3@mox.example"},
		resps: []Response{
			{Code: smtp.C250Completed},
			{Code: smtp.C250Completed},
			{Code: smtp.C250Completed},
		},
	}
	test(msg, multi1, nil, nil, nil, nil)
	multi1.pipelining = true
	test(msg, multi1, nil, nil, nil, nil)

	// Multiple recipients with 452 and other error, not pipelined
	multi2 := options{
		ehlo:       true,
		ecodes:     true,
		recipients: []string{"xmjl@mox.example", "xmjl2@mox.example", "xmjl3@mox.example"},
		resps: []Response{
			{Code: smtp.C250Completed},
			{Code: smtp.C554TransactionFailed}, // Will continue when not pipelined.
			{Code: smtp.C452StorageFull},       // Will stop sending further recipients.
		},
	}
	test(msg, multi2, nil, nil, nil, nil)
	multi2.pipelining = true
	test(msg, multi2, nil, nil, nil, nil)
	multi2.pipelining = false
	multi2.resps[2].Code = smtp.C552MailboxFull
	test(msg, multi2, nil, nil, nil, nil)
	multi2.pipelining = true
	test(msg, multi2, nil, nil, nil, nil)

	// Single recipient with error and pipelining is an error.
	multi3 := options{
		ehlo:       true,
		pipelining: true,
		ecodes:     true,
		recipients: []string{"xmjl@mox.example"},
		resps:      []Response{{Code: smtp.C452StorageFull}},
	}
	test(msg, multi3, nil, nil, Error{Code: smtp.C452StorageFull, Command: "rcptto", Line: "452 maybe"}, nil)

	authPlain := func(l []string, cs *tls.ConnectionState) (sasl.Client, error) {
		return sasl.NewClientPlain("test", "test"), nil
	}
	test(msg, options{ehlo: true, auths: []string{"PLAIN"}}, authPlain, nil, nil, nil)

	authCRAMMD5 := func(l []string, cs *tls.ConnectionState) (sasl.Client, error) {
		return sasl.NewClientCRAMMD5("test", "test"), nil
	}
	test(msg, options{ehlo: true, auths: []string{"CRAM-MD5"}}, authCRAMMD5, nil, nil, nil)

	// todo: add tests for failing authentication, also at various stages in SCRAM

	authSCRAMSHA1 := func(l []string, cs *tls.ConnectionState) (sasl.Client, error) {
		return sasl.NewClientSCRAMSHA1("test", "test", false), nil
	}
	test(msg, options{ehlo: true, auths: []string{"SCRAM-SHA-1"}}, authSCRAMSHA1, nil, nil, nil)

	authSCRAMSHA1PLUS := func(l []string, cs *tls.ConnectionState) (sasl.Client, error) {
		return sasl.NewClientSCRAMSHA1PLUS("test", "test", *cs), nil
	}
	test(msg, options{ehlo: true, starttls: true, auths: []string{"SCRAM-SHA-1-PLUS"}}, authSCRAMSHA1PLUS, nil, nil, nil)

	authSCRAMSHA256 := func(l []string, cs *tls.ConnectionState) (sasl.Client, error) {
		return sasl.NewClientSCRAMSHA256("test", "test", false), nil
	}
	test(msg, options{ehlo: true, auths: []string{"SCRAM-SHA-256"}}, authSCRAMSHA256, nil, nil, nil)

	authSCRAMSHA256PLUS := func(l []string, cs *tls.ConnectionState) (sasl.Client, error) {
		return sasl.NewClientSCRAMSHA256PLUS("test", "test", *cs), nil
	}
	test(msg, options{ehlo: true, starttls: true, auths: []string{"SCRAM-SHA-256-PLUS"}}, authSCRAMSHA256PLUS, nil, nil, nil)

	test(msg, options{ehlo: true, requiretls: false, needsrequiretls: true, nodeliver: true}, nil, nil, ErrRequireTLSUnsupported, nil)

	// Set an expired certificate. For non-strict TLS, we should still accept it.
	// ../rfc/7435:424
	cert = fakeCert(t, true)
	roots = x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	tlsConfig = tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	test(msg, options{ehlo: true, starttls: true, roots: roots}, nil, nil, nil, nil)

	// Again with empty cert pool so it isn't trusted in any way.
	roots = x509.NewCertPool()
	tlsConfig = tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	test(msg, options{ehlo: true, starttls: true, roots: roots}, nil, nil, nil, nil)
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	log := mlog.New("smtpclient", nil)

	// Invalid greeting.
	run(t, func(s xserver) {
		s.writeline("bogus") // Invalid, should be "220 <hostname>".
	}, func(conn net.Conn) {
		_, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		var xerr Error
		if err == nil || !errors.Is(err, ErrProtocol) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrProtocol without Permanent", err))
		}
	})

	// Server just closes connection.
	run(t, func(s xserver) {
		s.conn.Close()
	}, func(conn net.Conn) {
		_, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		var xerr Error
		if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v (%v), expected ErrUnexpectedEOF without Permanent", err, err))
		}
	})

	// Server does not want to speak SMTP.
	run(t, func(s xserver) {
		s.writeline("521 not accepting connections")
	}, func(conn net.Conn) {
		_, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || !xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with Permanent", err))
		}
	})

	// Server has invalid code in greeting.
	run(t, func(s xserver) {
		s.writeline("2200 mox.example") // Invalid, too many digits.
	}, func(conn net.Conn) {
		_, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		var xerr Error
		if err == nil || !errors.Is(err, ErrProtocol) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrProtocol without Permanent", err))
		}
	})

	// Server sends multiline response, but with different codes.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250-mox.example")
		s.writeline("500 different code") // Invalid.
	}, func(conn net.Conn) {
		_, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		var xerr Error
		if err == nil || !errors.Is(err, ErrProtocol) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrProtocol without Permanent", err))
		}
	})

	// Server permanently refuses MAIL FROM.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250-mox.example")
		s.writeline("250 ENHANCEDSTATUSCODES")
		s.readline("MAIL FROM:")
		s.writeline("550 5.7.0 not allowed")
	}, func(conn net.Conn) {
		c, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		if err != nil {
			panic(err)
		}
		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false, false)
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || !xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with Permanent", err))
		}
	})

	// Server temporarily refuses MAIL FROM.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250 mox.example")
		s.readline("MAIL FROM:")
		s.writeline("451 bad sender")
	}, func(conn net.Conn) {
		c, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		if err != nil {
			panic(err)
		}
		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false, false)
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with not-Permanent", err))
		}
	})

	// Server temporarily refuses RCPT TO.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250 mox.example")
		s.readline("MAIL FROM:")
		s.writeline("250 ok")
		s.readline("RCPT TO:")
		s.writeline("451")
	}, func(conn net.Conn) {
		c, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		if err != nil {
			panic(err)
		}
		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false, false)
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with not-Permanent", err))
		}
	})

	// Server permanently refuses DATA.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250 mox.example")
		s.readline("MAIL FROM:")
		s.writeline("250 ok")
		s.readline("RCPT TO:")
		s.writeline("250 ok")
		s.readline("DATA")
		s.writeline("550 no!")
	}, func(conn net.Conn) {
		c, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		if err != nil {
			panic(err)
		}
		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false, false)
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || !xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with Permanent", err))
		}
	})

	// TLS is required, so we attempt it regardless of whether it is advertised.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250 mox.example")
		s.readline("STARTTLS")
		s.writeline("502 command not implemented")
	}, func(conn net.Conn) {
		_, err := New(ctx, log.Logger, conn, TLSRequiredStartTLS, true, localhost, dns.Domain{ASCII: "mox.example"}, Opts{})
		var xerr Error
		if err == nil || !errors.Is(err, ErrTLS) || !errors.As(err, &xerr) || !xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrTLS with Permanent", err))
		}
	})

	// If TLS is available, but we don't want to use it, client should skip it.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250-mox.example")
		s.writeline("250 STARTTLS")
		s.readline("MAIL FROM:")
		s.writeline("451 enough")
	}, func(conn net.Conn) {
		c, err := New(ctx, log.Logger, conn, TLSSkip, false, localhost, dns.Domain{ASCII: "mox.example"}, Opts{})
		if err != nil {
			panic(err)
		}
		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false, false)
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with non-Permanent", err))
		}
	})

	// A transaction is aborted. If we try another one, we should send a RSET.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250 mox.example")
		s.readline("MAIL FROM:")
		s.writeline("250 ok")
		s.readline("RCPT TO:")
		s.writeline("451 not now")
		s.readline("RSET")
		s.writeline("250 ok")
		s.readline("MAIL FROM:")
		s.writeline("250 ok")
		s.readline("RCPT TO:")
		s.writeline("250 ok")
		s.readline("DATA")
		s.writeline("550 not now")
	}, func(conn net.Conn) {
		c, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		if err != nil {
			panic(err)
		}

		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false, false)
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with non-Permanent", err))
		}

		// Another delivery.
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false, false)
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || !xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with Permanent", err))
		}
	})

	// Remote closes connection after 550 response to MAIL FROM in pipelined
	// connection. Should result in permanent error, not temporary read error.
	// E.g. outlook.com that has your IP blocklisted.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250-mox.example")
		s.writeline("250 PIPELINING")
		s.readline("MAIL FROM:")
		s.writeline("550 ok")
	}, func(conn net.Conn) {
		c, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		if err != nil {
			panic(err)
		}

		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false, false)
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || !xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with Permanent", err))
		}
	})

	// Remote closes connection after 554 response to RCPT TO in pipelined
	// connection. Should result in permanent error, not temporary read error.
	// E.g. icloud.com that has your IP blocklisted.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250-mox.example")
		s.writeline("250-ENHANCEDSTATUSCODES")
		s.writeline("250 PIPELINING")
		s.readline("MAIL FROM:")
		s.writeline("250 2.1.0 ok")
		s.readline("RCPT TO:")
		s.writeline("554 5.7.0 Blocked")
	}, func(conn net.Conn) {
		c, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		if err != nil {
			panic(err)
		}

		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false, false)
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || !xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with Permanent", err))
		}
	})

	// If we try multiple recipients and first is 452, it is an error and a
	// non-pipelined deliver will be aborted.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250 mox.example")
		s.readline("MAIL FROM:")
		s.writeline("250 ok")
		s.readline("RCPT TO:")
		s.writeline("451 not now")
		s.readline("RCPT TO:")
		s.writeline("451 not now")
		s.readline("QUIT")
		s.writeline("250 ok")
	}, func(conn net.Conn) {
		c, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		if err != nil {
			panic(err)
		}

		msg := ""
		_, err = c.DeliverMultiple(ctx, "postmaster@other.example", []string{"mjl@mox.example", "mjl@mox.example"}, int64(len(msg)), strings.NewReader(msg), false, false, false)
		var xerr Error
		if err == nil || !errors.Is(err, errNoRecipients) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v (%s) expected errNoRecipients with non-Permanent", err, err))
		}
		c.Close()
	})

	// If we try multiple recipients and first is 452, it is an error and a pipelined
	// deliver will abort an allowed DATA.
	run(t, func(s xserver) {
		s.writeline("220 mox.example")
		s.readline("EHLO")
		s.writeline("250-mox.example")
		s.writeline("250 PIPELINING")
		s.readline("MAIL FROM:")
		s.writeline("250 ok")
		s.readline("RCPT TO:")
		s.writeline("451 not now")
		s.readline("RCPT TO:")
		s.writeline("451 not now")
		s.readline("DATA")
		s.writeline("354 ok")
		s.readline(".")
		s.writeline("503 no recipient")
		s.readline("QUIT")
		s.writeline("250 ok")
	}, func(conn net.Conn) {
		c, err := New(ctx, log.Logger, conn, TLSOpportunistic, false, localhost, zerohost, Opts{})
		if err != nil {
			panic(err)
		}

		msg := ""
		_, err = c.DeliverMultiple(ctx, "postmaster@other.example", []string{"mjl@mox.example", "mjl@mox.example"}, int64(len(msg)), strings.NewReader(msg), false, false, false)
		var xerr Error
		if err == nil || !errors.Is(err, errNoRecipientsPipelined) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v (%s), expected errNoRecipientsPipelined with non-Permanent", err, err))
		}
		c.Close()
	})
}

type xserver struct {
	conn net.Conn
	br   *bufio.Reader
}

func (s xserver) check(err error, msg string) {
	if err != nil {
		panic(fmt.Errorf("%s: %w", msg, err))
	}
}

func (s xserver) errorf(format string, args ...any) {
	panic(fmt.Errorf(format, args...))
}

func (s xserver) writeline(line string) {
	_, err := fmt.Fprintf(s.conn, "%s\r\n", line)
	s.check(err, "write")
}

func (s xserver) readline(prefix string) {
	line, err := s.br.ReadString('\n')
	s.check(err, "reading command")
	if !strings.HasPrefix(strings.ToLower(line), strings.ToLower(prefix)) {
		s.errorf("expected command %q, got: %s", prefix, line)
	}
}

func run(t *testing.T, server func(s xserver), client func(conn net.Conn)) {
	t.Helper()

	result := make(chan error, 2)
	clientConn, serverConn := net.Pipe()
	go func() {
		defer func() {
			serverConn.Close()
			x := recover()
			if x != nil {
				result <- fmt.Errorf("server: %v", x)
			} else {
				result <- nil
			}
		}()
		server(xserver{serverConn, bufio.NewReader(serverConn)})
	}()
	go func() {
		defer func() {
			clientConn.Close()
			x := recover()
			if x != nil {
				result <- fmt.Errorf("client: %v", x)
			} else {
				result <- nil
			}
		}()
		client(clientConn)
	}()
	var errs []error
	for i := 0; i < 2; i++ {
		err := <-result
		if err != nil {
			errs = append(errs, err)
		}
	}
	if errs != nil {
		t.Fatalf("errors: %v", errs)
	}
}

func TestLimits(t *testing.T) {
	check := func(s string, expLimits map[string]string, expMailMax, expRcptMax, expRcptDomainMax int) {
		t.Helper()
		limits, mailmax, rcptMax, rcptDomainMax := parseLimits([]byte(s))
		if !reflect.DeepEqual(limits, expLimits) || mailmax != expMailMax || rcptMax != expRcptMax || rcptDomainMax != expRcptDomainMax {
			t.Errorf("bad limits, got %v %d %d %d, expected %v %d %d %d, for %q", limits, mailmax, rcptMax, rcptDomainMax, expLimits, expMailMax, expRcptMax, expRcptDomainMax, s)
		}
	}
	check(" unknown=a=b -_1oK=xY", map[string]string{"UNKNOWN": "a=b", "-_1OK": "xY"}, 0, 0, 0)
	check(" MAILMAX=123 OTHER=ignored RCPTDOMAINMAX=1 RCPTMAX=321", map[string]string{"MAILMAX": "123", "OTHER": "ignored", "RCPTDOMAINMAX": "1", "RCPTMAX": "321"}, 123, 321, 1)
	check(" MAILMAX=invalid", map[string]string{"MAILMAX": "invalid"}, 0, 0, 0)
	check(" invalid syntax", nil, 0, 0, 0)
	check(" DUP=1 DUP=2", nil, 0, 0, 0)
}

// Just a cert that appears valid. SMTP client will not verify anything about it
// (that is opportunistic TLS for you, "better some than none"). Let's enjoy this
// one moment where it makes life easier.
func fakeCert(t *testing.T, expired bool) tls.Certificate {
	notAfter := time.Now()
	if expired {
		notAfter = notAfter.Add(-time.Hour)
	} else {
		notAfter = notAfter.Add(time.Hour)
	}

	privKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Fake key, don't use this for real!
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field...
		DNSNames:     []string{"mox.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	localCertBuf, err := x509.CreateCertificate(cryptorand.Reader, template, template, privKey.Public(), privKey)
	if err != nil {
		t.Fatalf("making certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(localCertBuf)
	if err != nil {
		t.Fatalf("parsing generated certificate: %s", err)
	}
	c := tls.Certificate{
		Certificate: [][]byte{localCertBuf},
		PrivateKey:  privKey,
		Leaf:        cert,
	}
	return c
}
