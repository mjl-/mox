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
	"math/big"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/scram"
	"github.com/mjl-/mox/smtp"
)

var zerohost dns.Domain
var localhost = dns.Domain{ASCII: "localhost"}

func TestClient(t *testing.T) {
	ctx := context.Background()
	log := mlog.New("smtpclient")

	type options struct {
		pipelining   bool
		ecodes       bool
		maxSize      int
		starttls     bool
		eightbitmime bool
		smtputf8     bool
		ehlo         bool

		tlsMode      TLSMode
		tlsHostname  dns.Domain
		need8bitmime bool
		needsmtputf8 bool
		auths        []string // Allowed mechanisms.

		nodeliver bool // For server, whether client will attempt a delivery.
	}

	// Make fake cert, and make it trusted.
	cert := fakeCert(t, false)
	mox.Conf.Static.TLS.CertPool = x509.NewCertPool()
	mox.Conf.Static.TLS.CertPool.AddCert(cert.Leaf)
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	test := func(msg string, opts options, auths []sasl.Client, expClientErr, expDeliverErr, expServerErr error) {
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
				if opts.auths != nil {
					writeline("250-AUTH " + strings.Join(opts.auths, " "))
				}
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
				case "SCRAM-SHA-1", "SCRAM-SHA-256":
					// Cannot fake/hardcode scram interactions.
					var h func() hash.Hash
					salt := scram.MakeRandom()
					var iterations int
					if t[0] == "SCRAM-SHA-1" {
						h = sha1.New
						iterations = 2 * 4096
					} else {
						h = sha256.New
						iterations = 4096
					}
					saltedPassword := scram.SaltPassword(h, "test", salt, iterations)

					clientFirst, err := base64.StdEncoding.DecodeString(t[1])
					if err != nil {
						fail("bad base64: %w", err)
					}
					s, err := scram.NewServer(h, clientFirst)
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
				readline("RCPT TO:")
				writeline("250 ok")
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
					readline("RCPT TO:")
					writeline("250 ok")
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

		go func() {
			defer func() {
				x := recover()
				if x != nil && x != "stop" {
					panic(x)
				}
			}()
			fail := func(format string, args ...any) {
				result <- fmt.Errorf("client: %w", fmt.Errorf(format, args...))
				panic("stop")
			}
			c, err := New(ctx, log, clientConn, opts.tlsMode, localhost, opts.tlsHostname, auths)
			if (err == nil) != (expClientErr == nil) || err != nil && !errors.As(err, reflect.New(reflect.ValueOf(expClientErr).Type()).Interface()) && !errors.Is(err, expClientErr) {
				fail("new client: got err %v, expected %#v", err, expClientErr)
			}
			if err != nil {
				result <- nil
				return
			}
			err = c.Deliver(ctx, "postmaster@mox.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), opts.need8bitmime, opts.needsmtputf8)
			if (err == nil) != (expDeliverErr == nil) || err != nil && !errors.Is(err, expDeliverErr) {
				fail("first deliver: got err %v, expected %v", err, expDeliverErr)
			}
			if err == nil {
				err = c.Reset()
				if err != nil {
					fail("reset: %v", err)
				}
				err = c.Deliver(ctx, "postmaster@mox.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), opts.need8bitmime, opts.needsmtputf8)
				if (err == nil) != (expDeliverErr == nil) || err != nil && !errors.Is(err, expDeliverErr) {
					fail("second deliver: got err %v, expected %v", err, expDeliverErr)
				}
			}
			err = c.Close()
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

		tlsMode:      TLSStrictStartTLS,
		tlsHostname:  dns.Domain{ASCII: "mox.example"},
		need8bitmime: true,
		needsmtputf8: true,
	}

	test(msg, options{}, nil, nil, nil, nil)
	test(msg, allopts, nil, nil, nil, nil)
	test(msg, options{ehlo: true, eightbitmime: true}, nil, nil, nil, nil)
	test(msg, options{ehlo: true, eightbitmime: false, need8bitmime: true, nodeliver: true}, nil, nil, Err8bitmimeUnsupported, nil)
	test(msg, options{ehlo: true, smtputf8: false, needsmtputf8: true, nodeliver: true}, nil, nil, ErrSMTPUTF8Unsupported, nil)
	test(msg, options{ehlo: true, starttls: true, tlsMode: TLSStrictStartTLS, tlsHostname: dns.Domain{ASCII: "mismatch.example"}, nodeliver: true}, nil, ErrTLS, nil, &net.OpError{}) // Server TLS handshake is a net.OpError with "remote error" as text.
	test(msg, options{ehlo: true, maxSize: len(msg) - 1, nodeliver: true}, nil, nil, ErrSize, nil)
	test(msg, options{ehlo: true, auths: []string{"PLAIN"}}, []sasl.Client{sasl.NewClientPlain("test", "test")}, nil, nil, nil)
	test(msg, options{ehlo: true, auths: []string{"CRAM-MD5"}}, []sasl.Client{sasl.NewClientCRAMMD5("test", "test")}, nil, nil, nil)
	test(msg, options{ehlo: true, auths: []string{"SCRAM-SHA-1"}}, []sasl.Client{sasl.NewClientSCRAMSHA1("test", "test")}, nil, nil, nil)
	test(msg, options{ehlo: true, auths: []string{"SCRAM-SHA-256"}}, []sasl.Client{sasl.NewClientSCRAMSHA256("test", "test")}, nil, nil, nil)
	// todo: add tests for failing authentication, also at various stages in SCRAM

	// Set an expired certificate. For non-strict TLS, we should still accept it.
	// ../rfc/7435:424
	cert = fakeCert(t, true)
	mox.Conf.Static.TLS.CertPool = x509.NewCertPool()
	mox.Conf.Static.TLS.CertPool.AddCert(cert.Leaf)
	tlsConfig = tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	test(msg, options{ehlo: true, starttls: true}, nil, nil, nil, nil)

	// Again with empty cert pool so it isn't trusted in any way.
	mox.Conf.Static.TLS.CertPool = x509.NewCertPool()
	tlsConfig = tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	test(msg, options{ehlo: true, starttls: true}, nil, nil, nil, nil)
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	log := mlog.New("")

	// Invalid greeting.
	run(t, func(s xserver) {
		s.writeline("bogus") // Invalid, should be "220 <hostname>".
	}, func(conn net.Conn) {
		_, err := New(ctx, log, conn, TLSOpportunistic, localhost, zerohost, nil)
		var xerr Error
		if err == nil || !errors.Is(err, ErrProtocol) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrProtocol without Permanent", err))
		}
	})

	// Server just closes connection.
	run(t, func(s xserver) {
		s.conn.Close()
	}, func(conn net.Conn) {
		_, err := New(ctx, log, conn, TLSOpportunistic, localhost, zerohost, nil)
		var xerr Error
		if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v (%v), expected ErrUnexpectedEOF without Permanent", err, err))
		}
	})

	// Server does not want to speak SMTP.
	run(t, func(s xserver) {
		s.writeline("521 not accepting connections")
	}, func(conn net.Conn) {
		_, err := New(ctx, log, conn, TLSOpportunistic, localhost, zerohost, nil)
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || !xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with Permanent", err))
		}
	})

	// Server has invalid code in greeting.
	run(t, func(s xserver) {
		s.writeline("2200 mox.example") // Invalid, too many digits.
	}, func(conn net.Conn) {
		_, err := New(ctx, log, conn, TLSOpportunistic, localhost, zerohost, nil)
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
		_, err := New(ctx, log, conn, TLSOpportunistic, localhost, zerohost, nil)
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
		c, err := New(ctx, log, conn, TLSOpportunistic, localhost, zerohost, nil)
		if err != nil {
			panic(err)
		}
		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false)
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
		c, err := New(ctx, log, conn, TLSOpportunistic, localhost, zerohost, nil)
		if err != nil {
			panic(err)
		}
		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false)
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
		c, err := New(ctx, log, conn, TLSOpportunistic, localhost, zerohost, nil)
		if err != nil {
			panic(err)
		}
		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false)
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
		c, err := New(ctx, log, conn, TLSOpportunistic, localhost, zerohost, nil)
		if err != nil {
			panic(err)
		}
		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false)
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
		_, err := New(ctx, log, conn, TLSStrictStartTLS, localhost, dns.Domain{ASCII: "mox.example"}, nil)
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
		c, err := New(ctx, log, conn, TLSSkip, localhost, dns.Domain{ASCII: "mox.example"}, nil)
		if err != nil {
			panic(err)
		}
		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false)
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
		c, err := New(ctx, log, conn, TLSOpportunistic, localhost, zerohost, nil)
		if err != nil {
			panic(err)
		}

		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false)
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with non-Permanent", err))
		}

		// Another delivery.
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false)
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
		c, err := New(ctx, log, conn, TLSOpportunistic, localhost, zerohost, nil)
		if err != nil {
			panic(err)
		}

		msg := ""
		err = c.Deliver(ctx, "postmaster@other.example", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, false)
		var xerr Error
		if err == nil || !errors.Is(err, ErrStatus) || !errors.As(err, &xerr) || !xerr.Permanent {
			panic(fmt.Errorf("got %#v, expected ErrStatus with Permanent", err))
		}
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
