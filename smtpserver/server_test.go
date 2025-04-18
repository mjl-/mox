package smtpserver

// todo: test delivery with failing spf/dkim/dmarc
// todo: test delivering a message to multiple recipients, and with some of them failing.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"mime/quotedprintable"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/subjectpass"
	"github.com/mjl-/mox/tlsrptdb"
	"github.com/mjl-/mox/webops"
)

var ctxbg = context.Background()

func init() {
	// Don't make tests slow.
	badClientDelay = 0
	authFailDelay = 0
	unknownRecipientsDelay = 0
}

func tcheck(t *testing.T, err error, msg string) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %s", msg, err)
	}
}

var submitMessage = strings.ReplaceAll(`From: <mjl@mox.example>
To: <remote@example.org>
Subject: test
Message-Id: <test@mox.example>

test email
`, "\n", "\r\n")

var deliverMessage = strings.ReplaceAll(`From: <remote@example.org>
To: <mjl@mox.example>
Subject: test
Message-Id: <test@example.org>

test email
`, "\n", "\r\n")

var deliverMessage2 = strings.ReplaceAll(`From: <remote@example.org>
To: <mjl@mox.example>
Subject: test
Message-Id: <test2@example.org>

test email, unique.
`, "\n", "\r\n")

type testserver struct {
	t            *testing.T
	acc          *store.Account
	switchStop   func()
	comm         *store.Comm
	cid          int64
	resolver     dns.Resolver
	auth         func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error)
	user, pass   string
	immediateTLS bool
	serverConfig *tls.Config
	clientConfig *tls.Config
	clientCert   *tls.Certificate // Passed to smtpclient for starttls authentication.
	submission   bool
	requiretls   bool
	dnsbls       []dns.Domain
	tlsmode      smtpclient.TLSMode
	tlspkix      bool
	xops         webops.XOps
}

const password0 = "te\u0301st \u00a0\u2002\u200a" // NFD and various unicode spaces.
const password1 = "tést    "                      // PRECIS normalized, with NFC.

func newTestServer(t *testing.T, configPath string, resolver dns.Resolver) *testserver {
	limitersInit() // Reset rate limiters.

	log := mlog.New("smtpserver", nil)

	checkf := func(ctx context.Context, err error, format string, args ...any) {
		tcheck(t, err, fmt.Sprintf(format, args...))
	}
	xops := webops.XOps{
		DBWrite: func(ctx context.Context, acc *store.Account, fn func(tx *bstore.Tx)) {
			err := acc.DB.Write(ctx, func(tx *bstore.Tx) error {
				fn(tx)
				return nil
			})
			tcheck(t, err, "db write")
		},
		Checkf:     checkf,
		Checkuserf: checkf,
	}

	ts := testserver{
		t:        t,
		cid:      1,
		resolver: resolver,
		tlsmode:  smtpclient.TLSOpportunistic,
		serverConfig: &tls.Config{
			Certificates: []tls.Certificate{fakeCert(t, false)},
		},
		xops: xops,
	}

	// Ensure session keys, for tests that check resume and authentication.
	ctx, cancel := context.WithCancel(ctxbg)
	defer cancel()
	mox.StartTLSSessionTicketKeyRefresher(ctx, log, ts.serverConfig)

	mox.Context = ctxbg
	mox.ConfigStaticPath = configPath
	mox.MustLoadConfig(true, false)
	dataDir := mox.ConfigDirPath(mox.Conf.Static.DataDir)
	os.RemoveAll(dataDir)

	err := dmarcdb.Init()
	tcheck(t, err, "dmarcdb init")
	err = tlsrptdb.Init()
	tcheck(t, err, "tlsrptdb init")
	err = store.Init(ctxbg)
	tcheck(t, err, "store init")

	ts.switchStop = store.Switchboard()
	err = queue.Init()
	tcheck(t, err, "queue init")

	ts.acc, err = store.OpenAccount(log, "mjl", false)
	tcheck(t, err, "open account")
	err = ts.acc.SetPassword(log, password0)
	tcheck(t, err, "set password")

	ts.comm = store.RegisterComm(ts.acc)

	return &ts
}

func (ts *testserver) close() {
	if ts.acc == nil {
		return
	}
	err := dmarcdb.Close()
	tcheck(ts.t, err, "dmarcdb close")
	err = tlsrptdb.Close()
	tcheck(ts.t, err, "tlsrptdb close")
	ts.comm.Unregister()
	queue.Shutdown()
	err = ts.acc.Close()
	tcheck(ts.t, err, "closing account")
	ts.acc.WaitClosed()
	ts.acc = nil
	ts.switchStop()
	err = store.Close()
	tcheck(ts.t, err, "store close")
}

func (ts *testserver) checkCount(mailboxName string, expect int) {
	t := ts.t
	t.Helper()
	q := bstore.QueryDB[store.Mailbox](ctxbg, ts.acc.DB)
	q.FilterNonzero(store.Mailbox{Name: mailboxName})
	q.FilterEqual("Expunged", false)
	mb, err := q.Get()
	tcheck(t, err, "get mailbox")
	qm := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB)
	qm.FilterNonzero(store.Message{MailboxID: mb.ID})
	qm.FilterEqual("Expunged", false)
	n, err := qm.Count()
	tcheck(t, err, "count messages in mailbox")
	if n != expect {
		t.Fatalf("messages in mailbox, found %d, expected %d", n, expect)
	}
}

func (ts *testserver) run(fn func(client *smtpclient.Client)) {
	ts.t.Helper()
	ts.runx(func(helloErr error, client *smtpclient.Client) {
		ts.t.Helper()
		tcheck(ts.t, helloErr, "hello")
		fn(client)
	})
}

func (ts *testserver) runx(fn func(helloErr error, client *smtpclient.Client)) {
	ts.t.Helper()
	ts.runRaw(func(conn net.Conn) {
		ts.t.Helper()

		auth := ts.auth
		if auth == nil && ts.user != "" {
			auth = func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error) {
				return sasl.NewClientPlain(ts.user, ts.pass), nil
			}
		}

		ourHostname := mox.Conf.Static.HostnameDomain
		remoteHostname := dns.Domain{ASCII: "mox.example"}
		opts := smtpclient.Opts{
			Auth:       auth,
			RootCAs:    mox.Conf.Static.TLS.CertPool,
			ClientCert: ts.clientCert,
		}
		log := pkglog.WithCid(ts.cid - 1)
		client, err := smtpclient.New(ctxbg, log.Logger, conn, ts.tlsmode, ts.tlspkix, ourHostname, remoteHostname, opts)
		if err != nil {
			conn.Close()
		} else {
			defer client.Close()
		}
		fn(err, client)
	})
}

func (ts *testserver) runRaw(fn func(clientConn net.Conn)) {
	ts.t.Helper()

	ts.cid += 2

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	// clientConn is closed as part of closing client.
	serverdone := make(chan struct{})
	defer func() { <-serverdone }()

	go func() {
		serve("test", ts.cid-2, dns.Domain{ASCII: "mox.example"}, ts.serverConfig, serverConn, ts.resolver, ts.submission, ts.immediateTLS, false, 100<<20, false, false, ts.requiretls, ts.dnsbls, 0)
		close(serverdone)
	}()

	if ts.immediateTLS {
		clientConn = tls.Client(clientConn, ts.clientConfig)
	}

	fn(clientConn)
}

func (ts *testserver) smtpErr(err error, expErr *smtpclient.Error) *smtpclient.Error {
	t := ts.t
	t.Helper()
	var cerr smtpclient.Error
	if expErr == nil && err != nil || expErr != nil && (err == nil || !errors.As(err, &cerr) || cerr.Permanent != expErr.Permanent || cerr.Code != expErr.Code || cerr.Secode != expErr.Secode) {
		t.Fatalf("got err:\n%#v (%q)\nexpected:\n%#v", err, err, expErr)
	}
	return &cerr
}

// Just a cert that appears valid. SMTP client will not verify anything about it
// (that is opportunistic TLS for you, "better some than none"). Let's enjoy this
// one moment where it makes life easier.
func fakeCert(t *testing.T, randomkey bool) tls.Certificate {
	seed := make([]byte, ed25519.SeedSize)
	if randomkey {
		cryptorand.Read(seed)
	}
	privKey := ed25519.NewKeyFromSeed(seed) // Fake key, don't use this for real!
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field...
		// Valid period is needed to get session resumption enabled.
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
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

// check expected dmarc evaluations for outgoing aggregate reports.
func checkEvaluationCount(t *testing.T, n int) []dmarcdb.Evaluation {
	t.Helper()
	l, err := dmarcdb.Evaluations(ctxbg)
	tcheck(t, err, "get dmarc evaluations")
	tcompare(t, len(l), n)
	return l
}

// Test submission from authenticated user.
func TestSubmission(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()

	// Set DKIM signing config.
	dom, _ := mox.Conf.Domain(dns.Domain{ASCII: "mox.example"})
	sel := config.Selector{
		HashEffective:    "sha256",
		HeadersEffective: []string{"From", "To", "Subject"},
		Key:              ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), // Fake key, don't use for real.
		Domain:           dns.Domain{ASCII: "mox.example"},
	}
	dom.DKIM = config.DKIM{
		Selectors: map[string]config.Selector{"testsel": sel},
		Sign:      []string{"testsel"},
	}
	mox.Conf.Dynamic.Domains["mox.example"] = dom

	testAuth := func(authfn func(user, pass string, cs *tls.ConnectionState) sasl.Client, user, pass string, expErr *smtpclient.Error) {
		t.Helper()
		if authfn != nil {
			ts.auth = func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error) {
				return authfn(user, pass, cs), nil
			}
		} else {
			ts.auth = nil
		}
		ts.runx(func(err error, client *smtpclient.Client) {
			mailFrom := "mjl@mox.example"
			rcptTo := "remote@example.org"
			if err == nil {
				err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(submitMessage)), strings.NewReader(submitMessage), false, false, false)
			}
			var cerr smtpclient.Error
			if expErr == nil && err != nil || expErr != nil && (err == nil || !errors.As(err, &cerr) || cerr.Code != expErr.Code || cerr.Secode != expErr.Secode) {
				t.Fatalf("got err:\n%#v (%q)\nexpected:\n%#v", err, err, expErr)
			}
			checkEvaluationCount(t, 0)
		})
	}

	acc, err := store.OpenAccount(pkglog, "disabled", false)
	tcheck(t, err, "open account")
	err = acc.SetPassword(pkglog, "test1234")
	tcheck(t, err, "set password")
	err = acc.Close()
	tcheck(t, err, "close account")

	ts.submission = true
	testAuth(nil, "", "", &smtpclient.Error{Permanent: true, Code: smtp.C530SecurityRequired, Secode: smtp.SePol7Other0})
	authfns := []func(user, pass string, cs *tls.ConnectionState) sasl.Client{
		func(user, pass string, cs *tls.ConnectionState) sasl.Client { return sasl.NewClientPlain(user, pass) },
		func(user, pass string, cs *tls.ConnectionState) sasl.Client { return sasl.NewClientLogin(user, pass) },
		func(user, pass string, cs *tls.ConnectionState) sasl.Client { return sasl.NewClientCRAMMD5(user, pass) },
		func(user, pass string, cs *tls.ConnectionState) sasl.Client {
			return sasl.NewClientSCRAMSHA1(user, pass, false)
		},
		func(user, pass string, cs *tls.ConnectionState) sasl.Client {
			return sasl.NewClientSCRAMSHA256(user, pass, false)
		},
		func(user, pass string, cs *tls.ConnectionState) sasl.Client {
			return sasl.NewClientSCRAMSHA1PLUS(user, pass, *cs)
		},
		func(user, pass string, cs *tls.ConnectionState) sasl.Client {
			return sasl.NewClientSCRAMSHA256PLUS(user, pass, *cs)
		},
	}
	for _, fn := range authfns {
		testAuth(fn, "mjl@mox.example", "test", &smtpclient.Error{Code: smtp.C535AuthBadCreds, Secode: smtp.SePol7AuthBadCreds8})           // Bad (short) password.
		testAuth(fn, "mjl@mox.example", password0+"test", &smtpclient.Error{Code: smtp.C535AuthBadCreds, Secode: smtp.SePol7AuthBadCreds8}) // Bad password.
		testAuth(fn, "mjl@mox.example", password0, nil)
		testAuth(fn, "mjl@mox.example", password1, nil)
		testAuth(fn, "móx@mox.example", password0, nil)
		testAuth(fn, "móx@mox.example", password1, nil)
		testAuth(fn, "mo\u0301x@mox.example", password0, nil)
		testAuth(fn, "mo\u0301x@mox.example", password1, nil)
		testAuth(fn, "disabled@mox.example", "test1234", &smtpclient.Error{Code: smtp.C525AccountDisabled, Secode: smtp.SePol7AccountDisabled13})
		testAuth(fn, "disabled@mox.example", "bogus", &smtpclient.Error{Code: smtp.C535AuthBadCreds, Secode: smtp.SePol7AuthBadCreds8})
	}

	// Create a certificate, register its public key with account, and make a tls
	// client config that sends the certificate.
	clientCert0 := fakeCert(ts.t, true)
	tlspubkey, err := store.ParseTLSPublicKeyCert(clientCert0.Certificate[0])
	tcheck(t, err, "parse certificate")
	tlspubkey.Account = "mjl"
	tlspubkey.LoginAddress = "mjl@mox.example"
	err = store.TLSPublicKeyAdd(ctxbg, &tlspubkey)
	tcheck(t, err, "add tls public key to account")
	ts.immediateTLS = true
	ts.clientConfig = &tls.Config{
		InsecureSkipVerify: true,
		Certificates: []tls.Certificate{
			clientCert0,
		},
	}

	// No explicit address in EXTERNAL.
	testAuth(func(user, pass string, cs *tls.ConnectionState) sasl.Client {
		return sasl.NewClientExternal(user)
	}, "", "", nil)

	// Same username in EXTERNAL as configured for key.
	testAuth(func(user, pass string, cs *tls.ConnectionState) sasl.Client {
		return sasl.NewClientExternal(user)
	}, "mjl@mox.example", "", nil)

	// Different username in EXTERNAL as configured for key, but same account.
	testAuth(func(user, pass string, cs *tls.ConnectionState) sasl.Client {
		return sasl.NewClientExternal(user)
	}, "móx@mox.example", "", nil)

	// Different username as configured for key, but same account, but not EXTERNAL auth.
	testAuth(func(user, pass string, cs *tls.ConnectionState) sasl.Client {
		return sasl.NewClientSCRAMSHA256PLUS(user, pass, *cs)
	}, "móx@mox.example", password0, nil)

	// Different account results in error.
	testAuth(func(user, pass string, cs *tls.ConnectionState) sasl.Client {
		return sasl.NewClientExternal(user)
	}, "☺@mox.example", "", &smtpclient.Error{Code: smtp.C535AuthBadCreds, Secode: smtp.SePol7AuthBadCreds8})

	// Starttls with client cert should authenticate too.
	ts.immediateTLS = false
	ts.clientCert = &clientCert0
	testAuth(func(user, pass string, cs *tls.ConnectionState) sasl.Client {
		return sasl.NewClientExternal(user)
	}, "", "", nil)
	ts.immediateTLS = true
	ts.clientCert = nil

	// Add a client session cache, so our connections will be resumed. We are testing
	// that the credentials are applied to resumed connections too.
	ts.clientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)
	testAuth(func(user, pass string, cs *tls.ConnectionState) sasl.Client {
		if cs.DidResume {
			panic("tls connection was resumed")
		}
		return sasl.NewClientExternal(user)
	}, "", "", nil)
	testAuth(func(user, pass string, cs *tls.ConnectionState) sasl.Client {
		if !cs.DidResume {
			panic("tls connection was not resumed")
		}
		return sasl.NewClientExternal(user)
	}, "", "", nil)

	// Unknown client certificate should fail the connection.
	serverConn, clientConn := net.Pipe()
	serverdone := make(chan struct{})
	defer func() { <-serverdone }()

	go func() {
		defer serverConn.Close()
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{fakeCert(ts.t, false)},
		}
		serve("test", ts.cid-2, dns.Domain{ASCII: "mox.example"}, tlsConfig, serverConn, ts.resolver, ts.submission, ts.immediateTLS, false, 100<<20, false, false, false, ts.dnsbls, 0)
		close(serverdone)
	}()

	defer clientConn.Close()

	// Authentication with an unknown/untrusted certificate should fail.
	clientCert1 := fakeCert(ts.t, true)
	ts.clientConfig.ClientSessionCache = nil
	ts.clientConfig.Certificates = []tls.Certificate{
		clientCert1,
	}
	clientConn = tls.Client(clientConn, ts.clientConfig)
	// note: It's not enough to do a handshake and check if that was successful. If the
	// client cert is not acceptable, we only learn after the handshake, when the first
	// data messages are exchanged.
	buf := make([]byte, 100)
	_, err = clientConn.Read(buf)
	if err == nil {
		t.Fatalf("tls handshake with unknown client certificate succeeded")
	}
	if alert, ok := mox.AsTLSAlert(err); !ok || alert != 42 {
		t.Fatalf("got err %#v, expected tls 'bad certificate' alert", err)
	}
}

func TestDomainDisabled(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()

	ts.submission = true
	ts.user = "mjl@mox.example"
	ts.pass = password0

	// Submission with SMTP MAIL FROM of disabled domain must fail.
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@disabled.example" // Disabled.
		rcptTo := "remote@example.org"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(submitMessage)), strings.NewReader(submitMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0})
		checkEvaluationCount(t, 0)
	})

	// Message From-address has disabled domain, must fail.
	var submitMessage2 = strings.ReplaceAll(`From: <mjl@disabled.example>
To: <remote@example.org>
Subject: test
Message-Id: <test@mox.example>

test email
`, "\n", "\r\n")
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@mox.example"
		rcptTo := "remote@example.org"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(submitMessage2)), strings.NewReader(submitMessage2), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0})
		checkEvaluationCount(t, 0)
	})
}

// Test delivery from external MTA.
func TestDelivery(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@[127.0.0.10]"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SeAddr1UnknownDestMailbox1})
	})

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@[IPv6:::1]"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SeAddr1UnknownDestMailbox1})
	})

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@test.example" // Not configured as destination.
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SeAddr1UnknownDestMailbox1})
	})

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "unknown@mox.example" // User unknown.
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SeAddr1UnknownDestMailbox1})
	})

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0})
	})

	// Set up iprev to get delivery from unknown user to be accepted.
	resolver.PTR["127.0.0.10"] = []string{"example.org."}

	// Only ascii o@ is configured, not the greek and cyrillic lookalikes.
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "ο@mox.example" // omicron \u03bf, looks like the configured o@
		msg := strings.ReplaceAll(deliverMessage, "mjl@mox.example", rcptTo)
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, true, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SeAddr1UnknownDestMailbox1})
	})

	// Deliveries to disabled domain are rejected with temporary error.
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@disabled.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C450MailboxUnavail, Secode: smtp.SeMailbox2Disabled1})
	})

	ts.run(func(client *smtpclient.Client) {
		recipients := []string{
			"mjl@mox.example",
			"o@mox.example",         // ascii o, as configured
			"\u2126@mox.example",    // ohm sign, as configured
			"ω@mox.example",         // lower-case omega, we match case-insensitively and this is the lowercase of ohm (!)
			"\u03a9@mox.example",    // capital omega, also lowercased to omega.
			"móx@mox.example",       // NFC
			"mo\u0301x@mox.example", // not NFC, but normalized as móx@, see https://go.dev/blog/normalization
		}

		for _, rcptTo := range recipients {
			// Ensure SMTP RCPT TO and message address headers are the same, otherwise the junk
			// filter treats us more strictly.
			msg := strings.ReplaceAll(deliverMessage, "mjl@mox.example", rcptTo)

			mailFrom := "remote@example.org"
			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, true, false)
			tcheck(t, err, "deliver to remote")

			changes := make(chan []store.Change)
			go func() {
				_, l := ts.comm.Get()
				changes <- l
			}()

			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			select {
			case <-changes:
			case <-timer.C:
				t.Fatalf("no delivery in 1s")
			}
		}
	})

	checkEvaluationCount(t, 0)
}

func tinsertmsg(t *testing.T, acc *store.Account, mailbox string, m *store.Message, msg string) {
	mf, err := store.CreateMessageTemp(pkglog, "insertmsg")
	tcheck(t, err, "temp message")
	defer os.Remove(mf.Name())
	defer mf.Close()
	_, err = mf.Write([]byte(msg))
	tcheck(t, err, "write message")

	acc.WithWLock(func() {
		err = acc.DeliverMailbox(pkglog, mailbox, m, mf)
		tcheck(t, err, "deliver message")
	})
}

func tretrain(t *testing.T, acc *store.Account) {
	t.Helper()

	// Fresh empty junkfilter.
	basePath := mox.DataDirPath("accounts")
	dbPath := filepath.Join(basePath, acc.Name, "junkfilter.db")
	bloomPath := filepath.Join(basePath, acc.Name, "junkfilter.bloom")
	os.Remove(dbPath)
	os.Remove(bloomPath)
	jf, _, err := acc.OpenJunkFilter(ctxbg, pkglog)
	tcheck(t, err, "open junk filter")
	defer jf.Close()

	// Fetch messags to retrain on.
	q := bstore.QueryDB[store.Message](ctxbg, acc.DB)
	q.FilterEqual("Expunged", false)
	q.FilterFn(func(m store.Message) bool {
		return m.Flags.Junk != m.Flags.Notjunk
	})
	msgs, err := q.List()
	tcheck(t, err, "fetch messages")

	// Retrain the messages.
	for _, m := range msgs {
		ham := m.Flags.Notjunk

		f, err := os.Open(acc.MessagePath(m.ID))
		tcheck(t, err, "open message")
		r := store.FileMsgReader(m.MsgPrefix, f)

		jf.TrainMessage(ctxbg, r, m.Size, ham)

		err = r.Close()
		tcheck(t, err, "close message")
	}

	err = jf.Save()
	tcheck(t, err, "save junkfilter")
}

// Test accept/reject with DMARC reputation and with spammy content.
func TestSpam(t *testing.T) {
	resolver := &dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.1"}, // For mx check.
		},
		TXT: map[string][]string{
			"example.org.":        {"v=spf1 ip4:127.0.0.10 -all"},
			"_dmarc.example.org.": {"v=DMARC1;p=reject; rua=mailto:dmarcrpt@example.org"},
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/junk/mox.conf"), resolver)
	defer ts.close()

	// Insert spammy messages. No junkfilter training yet.
	m := store.Message{
		RemoteIP:          "127.0.0.10",
		RemoteIPMasked1:   "127.0.0.10",
		RemoteIPMasked2:   "127.0.0.0",
		RemoteIPMasked3:   "127.0.0.0",
		MailFrom:          "remote@example.org",
		MailFromLocalpart: smtp.Localpart("remote"),
		MailFromDomain:    "example.org",
		RcptToLocalpart:   smtp.Localpart("mjl"),
		RcptToDomain:      "mox.example",
		MsgFromLocalpart:  smtp.Localpart("remote"),
		MsgFromDomain:     "example.org",
		MsgFromOrgDomain:  "example.org",
		MsgFromValidated:  true,
		MsgFromValidation: store.ValidationStrict,
		Flags:             store.Flags{Seen: true, Junk: true},
		Size:              int64(len(deliverMessage)),
	}
	for range 3 {
		nm := m
		tinsertmsg(t, ts.acc, "Inbox", &nm, deliverMessage)
		nm = m
		tinsertmsg(t, ts.acc, "mjl2", &nm, deliverMessage)
	}

	// Delivery from sender with bad reputation should fail.
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0})

		ts.checkCount("Rejects", 1)
		checkEvaluationCount(t, 0) // No positive interactions yet.
	})

	// Delivery from sender with bad reputation matching AcceptRejectsToMailbox should
	// result in accepted delivery to the mailbox.
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl2@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage2)), strings.NewReader(deliverMessage2), false, false, false)
		tcheck(t, err, "deliver")

		ts.checkCount("mjl2junk", 1) // In ruleset rejects mailbox.
		ts.checkCount("Rejects", 1)  // Same as before.
		checkEvaluationCount(t, 0)   // This is not an actual accept.
	})

	// Mark the messages as having good reputation.
	var ids []int64
	err := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB).FilterEqual("Expunged", false).ForEach(func(m store.Message) error {
		ids = append(ids, m.ID)
		return nil
	})
	tcheck(t, err, "get message ids")
	ts.xops.MessageFlagsClear(ctxbg, pkglog, ts.acc, ids, []string{"$Junk"})
	ts.xops.MessageFlagsAdd(ctxbg, pkglog, ts.acc, ids, []string{"$NotJunk"})

	// Message should now be accepted.
	ts.run(func(client *smtpclient.Client) {
		tcheck(t, err, "hello")
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		tcheck(t, err, "deliver")

		// Message should now be removed from Rejects mailboxes.
		ts.checkCount("Rejects", 0)
		ts.checkCount("mjl2junk", 1)
		checkEvaluationCount(t, 1)
	})

	// Undo dmarc pass, mark messages as junk, and train the filter.
	resolver.TXT = nil
	q := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB)
	q.FilterEqual("Expunged", false)
	_, err = q.UpdateFields(map[string]any{"Junk": true, "Notjunk": false})
	tcheck(t, err, "update junkiness")
	tretrain(t, ts.acc)

	// Message should be refused for spammy content.
	ts.run(func(client *smtpclient.Client) {
		tcheck(t, err, "hello")
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0})
		checkEvaluationCount(t, 1) // No new evaluation, this isn't a DMARC reject.
	})
}

// Test accept/reject with forwarded messages, DMARC ignored, no IP/EHLO/MAIL
// FROM-based reputation.
func TestForward(t *testing.T) {
	// Do a run without forwarding, and with.
	check := func(forward bool) {

		resolver := &dns.MockResolver{
			A: map[string][]string{
				"bad.example.":     {"127.0.0.1"},  // For mx check.
				"good.example.":    {"127.0.0.1"},  // For mx check.
				"forward.example.": {"127.0.0.10"}, // For mx check.
			},
			TXT: map[string][]string{
				"bad.example.":            {"v=spf1 ip4:127.0.0.1 -all"},
				"good.example.":           {"v=spf1 ip4:127.0.0.1 -all"},
				"forward.example.":        {"v=spf1 ip4:127.0.0.10 -all"},
				"_dmarc.bad.example.":     {"v=DMARC1;p=reject; rua=mailto:dmarc@bad.example"},
				"_dmarc.good.example.":    {"v=DMARC1;p=reject; rua=mailto:dmarc@good.example"},
				"_dmarc.forward.example.": {"v=DMARC1;p=reject; rua=mailto:dmarc@forward.example"},
			},
			PTR: map[string][]string{
				"127.0.0.10": {"forward.example."}, // For iprev check.
			},
		}
		rcptTo := "mjl3@mox.example"
		if !forward {
			// For SPF and DMARC pass, otherwise the test ends quickly.
			resolver.TXT["bad.example."] = []string{"v=spf1 ip4:127.0.0.10 -all"}
			resolver.TXT["good.example."] = []string{"v=spf1 ip4:127.0.0.10 -all"}
			rcptTo = "mjl@mox.example" // Without IsForward rule.
		}

		ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/junk/mox.conf"), resolver)
		defer ts.close()

		totalEvaluations := 0

		var msgBad = strings.ReplaceAll(`From: <remote@bad.example>
To: <mjl@mox.example>
Subject: test
Message-Id: <bad@example.org>

test email
`, "\n", "\r\n")
		var msgOK = strings.ReplaceAll(`From: <remote@good.example>
To: <mjl@mox.example>
Subject: other
Message-Id: <good@example.org>

unrelated message.
`, "\n", "\r\n")
		var msgOK2 = strings.ReplaceAll(`From: <other@forward.example>
To: <mjl@mox.example>
Subject: non-forward
Message-Id: <regular@example.org>

happens to come from forwarding mail server.
`, "\n", "\r\n")

		// Deliver forwarded messages, then classify as junk. Normally enough to treat
		// other unrelated messages from IP as junk, but not for forwarded messages.
		ts.run(func(client *smtpclient.Client) {
			mailFrom := "remote@forward.example"
			if !forward {
				mailFrom = "remote@bad.example"
			}

			for range 10 {
				err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msgBad)), strings.NewReader(msgBad), false, false, false)
				tcheck(t, err, "deliver message")
			}
			totalEvaluations += 10

			n, err := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB).UpdateFields(map[string]any{"Junk": true, "MsgFromValidated": true})
			tcheck(t, err, "marking messages as junk")
			tcompare(t, n, 10)
			tretrain(t, ts.acc)

			// Next delivery will fail, with negative "message From" signal.
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msgBad)), strings.NewReader(msgBad), false, false, false)
			ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0})

			checkEvaluationCount(t, totalEvaluations)
		})

		// Delivery from different "message From" without reputation, but from same
		// forwarding email server, should succeed under forwarding, not as regular sending
		// server.
		ts.run(func(client *smtpclient.Client) {
			mailFrom := "remote@forward.example"
			if !forward {
				mailFrom = "remote@good.example"
			}

			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msgOK)), strings.NewReader(msgOK), false, false, false)
			if forward {
				tcheck(t, err, "deliver")
				totalEvaluations += 1
			} else {
				ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0})
			}
			checkEvaluationCount(t, totalEvaluations)
		})

		// Delivery from forwarding server that isn't a forward should get same treatment.
		ts.run(func(client *smtpclient.Client) {
			mailFrom := "other@forward.example"

			// Ensure To header matches.
			msg := msgOK2
			if forward {
				msg = strings.ReplaceAll(msg, "<mjl@mox.example>", "<mjl3@mox.example>")
			}

			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
			if forward {
				tcheck(t, err, "deliver")
				totalEvaluations += 1
			} else {
				ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0})
			}
			checkEvaluationCount(t, totalEvaluations)
		})
	}

	check(true)
	check(false)
}

// Messages that we sent to, that have passing DMARC, but that are otherwise spammy, should be accepted.
func TestDMARCSent(t *testing.T) {
	resolver := &dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.1"}, // For mx check.
		},
		TXT: map[string][]string{
			"example.org.":        {"v=spf1 ip4:127.0.0.1 -all"},
			"_dmarc.example.org.": {"v=DMARC1;p=reject;rua=mailto:dmarcrpt@example.org"},
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/junk/mox.conf"), resolver)
	defer ts.close()

	// First check that DMARC policy rejects message and results in optional evaluation.
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7MultiAuthFails26})
		l := checkEvaluationCount(t, 1)
		tcompare(t, l[0].Optional, true)
	})

	// Update DNS for an SPF pass, and DMARC pass.
	resolver.TXT["example.org."] = []string{"v=spf1 ip4:127.0.0.10 -all"}

	// Insert hammy & spammy messages not related to the test message.
	m := store.Message{
		MailFrom:        "remote@test.example",
		RcptToLocalpart: smtp.Localpart("mjl"),
		RcptToDomain:    "mox.example",
		Flags:           store.Flags{Seen: true},
		Size:            int64(len(deliverMessage)),
	}
	// We need at least 50 ham messages for the junk filter to become significant. We
	// offset it with negative messages for mediocre score.
	for range 50 {
		nm := m
		nm.Junk = true
		tinsertmsg(t, ts.acc, "Archive", &nm, deliverMessage)

		nm = m
		nm.Notjunk = true
		tinsertmsg(t, ts.acc, "Archive", &nm, deliverMessage)
	}
	tretrain(t, ts.acc)

	// Baseline, message should be refused for spammy content.
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0})
		checkEvaluationCount(t, 1) // No new evaluation.
	})

	// Insert a message that we sent to the address that is about to send to us.
	sentMsg := store.Message{Size: int64(len(deliverMessage))}
	tinsertmsg(t, ts.acc, "Sent", &sentMsg, deliverMessage)
	err := ts.acc.DB.Insert(ctxbg, &store.Recipient{MessageID: sentMsg.ID, Localpart: "remote", Domain: "example.org", OrgDomain: "example.org", Sent: time.Now()})
	tcheck(t, err, "inserting message recipient")

	// Reject a message due to DMARC again. Since we sent a message to the domain, it
	// is no longer unknown and we should see a non-optional evaluation that will
	// result in a DMARC report.
	resolver.TXT["example.org."] = []string{"v=spf1 ip4:127.0.0.1 -all"}
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7MultiAuthFails26})
		l := checkEvaluationCount(t, 2) // New evaluation.
		tcompare(t, l[1].Optional, false)
	})

	// We should now be accepting the message because we recently sent a message.
	resolver.TXT["example.org."] = []string{"v=spf1 ip4:127.0.0.10 -all"}
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		tcheck(t, err, "deliver")
		l := checkEvaluationCount(t, 3) // New evaluation.
		tcompare(t, l[2].Optional, false)
	})
}

// Test DNSBL, then getting through with subjectpass.
func TestBlocklistedSubjectpass(t *testing.T) {
	// Set up a DNSBL on dnsbl.example, and get DMARC pass.
	resolver := &dns.MockResolver{
		A: map[string][]string{
			"example.org.":              {"127.0.0.10"}, // For mx check.
			"2.0.0.127.dnsbl.example.":  {"127.0.0.2"},  // For healthcheck.
			"10.0.0.127.dnsbl.example.": {"127.0.0.10"}, // Where our connection pretends to come from.
		},
		TXT: map[string][]string{
			"10.0.0.127.dnsbl.example.": {"blocklisted"},
			"example.org.":              {"v=spf1 ip4:127.0.0.10 -all"},
			"_dmarc.example.org.":       {"v=DMARC1;p=reject"},
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."}, // For iprev check.
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	ts.dnsbls = []dns.Domain{{ASCII: "dnsbl.example"}}
	defer ts.close()

	// Message should be refused softly (temporary error) due to DNSBL.
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0})
	})

	// Set up subjectpass on account.
	acc := mox.Conf.Dynamic.Accounts[ts.acc.Name]
	acc.SubjectPass.Period = time.Hour
	mox.Conf.Dynamic.Accounts[ts.acc.Name] = acc

	// Message should be refused quickly (permanent error) due to DNSBL and Subjectkey.
	var pass string
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		cerr := ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7DeliveryUnauth1})
		i := strings.Index(cerr.Line, subjectpass.Explanation)
		if i < 0 {
			t.Fatalf("got error line %q, expected error line with subjectpass", cerr.Line)
		}
		pass = cerr.Line[i+len(subjectpass.Explanation):]
	})

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		passMessage := strings.Replace(deliverMessage, "Subject: test", "Subject: test "+pass, 1)
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(passMessage)), strings.NewReader(passMessage), false, false, false)
		tcheck(t, err, "deliver with subjectpass")
	})
}

// Test accepting a DMARC report.
func TestDMARCReport(t *testing.T) {
	resolver := &dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		TXT: map[string][]string{
			"example.org.":        {"v=spf1 ip4:127.0.0.10 -all"},
			"_dmarc.example.org.": {"v=DMARC1;p=reject; rua=mailto:dmarcrpt@example.org"},
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."}, // For iprev check.
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/dmarcreport/mox.conf"), resolver)
	defer ts.close()

	run := func(rcptTo, report string, n int) {
		t.Helper()
		ts.run(func(client *smtpclient.Client) {
			t.Helper()

			mailFrom := "remote@example.org"

			msgb := &bytes.Buffer{}
			_, xerr := fmt.Fprintf(msgb, "From: %s\r\nTo: %s\r\nSubject: dmarc report\r\nMIME-Version: 1.0\r\nContent-Type: text/xml\r\n\r\n", mailFrom, rcptTo)
			tcheck(t, xerr, "write msg headers")
			w := quotedprintable.NewWriter(msgb)
			_, xerr = w.Write([]byte(strings.ReplaceAll(report, "\n", "\r\n")))
			tcheck(t, xerr, "write message")
			msg := msgb.String()

			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
			tcheck(t, err, "deliver")

			records, err := dmarcdb.Records(ctxbg)
			tcheck(t, err, "dmarcdb records")
			if len(records) != n {
				t.Fatalf("got %d dmarcdb records, expected %d or more", len(records), n)
			}
		})
	}

	n := 0
	run("dmarc-reports@mox.example", dmarcReport, 0) // Wrong domain in report.

	report := strings.ReplaceAll(dmarcReport, "xmox.nl", "mox.example")
	n++
	run("dmarc-reports@mox.example", report, n)

	// We always store as an evaluation, but as optional for reports.
	evals := checkEvaluationCount(t, 2)
	tcompare(t, evals[0].Optional, true)
	tcompare(t, evals[1].Optional, true)

	// Not a dmarc recipient, delivery should succeed.
	run("mjl@mox.example", report, n)
	run("mjl-test@mox.example", report, n)
	run("mjl+test@mox.example", report, n)
	// Likewise, address that is prefix of reporting address.
	run("dmarc@mox.example", report, n)
	run("Dmarc-test@mox.example", report, n)
	run("dmarc+test@mox.example", report, n)

	// Localpart catchall separators work for dmarc reporting addresses too.
	n++
	run("Dmarc-reports-test@mox.example", report, n)

	n++
	run("dmarc-Reports+test@mox.example", report, n)
}

const dmarcReport = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>example.org</org_name>
    <email>postmaster@example.org</email>
    <report_id>1</report_id>
    <date_range>
      <begin>1596412800</begin>
      <end>1596499199</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>xmox.nl</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>127.0.0.10</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>xmox.nl</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>xmox.nl</domain>
        <result>pass</result>
        <selector>testsel</selector>
      </dkim>
      <spf>
        <domain>xmox.nl</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>
`

// Test accepting a TLS report.
func TestTLSReport(t *testing.T) {
	// Requires setting up DKIM.
	privKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Fake key, don't use this for real!
	dkimRecord := dkim.Record{
		Version:   "DKIM1",
		Hashes:    []string{"sha256"},
		Flags:     []string{"s"},
		PublicKey: privKey.Public(),
		Key:       "ed25519",
	}
	dkimTxt, err := dkimRecord.Record()
	tcheck(t, err, "dkim record")

	sel := config.Selector{
		HashEffective:    "sha256",
		HeadersEffective: []string{"From", "To", "Subject", "Date"},
		Key:              privKey,
		Domain:           dns.Domain{ASCII: "testsel"},
	}
	dkimConf := config.DKIM{
		Selectors: map[string]config.Selector{"testsel": sel},
		Sign:      []string{"testsel"},
	}

	resolver := &dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		TXT: map[string][]string{
			"testsel._domainkey.example.org.": {dkimTxt},
			"_dmarc.example.org.":             {"v=DMARC1;p=reject;rua=mailto:dmarcrpt@example.org"},
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."}, // For iprev check.
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/tlsrpt/mox.conf"), resolver)
	defer ts.close()

	run := func(rcptTo, tlsrpt string, n int) {
		t.Helper()
		ts.run(func(client *smtpclient.Client) {
			t.Helper()

			mailFrom := "remote@example.org"

			msgb := &bytes.Buffer{}
			_, xerr := fmt.Fprintf(msgb, "From: %s\r\nTo: %s\r\nSubject: tlsrpt report\r\nMIME-Version: 1.0\r\nContent-Type: application/tlsrpt+json\r\n\r\n%s\r\n", mailFrom, rcptTo, tlsrpt)
			tcheck(t, xerr, "write msg")
			msg := msgb.String()

			selectors := mox.DKIMSelectors(dkimConf)
			headers, xerr := dkim.Sign(ctxbg, pkglog.Logger, "remote", dns.Domain{ASCII: "example.org"}, selectors, false, strings.NewReader(msg))
			tcheck(t, xerr, "dkim sign")
			msg = headers + msg

			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
			tcheck(t, err, "deliver")

			records, err := tlsrptdb.Records(ctxbg)
			tcheck(t, err, "tlsrptdb records")
			if len(records) != n {
				t.Fatalf("got %d tlsrptdb records, expected %d", len(records), n)
			}
		})
	}

	tlsrpt := `{"organization-name":"Example.org","date-range":{"start-datetime":"2022-01-07T00:00:00Z","end-datetime":"2022-01-07T23:59:59Z"},"contact-info":"tlsrpt@example.org","report-id":"1","policies":[{"policy":{"policy-type":"no-policy-found","policy-domain":"xmox.nl"},"summary":{"total-successful-session-count":1,"total-failure-session-count":0}}]}`

	n := 0
	run("tls-reports@mox.example", tlsrpt, n) // Wrong domain in report.

	tlsrptdom := strings.ReplaceAll(tlsrpt, "xmox.nl", "mox.example")
	n++
	run("tls-reports@mox.example", tlsrptdom, n)

	tlsrpthost := strings.ReplaceAll(tlsrpt, "xmox.nl", "mailhost.mox.example")
	n++
	run("tls-reports@mailhost.mox.example", tlsrpthost, n)

	// We always store as an evaluation, but as optional for reports.
	evals := checkEvaluationCount(t, 3)
	tcompare(t, evals[0].Optional, true)
	tcompare(t, evals[1].Optional, true)
	tcompare(t, evals[2].Optional, true)

	// Catchall separators work for reporting address too.
	n++
	run("Tls-reports+more@mox.example", tlsrptdom, n)
	n++
	run("tls-Reports-more@mox.example", tlsrptdom, n)

	// Non-reporting addresses, mail accepted, but not as report.
	run("mjl@mox.example", tlsrptdom, n)
	run("Mjl-other@mox.example", tlsrptdom, n)
	run("mjl+other@mox.example", tlsrptdom, n)
	// Likewise, address that is prefix of reporting address.
	run("tls@mox.example", tlsrptdom, n)
	run("Tls-other@mox.example", tlsrptdom, n)
	run("tls+other@mox.example", tlsrptdom, n)
}

func TestRatelimitConnectionrate(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()

	// We'll be creating 300 connections, no TLS and reduce noise.
	ts.tlsmode = smtpclient.TLSSkip
	mlog.SetConfig(map[string]slog.Level{"": mlog.LevelInfo})
	defer mlog.SetConfig(map[string]slog.Level{"": mlog.LevelDebug})

	// We may be passing a window boundary during this tests. The limit is 300/minute.
	// So make twice that many connections and hope the tests don't take too long.
	for i := 0; i <= 2*300; i++ {
		ts.runx(func(err error, client *smtpclient.Client) {
			t.Helper()
			if err != nil && i < 300 {
				t.Fatalf("expected smtp connection, got %v", err)
			}
			if err == nil && i == 600 {
				t.Fatalf("expected no smtp connection due to connection rate limit, got connection")
			}
			if client != nil {
				client.Close()
			}
		})
	}
}

func TestRatelimitAuth(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()

	ts.submission = true
	ts.tlsmode = smtpclient.TLSSkip
	ts.user = "bad"
	ts.pass = "bad"

	// We may be passing a window boundary during this tests. The limit is 10 auth
	// failures/minute. So make twice that many connections and hope the tests don't
	// take too long.
	for i := 0; i <= 2*10; i++ {
		ts.runx(func(err error, client *smtpclient.Client) {
			t.Helper()
			if err == nil {
				t.Fatalf("got auth success with bad credentials")
			}
			var cerr smtpclient.Error
			badauth := errors.As(err, &cerr) && cerr.Code == smtp.C535AuthBadCreds
			if !badauth && i < 10 {
				t.Fatalf("expected auth failure, got %v", err)
			}
			if badauth && i == 20 {
				t.Fatalf("expected no smtp connection due to failed auth rate limit, got other error %v", err)
			}
			if client != nil {
				client.Close()
			}
		})
	}
}

func TestRatelimitDelivery(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."},
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	orig := limitIPMasked1MessagesPerMinute
	limitIPMasked1MessagesPerMinute = 1
	defer func() {
		limitIPMasked1MessagesPerMinute = orig
	}()

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		tcheck(t, err, "deliver to remote")

		err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C452StorageFull, Secode: smtp.SeMailbox2Full2})
	})

	limitIPMasked1MessagesPerMinute = orig

	origSize := limitIPMasked1SizePerMinute
	// Message was already delivered once. We'll do another one. But the 3rd will fail.
	// We need the actual size with prepended headers, since that is used in the
	// calculations.
	msg, err := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB).Get()
	if err != nil {
		t.Fatalf("getting delivered message for its size: %v", err)
	}
	limitIPMasked1SizePerMinute = 2*msg.Size + int64(len(deliverMessage)/2)
	defer func() {
		limitIPMasked1SizePerMinute = origSize
	}()
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		tcheck(t, err, "deliver to remote")

		err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: false, Code: smtp.C452StorageFull, Secode: smtp.SeMailbox2Full2})
	})
}

func TestNonSMTP(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()
	ts.cid += 2

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	serverdone := make(chan struct{})
	defer func() { <-serverdone }()

	go func() {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{fakeCert(ts.t, false)},
		}
		serve("test", ts.cid-2, dns.Domain{ASCII: "mox.example"}, tlsConfig, serverConn, ts.resolver, ts.submission, false, false, 100<<20, false, false, false, ts.dnsbls, 0)
		close(serverdone)
	}()

	defer clientConn.Close()

	buf := make([]byte, 128)

	// Read and ignore hello.
	if _, err := clientConn.Read(buf); err != nil {
		t.Fatalf("reading hello: %v", err)
	}

	if _, err := fmt.Fprintf(clientConn, "bogus\r\n"); err != nil {
		t.Fatalf("write command: %v", err)
	}
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("read response line: %v", err)
	}
	s := string(buf[:n])
	if !strings.HasPrefix(s, "500 5.5.2 ") {
		t.Fatalf(`got %q, expected "500 5.5.2 ...`, s)
	}
	if _, err := clientConn.Read(buf); err == nil {
		t.Fatalf("connection not closed after bogus command")
	}
}

// Test limits on outgoing messages.
func TestLimitOutgoing(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtpserversendlimit/mox.conf"), dns.MockResolver{})
	defer ts.close()

	ts.user = "mjl@mox.example"
	ts.pass = password0
	ts.submission = true

	err := ts.acc.DB.Insert(ctxbg, &store.Outgoing{Recipient: "a@other.example", Submitted: time.Now().Add(-24*time.Hour - time.Minute)})
	tcheck(t, err, "inserting outgoing/recipient past 24h window")

	testSubmit := func(rcptTo string, expErr *smtpclient.Error) {
		t.Helper()
		ts.run(func(client *smtpclient.Client) {
			t.Helper()
			mailFrom := "mjl@mox.example"
			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(submitMessage)), strings.NewReader(submitMessage), false, false, false)
			ts.smtpErr(err, expErr)
		})
	}

	// Limits are set to 4 messages a day, 2 first-time recipients.
	testSubmit("b@other.example", nil)
	testSubmit("c@other.example", nil)
	testSubmit("d@other.example", &smtpclient.Error{Code: smtp.C451LocalErr, Secode: smtp.SePol7DeliveryUnauth1}) // Would be 3rd recipient.
	testSubmit("b@other.example", nil)
	testSubmit("b@other.example", nil)
	testSubmit("b@other.example", &smtpclient.Error{Code: smtp.C451LocalErr, Secode: smtp.SePol7DeliveryUnauth1}) // Would be 5th message.
}

// Test account size limit enforcement.
func TestQuota(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"other.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"other.example."},
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtpserverquota/mox.conf"), resolver)
	defer ts.close()

	testDeliver := func(rcptTo string, expErr *smtpclient.Error) {
		ts.run(func(client *smtpclient.Client) {
			mailFrom := "mjl@other.example"
			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
			ts.smtpErr(err, expErr)
		})
	}

	testDeliver("mjl@mox.example", &smtpclient.Error{Code: smtp.C452StorageFull, Secode: smtp.SeMailbox2Full2})
}

// Test with catchall destination address.
func TestCatchall(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"other.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"other.example."},
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtpservercatchall/mox.conf"), resolver)
	defer ts.close()

	testDeliver := func(rcptTo string, expErr *smtpclient.Error) {
		t.Helper()
		ts.run(func(client *smtpclient.Client) {
			t.Helper()
			mailFrom := "mjl@other.example"
			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(submitMessage)), strings.NewReader(submitMessage), false, false, false)
			ts.smtpErr(err, expErr)
		})
	}

	testDeliver("mjl@mox.example", nil)      // Exact match.
	testDeliver("mjl+test@mox.example", nil) // Domain localpart catchall separator.
	testDeliver("MJL+TEST@mox.example", nil) // Again, and case insensitive.

	n, err := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB).Count()
	tcheck(t, err, "checking delivered messages")
	tcompare(t, n, 3)

	testDeliver("unknown@mox.example", nil) // Catchall address, to account catchall.

	acc, err := store.OpenAccount(pkglog, "catchall", false)
	tcheck(t, err, "open account")
	defer func() {
		acc.Close()
		acc.WaitClosed()
	}()
	n, err = bstore.QueryDB[store.Message](ctxbg, acc.DB).Count()
	tcheck(t, err, "checking delivered messages to catchall account")
	tcompare(t, n, 1)

	testDeliver("mjl-test@mox2.example", nil)      // Second catchall separator.
	testDeliver("mjl-test+test@mox2.example", nil) // Silly, both separators in address.
	testDeliver("mjl+test-test@mox2.example", nil)
	n, err = bstore.QueryDB[store.Message](ctxbg, ts.acc.DB).Count()
	tcheck(t, err, "checking delivered messages")
	tcompare(t, n, 6)
}

// Test DKIM signing for outgoing messages.
func TestDKIMSign(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"mox.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"mox.example."},
		},
	}

	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	// Set DKIM signing config.
	var gen byte
	genDKIM := func(domain string) string {
		dom, _ := mox.Conf.Domain(dns.Domain{ASCII: domain})

		privkey := make([]byte, ed25519.SeedSize) // Fake key, don't use for real.
		gen++
		privkey[0] = byte(gen)

		sel := config.Selector{
			HashEffective:    "sha256",
			HeadersEffective: []string{"From", "To", "Subject"},
			Key:              ed25519.NewKeyFromSeed(privkey),
			Domain:           dns.Domain{ASCII: "testsel"},
		}
		dom.DKIM = config.DKIM{
			Selectors: map[string]config.Selector{"testsel": sel},
			Sign:      []string{"testsel"},
		}
		mox.Conf.Dynamic.Domains[domain] = dom
		pubkey := sel.Key.Public().(ed25519.PublicKey)
		return "v=DKIM1;k=ed25519;p=" + base64.StdEncoding.EncodeToString(pubkey)
	}

	dkimtxt := genDKIM("mox.example")
	dkimtxt2 := genDKIM("mox2.example")

	// DKIM verify needs to find the key.
	resolver.TXT = map[string][]string{
		"testsel._domainkey.mox.example.":  {dkimtxt},
		"testsel._domainkey.mox2.example.": {dkimtxt2},
	}

	ts.submission = true
	ts.user = "mjl@mox.example"
	ts.pass = password0

	n := 0
	testSubmit := func(mailFrom, msgFrom string) {
		t.Helper()
		ts.run(func(client *smtpclient.Client) {
			t.Helper()

			msg := strings.ReplaceAll(fmt.Sprintf(`From: <%s>
To: <remote@example.org>
Subject: test
Message-Id: <test@mox.example>

test email
`, msgFrom), "\n", "\r\n")

			rcptTo := "remote@example.org"
			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
			tcheck(t, err, "deliver")

			msgs, err := queue.List(ctxbg, queue.Filter{}, queue.Sort{})
			tcheck(t, err, "listing queue")
			n++
			tcompare(t, len(msgs), n)
			sort.Slice(msgs, func(i, j int) bool {
				return msgs[i].ID > msgs[j].ID
			})
			f, err := queue.OpenMessage(ctxbg, msgs[0].ID)
			tcheck(t, err, "open message in queue")
			defer f.Close()
			results, err := dkim.Verify(ctxbg, pkglog.Logger, resolver, false, dkim.DefaultPolicy, f, false)
			tcheck(t, err, "verifying dkim message")
			tcompare(t, len(results), 1)
			tcompare(t, results[0].Status, dkim.StatusPass)
			tcompare(t, results[0].Sig.Domain.ASCII, strings.Split(msgFrom, "@")[1])
		})
	}

	testSubmit("mjl@mox.example", "mjl@mox.example")
	testSubmit("mjl@mox.example", "mjl@mox2.example") // DKIM signature will be for mox2.example.
}

// Test to postmaster addresses.
func TestPostmaster(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"other.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"other.example."},
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/postmaster/mox.conf"), resolver)
	defer ts.close()

	testDeliver := func(rcptTo string, expErr *smtpclient.Error) {
		t.Helper()
		ts.run(func(client *smtpclient.Client) {
			t.Helper()
			mailFrom := "mjl@other.example"
			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
			ts.smtpErr(err, expErr)
		})
	}

	testDeliver("postmaster", nil)                  // Plain postmaster address without domain.
	testDeliver("postmaster@host.mox.example", nil) // Postmaster address with configured mail server hostname.
	testDeliver("postmaster@mox.example", nil)      // Postmaster address without explicitly configured destination.
	testDeliver("postmaster@unknown.example", &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SeAddr1UnknownDestMailbox1})
}

// Test to address with empty localpart.
func TestEmptylocalpart(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"other.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"other.example."},
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	testDeliver := func(rcptTo string, expErr *smtpclient.Error) {
		ts.run(func(client *smtpclient.Client) {
			mailFrom := `""@other.example`
			msg := strings.ReplaceAll(deliverMessage, "To: <mjl@mox.example>", `To: <""@mox.example>`)
			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
			ts.smtpErr(err, expErr)
		})
	}

	testDeliver(`""@mox.example`, nil)
}

// Test handling REQUIRETLS and TLS-Required: No.
func TestRequireTLS(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"mox.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"mox.example."},
		},
	}

	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	ts.submission = true
	ts.requiretls = true
	ts.user = "mjl@mox.example"
	ts.pass = password0

	no := false
	yes := true

	msg0 := strings.ReplaceAll(`From: <mjl@mox.example>
To: <remote@example.org>
Subject: test
Message-Id: <test@mox.example>
TLS-Required: No

test email
`, "\n", "\r\n")

	msg1 := strings.ReplaceAll(`From: <mjl@mox.example>
To: <remote@example.org>
Subject: test
Message-Id: <test@mox.example>
TLS-Required: No
TLS-Required: bogus

test email
`, "\n", "\r\n")

	msg2 := strings.ReplaceAll(`From: <mjl@mox.example>
To: <remote@example.org>
Subject: test
Message-Id: <test@mox.example>

test email
`, "\n", "\r\n")

	testSubmit := func(msg string, requiretls bool, expRequireTLS *bool) {
		t.Helper()
		ts.run(func(client *smtpclient.Client) {
			t.Helper()

			rcptTo := "remote@example.org"
			err := client.Deliver(ctxbg, "mjl@mox.example", rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, requiretls)
			tcheck(t, err, "deliver")

			msgs, err := queue.List(ctxbg, queue.Filter{}, queue.Sort{})
			tcheck(t, err, "listing queue")
			tcompare(t, len(msgs), 1)
			tcompare(t, msgs[0].RequireTLS, expRequireTLS)
			_, err = queue.Drop(ctxbg, pkglog, queue.Filter{IDs: []int64{msgs[0].ID}})
			tcheck(t, err, "deleting message from queue")
		})
	}

	testSubmit(msg0, true, &yes) // Header ignored, requiretls applied.
	testSubmit(msg0, false, &no) // TLS-Required header applied.
	testSubmit(msg1, true, &yes) // Bad headers ignored, requiretls applied.
	testSubmit(msg1, false, nil) // Inconsistent multiple headers ignored.
	testSubmit(msg2, false, nil) // Regular message, no RequireTLS setting.
	testSubmit(msg2, true, &yes) // Requiretls applied.

	// Check that we get an error if remote SMTP server does not support the requiretls
	// extension.
	ts.requiretls = false
	ts.run(func(client *smtpclient.Client) {
		rcptTo := "remote@example.org"
		err := client.Deliver(ctxbg, "mjl@mox.example", rcptTo, int64(len(msg0)), strings.NewReader(msg0), false, false, true)
		if err == nil {
			t.Fatalf("delivered with requiretls to server without requiretls")
		}
		if !errors.Is(err, smtpclient.ErrRequireTLSUnsupported) {
			t.Fatalf("got err %v, expected ErrRequireTLSUnsupported", err)
		}
	})
}

func TestSmuggle(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."}, // For iprev check.
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtpsmuggle/mox.conf"), resolver)
	ts.tlsmode = smtpclient.TLSSkip
	defer ts.close()

	test := func(data string) {
		t.Helper()

		ts.runRaw(func(conn net.Conn) {
			t.Helper()

			ourHostname := mox.Conf.Static.HostnameDomain
			remoteHostname := dns.Domain{ASCII: "mox.example"}
			opts := smtpclient.Opts{
				RootCAs: mox.Conf.Static.TLS.CertPool,
			}
			log := pkglog.WithCid(ts.cid - 1)
			_, err := smtpclient.New(ctxbg, log.Logger, conn, ts.tlsmode, ts.tlspkix, ourHostname, remoteHostname, opts)
			tcheck(t, err, "smtpclient")
			defer conn.Close()

			write := func(s string) {
				_, err := conn.Write([]byte(s))
				tcheck(t, err, "write")
			}

			readPrefixLine := func(prefix string) string {
				t.Helper()
				buf := make([]byte, 512)
				n, err := conn.Read(buf)
				tcheck(t, err, "read")
				s := strings.TrimRight(string(buf[:n]), "\r\n")
				if !strings.HasPrefix(s, prefix) {
					t.Fatalf("got smtp response %q, expected line with prefix %q", s, prefix)
				}
				return s
			}

			write("MAIL FROM:<remote@example.org>\r\n")
			readPrefixLine("2")
			write("RCPT TO:<mjl@mox.example>\r\n")
			readPrefixLine("2")

			write("DATA\r\n")
			readPrefixLine("3")
			write("\r\n") // Empty header.
			write(data)
			write("\r\n.\r\n") // End of message.
			line := readPrefixLine("5")
			if !strings.Contains(line, "smug") {
				t.Errorf("got 5xx error with message %q, expected error text containing smug", line)
			}
		})
	}

	test("\r\n.\n")
	test("\n.\n")
	test("\r.\r")
	test("\n.\r\n")
}

func TestFutureRelease(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	ts.tlsmode = smtpclient.TLSSkip
	ts.user = "mjl@mox.example"
	ts.pass = password0
	ts.submission = true
	defer ts.close()

	ts.auth = func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error) {
		return sasl.NewClientPlain(ts.user, ts.pass), nil
	}

	test := func(mailtoMore, expResponsePrefix string) {
		t.Helper()

		ts.runRaw(func(conn net.Conn) {
			t.Helper()

			ourHostname := mox.Conf.Static.HostnameDomain
			remoteHostname := dns.Domain{ASCII: "mox.example"}
			opts := smtpclient.Opts{Auth: ts.auth}
			log := pkglog.WithCid(ts.cid - 1)
			_, err := smtpclient.New(ctxbg, log.Logger, conn, ts.tlsmode, false, ourHostname, remoteHostname, opts)
			tcheck(t, err, "smtpclient")
			defer conn.Close()

			write := func(s string) {
				_, err := conn.Write([]byte(s))
				tcheck(t, err, "write")
			}

			readPrefixLine := func(prefix string) string {
				t.Helper()
				buf := make([]byte, 512)
				n, err := conn.Read(buf)
				tcheck(t, err, "read")
				s := strings.TrimRight(string(buf[:n]), "\r\n")
				if !strings.HasPrefix(s, prefix) {
					t.Fatalf("got smtp response %q, expected line with prefix %q", s, prefix)
				}
				return s
			}

			write(fmt.Sprintf("MAIL FROM:<mjl@mox.example>%s\r\n", mailtoMore))
			readPrefixLine(expResponsePrefix)
			if expResponsePrefix != "2" {
				return
			}
			write("RCPT TO:<mjl@mox.example>\r\n")
			readPrefixLine("2")

			write("DATA\r\n")
			readPrefixLine("3")
			write("From: <mjl@mox.example>\r\n\r\nbody\r\n\r\n.\r\n")
			readPrefixLine("2")
		})
	}

	test(" HOLDFOR=1", "2")
	test(" HOLDUNTIL="+time.Now().Add(time.Minute).UTC().Format(time.RFC3339), "2")
	test(" HOLDUNTIL="+time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), "2")

	test(" HOLDFOR=0", "501")                                                                                        // 0 is invalid syntax.
	test(fmt.Sprintf(" HOLDFOR=%d", int64((queue.FutureReleaseIntervalMax+time.Minute)/time.Second)), "554")         // Too far in the future.
	test(" HOLDUNTIL="+time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), "554")                               // In the past.
	test(" HOLDUNTIL="+time.Now().Add(queue.FutureReleaseIntervalMax+time.Minute).UTC().Format(time.RFC3339), "554") // Too far in the future.
	test(" HOLDUNTIL=2024-02-10T17:28:00+00:00", "501")                                                              // "Z" required.
	test(" HOLDUNTIL=24-02-10T17:28:00Z", "501")                                                                     // Invalid.
	test(" HOLDFOR=1 HOLDFOR=1", "501")                                                                              // Duplicate.
	test(" HOLDFOR=1 HOLDUNTIL="+time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "501")                        // Duplicate.
}

// Test SMTPUTF8
func TestSMTPUTF8(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()

	ts.user = "mjl@mox.example"
	ts.pass = password0
	ts.submission = true

	test := func(mailFrom string, rcptTo string, headerValue string, filename string, clientSmtputf8 bool, expectedSmtputf8 bool, expErr *smtpclient.Error) {
		t.Helper()

		ts.run(func(client *smtpclient.Client) {
			t.Helper()
			msg := strings.ReplaceAll(fmt.Sprintf(`From: <%s>
To: <%s>
Subject: test
X-Custom-Test-Header: %s
MIME-Version: 1.0
Content-type: multipart/mixed; boundary="simple boundary"

--simple boundary
Content-Type: text/plain; charset=UTF-8;
Content-Disposition: attachment; filename="%s"
Content-Transfer-Encoding: base64

QW4gYXR0YWNoZWQgdGV4dCBmaWxlLg==

--simple boundary--
`, mailFrom, rcptTo, headerValue, filename), "\n", "\r\n")

			err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), true, clientSmtputf8, false)
			ts.smtpErr(err, expErr)
			if err != nil {
				return
			}

			msgs, _ := queue.List(ctxbg, queue.Filter{}, queue.Sort{Field: "Queued", Asc: false})
			queuedMsg := msgs[0]
			if queuedMsg.SMTPUTF8 != expectedSmtputf8 {
				t.Fatalf("[%s / %s / %s / %s] got SMTPUTF8 %t, expected %t", mailFrom, rcptTo, headerValue, filename, queuedMsg.SMTPUTF8, expectedSmtputf8)
			}
		})
	}

	test(`mjl@mox.example`, `remote@example.org`, "header-ascii", "ascii.txt", false, false, nil)
	test(`mjl@mox.example`, `remote@example.org`, "header-ascii", "ascii.txt", true, false, nil)
	test(`mjl@mox.example`, `🙂@example.org`, "header-ascii", "ascii.txt", true, true, nil)
	test(`mjl@mox.example`, `🙂@example.org`, "header-ascii", "ascii.txt", false, true, &smtpclient.Error{Permanent: true, Code: smtp.C553BadMailbox, Secode: smtp.SeMsg6NonASCIIAddrNotPermitted7})
	test(`Ω@mox.example`, `remote@example.org`, "header-ascii", "ascii.txt", true, true, nil)
	test(`Ω@mox.example`, `remote@example.org`, "header-ascii", "ascii.txt", false, true, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SeMsg6NonASCIIAddrNotPermitted7})
	test(`mjl@mox.example`, `remote@example.org`, "header-utf8-😍", "ascii.txt", true, true, nil)
	test(`mjl@mox.example`, `remote@example.org`, "header-utf8-😍", "ascii.txt", false, true, nil)
	test(`mjl@mox.example`, `remote@example.org`, "header-ascii", "utf8-🫠️.txt", true, true, nil)
	test(`Ω@mox.example`, `🙂@example.org`, "header-utf8-😍", "utf8-🫠️.txt", true, true, nil)
	test(`mjl@mox.example`, `remote@xn--vg8h.example.org`, "header-ascii", "ascii.txt", true, false, nil)
}

// TestExtra checks whether submission of messages with "X-Mox-Extra-<key>: value"
// headers cause those those key/value pairs to be added to the Extra field in the
// queue.
func TestExtra(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()

	ts.user = "mjl@mox.example"
	ts.pass = password0
	ts.submission = true

	extraMsg := strings.ReplaceAll(`From: <mjl@mox.example>
To: <remote@example.org>
Subject: test
X-Mox-Extra-Test: testvalue
X-Mox-Extra-a: 123
X-Mox-Extra-☺: ☹
X-Mox-Extra-x-cANONICAL-z: ok
Message-Id: <test@mox.example>

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@mox.example"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(extraMsg)), strings.NewReader(extraMsg), true, true, false)
		tcheck(t, err, "deliver")
	})
	msgs, err := queue.List(ctxbg, queue.Filter{}, queue.Sort{})
	tcheck(t, err, "queue list")
	tcompare(t, len(msgs), 1)
	tcompare(t, msgs[0].Extra, map[string]string{
		"Test":          "testvalue",
		"A":             "123",
		"☺":             "☹",
		"X-Canonical-Z": "ok",
	})
	// note: these headers currently stay in the message.
}

// TestExtraDup checks for an error for duplicate x-mox-extra-* keys.
func TestExtraDup(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()

	ts.user = "mjl@mox.example"
	ts.pass = password0
	ts.submission = true

	extraMsg := strings.ReplaceAll(`From: <mjl@mox.example>
To: <remote@example.org>
Subject: test
X-Mox-Extra-Test: testvalue
X-Mox-Extra-Test: testvalue
Message-Id: <test@mox.example>

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@mox.example"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(extraMsg)), strings.NewReader(extraMsg), true, true, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C554TransactionFailed, Secode: smtp.SeMsg6Other0})
	})
}

// FromID can be specified during submission, but must be unique, with single recipient.
func TestUniqueFromID(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtpfromid/mox.conf"), dns.MockResolver{})
	defer ts.close()

	ts.user = "mjl+fromid@mox.example"
	ts.pass = password0
	ts.submission = true

	extraMsg := strings.ReplaceAll(`From: <mjl@mox.example>
To: <remote@example.org>
Subject: test

test email
`, "\n", "\r\n")

	// Specify our own unique id when queueing.
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl+unique@mox.example"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(extraMsg)), strings.NewReader(extraMsg), true, true, false)
		ts.smtpErr(err, nil)
	})

	// But we can only use it once.
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl+unique@mox.example"
		rcptTo := "mjl@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(extraMsg)), strings.NewReader(extraMsg), true, true, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C554TransactionFailed, Secode: smtp.SeAddr1SenderSyntax7})
	})

	// We cannot use our own fromid with multiple recipients.
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl+unique2@mox.example"
		rcptTo := []string{"mjl@mox.example", "mjl@mox.example"}
		_, err := client.DeliverMultiple(ctxbg, mailFrom, rcptTo, int64(len(extraMsg)), strings.NewReader(extraMsg), true, true, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C554TransactionFailed, Secode: smtp.SeProto5TooManyRcpts3})
	})
}

// TestDestinationSMTPError checks delivery to a destination with an SMTPError is rejected as configured.
func TestDestinationSMTPError(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
	}

	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@example.org"
		rcptTo := "blocked@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SeAddr1UnknownDestMailbox1})
	})
}

// TestDestinationMessageAuthRequiredSMTPError checks delivery to a destination
// with an MessageAuthRequiredSMTPError is accepted/rejected as configured.
func TestDestinationMessageAuthRequiredSMTPError(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."},
		},
		TXT: map[string][]string{},
	}

	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@example.org"
		rcptTo := "msgauthrequired@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7MultiAuthFails26})
	})

	// Ensure SPF pass, message should now be accepted.
	resolver.TXT["example.org."] = []string{"v=spf1 ip4:127.0.0.10 -all"}
	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@example.org"
		rcptTo := "msgauthrequired@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, nil)
	})
}
