package mtasts

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mjl-/adns"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

func TestLookup(t *testing.T) {
	mlog.SetConfig(map[string]mlog.Level{"": mlog.LevelDebug})

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_mta-sts.a.example.":         {"v=STSv1; id=1"},
			"_mta-sts.one.example.":       {"v=STSv1; id=1", "bogus"},
			"_mta-sts.bad.example.":       {"v=STSv1; bogus"},
			"_mta-sts.multiple.example.":  {"v=STSv1; id=1", "v=STSv1; id=2"},
			"_mta-sts.c.cnames.example.":  {"v=STSv1; id=1"},
			"_mta-sts.temperror.example.": {"v=STSv1; id=1"},
			"_mta-sts.other.example.":     {"bogus", "more"},
		},
		CNAME: map[string]string{
			"_mta-sts.a.cnames.example.":        "_mta-sts.b.cnames.example.",
			"_mta-sts.b.cnames.example.":        "_mta-sts.c.cnames.example.",
			"_mta-sts.followtemperror.example.": "_mta-sts.temperror.example.",
		},
		Fail: []string{
			"txt _mta-sts.temperror.example.",
		},
	}

	test := func(host string, expRecord *Record, expErr error) {
		t.Helper()

		record, _, err := LookupRecord(context.Background(), resolver, dns.Domain{ASCII: host})
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("lookup: got err %#v, expected %#v", err, expErr)
		}
		if err != nil {
			return
		}
		if !reflect.DeepEqual(record, expRecord) {
			t.Fatalf("lookup: got record %#v, expected %#v", record, expRecord)
		}
	}

	test("absent.example", nil, ErrNoRecord)
	test("other.example", nil, ErrNoRecord)
	test("a.example", &Record{Version: "STSv1", ID: "1"}, nil)
	test("one.example", &Record{Version: "STSv1", ID: "1"}, nil)
	test("bad.example", nil, ErrRecordSyntax)
	test("multiple.example", nil, ErrMultipleRecords)
	test("a.cnames.example", &Record{Version: "STSv1", ID: "1"}, nil)
	test("temperror.example", nil, ErrDNS)
	test("followtemperror.example", nil, ErrDNS)
}

func TestMatches(t *testing.T) {
	p, err := ParsePolicy("version: STSv1\nmode: enforce\nmax_age: 1\nmx: a.example\nmx: *.b.example\n")
	if err != nil {
		t.Fatalf("parsing policy: %s", err)
	}

	mustParseDomain := func(s string) dns.Domain {
		t.Helper()
		d, err := dns.ParseDomain(s)
		if err != nil {
			t.Fatalf("parsing domain %q: %s", s, err)
		}
		return d
	}

	match := func(s string) {
		t.Helper()
		if !p.Matches(mustParseDomain(s)) {
			t.Fatalf("unexpected mismatch for %q", s)
		}
	}

	not := func(s string) {
		t.Helper()
		if p.Matches(mustParseDomain(s)) {
			t.Fatalf("unexpected match for %q", s)
		}
	}

	match("a.example")
	match("sub.b.example")
	not("b.example")
	not("sub.sub.b.example")
	not("other")
}

type pipeListener struct {
	sync.Mutex
	closed bool
	C      chan net.Conn
}

var _ net.Listener = &pipeListener{}

func newPipeListener() *pipeListener { return &pipeListener{C: make(chan net.Conn)} }
func (l *pipeListener) Dial() (net.Conn, error) {
	l.Lock()
	defer l.Unlock()
	if l.closed {
		return nil, errors.New("closed")
	}
	c, s := net.Pipe()
	l.C <- s
	return c, nil
}
func (l *pipeListener) Accept() (net.Conn, error) {
	conn := <-l.C
	if conn == nil {
		return nil, io.EOF
	}
	return conn, nil
}
func (l *pipeListener) Close() error {
	l.Lock()
	defer l.Unlock()
	if !l.closed {
		l.closed = true
		close(l.C)
	}
	return nil
}
func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return "pipe" }

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
		DNSNames:     []string{"mta-sts.mox.example"},
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

func TestFetch(t *testing.T) {
	certok := fakeCert(t, false)
	certbad := fakeCert(t, true)

	defer func() {
		HTTPClient.Transport = nil
	}()

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_mta-sts.mox.example.":   {"v=STSv1; id=1"},
			"_mta-sts.other.example.": {"v=STSv1; id=1"},
		},
	}

	test := func(cert tls.Certificate, domain string, status int, policyText string, expPolicy *Policy, expErr error) {
		t.Helper()

		pool := x509.NewCertPool()
		pool.AddCert(cert.Leaf)

		l := newPipeListener()
		defer l.Close()
		go func() {
			mux := &http.ServeMux{}
			mux.HandleFunc("/.well-known/mta-sts.txt", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Location", "/other") // Ignored except for redirect.
				w.WriteHeader(status)
				w.Write([]byte(policyText))
			})
			s := &http.Server{
				Handler: mux,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
				},
				ErrorLog: log.New(io.Discard, "", 0),
			}
			s.ServeTLS(l, "", "")
		}()

		HTTPClient.Transport = &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				if strings.HasPrefix(addr, "mta-sts.doesnotexist.example") {
					return nil, &adns.DNSError{IsNotFound: true}
				}
				return l.Dial()
			},
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		}

		p, _, err := FetchPolicy(context.Background(), dns.Domain{ASCII: domain})
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("policy: got err %#v, expected %#v", err, expErr)
		}
		if err == nil && !reflect.DeepEqual(p, expPolicy) {
			t.Fatalf("policy: got %#v, expected %#v", p, expPolicy)
		}

		if domain == "doesnotexist.example" {
			expErr = ErrNoRecord
		}

		_, p, _, err = Get(context.Background(), resolver, dns.Domain{ASCII: domain})
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("get: got err %#v, expected %#v", err, expErr)
		}
		if err == nil && !reflect.DeepEqual(p, expPolicy) {
			t.Fatalf("get: got %#v, expected %#v", p, expPolicy)
		}
	}

	test(certok, "mox.example", 200, "bogus", nil, ErrPolicySyntax)
	test(certok, "other.example", 200, "bogus", nil, ErrPolicyFetch)
	test(certbad, "mox.example", 200, "bogus", nil, ErrPolicyFetch)
	test(certok, "mox.example", 404, "bogus", nil, ErrNoPolicy)
	test(certok, "doesnotexist.example", 200, "bogus", nil, ErrNoPolicy)
	test(certok, "mox.example", 301, "bogus", nil, ErrPolicyFetch)
	test(certok, "mox.example", 500, "bogus", nil, ErrPolicyFetch)
	large := make([]byte, 64*1024+2)
	test(certok, "mox.example", 200, string(large), nil, ErrPolicySyntax)
	validPolicy := "version:STSv1\nmode:none\nmax_age:1"
	test(certok, "mox.example", 200, validPolicy, &Policy{Version: "STSv1", Mode: "none", MaxAgeSeconds: 1}, nil)
}
