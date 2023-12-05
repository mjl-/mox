package mtastsdb

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtasts"
)

var ctxbg = context.Background()

func TestRefresh(t *testing.T) {
	mox.Shutdown = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/mtasts/fake.conf")
	mox.Conf.Static.DataDir = "."

	dbpath := mox.DataDirPath("mtasts.db")
	os.MkdirAll(filepath.Dir(dbpath), 0770)
	os.Remove(dbpath)
	defer os.Remove(dbpath)

	if err := Init(false); err != nil {
		t.Fatalf("init database: %s", err)
	}
	defer Close()

	db, err := database(ctxbg)
	if err != nil {
		t.Fatalf("database: %s", err)
	}

	cert := fakeCert(t, false)
	defer func() {
		mtasts.HTTPClient.Transport = nil
	}()

	insert := func(domain string, validEnd, lastUpdate, lastUse time.Time, backoff bool, recordID string, mode mtasts.Mode, maxAge int, mx string) {
		t.Helper()

		mxd, err := dns.ParseDomain(mx)
		if err != nil {
			t.Fatalf("parsing mx domain %q: %s", mx, err)
		}
		policy := mtasts.Policy{
			Version:       "STSv1",
			Mode:          mode,
			MX:            []mtasts.STSMX{{Wildcard: false, Domain: mxd}},
			MaxAgeSeconds: maxAge,
			Extensions:    nil,
		}

		pr := PolicyRecord{domain, time.Time{}, validEnd, lastUpdate, lastUse, backoff, recordID, policy, policy.String()}
		if err := db.Insert(ctxbg, &pr); err != nil {
			t.Fatalf("insert policy: %s", err)
		}
	}

	now := time.Now()
	// Updated just now.
	insert("mox.example", now.Add(24*time.Hour), now, now, false, "1", mtasts.ModeEnforce, 3600, "mx.mox.example.com")
	// To be removed.
	insert("stale.mox.example", now.Add(-time.Hour), now, now.Add(-181*24*time.Hour), false, "1", mtasts.ModeEnforce, 3600, "mx.mox.example.com")
	// To be refreshed, same id.
	insert("refresh.mox.example", now.Add(7*24*time.Hour), now.Add(-24*time.Hour), now.Add(-179*24*time.Hour), false, "1", mtasts.ModeEnforce, 3600, "mx.mox.example.com")
	// To be refreshed and succeed.
	insert("policyok.mox.example", now.Add(7*24*time.Hour), now.Add(-24*time.Hour), now.Add(-179*24*time.Hour), false, "1", mtasts.ModeEnforce, 3600, "mx.mox.example.com")
	// To be refreshed and fail to fetch.
	insert("policybad.mox.example", now.Add(7*24*time.Hour), now.Add(-24*time.Hour), now.Add(-179*24*time.Hour), false, "1", mtasts.ModeEnforce, 3600, "mx.mox.example.com")

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_mta-sts.refresh.mox.example.":   {"v=STSv1; id=1"},
			"_mta-sts.policyok.mox.example.":  {"v=STSv1; id=2"},
			"_mta-sts.policybad.mox.example.": {"v=STSv1; id=2"},
		},
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)

	l := newPipeListener()
	defer l.Close()
	go func() {
		mux := &http.ServeMux{}
		mux.HandleFunc("/.well-known/mta-sts.txt", func(w http.ResponseWriter, r *http.Request) {
			if r.Host == "mta-sts.policybad.mox.example" {
				w.WriteHeader(500)
				return
			}
			fmt.Fprintf(w, "version: STSv1\nmode: enforce\nmx: mx.mox.example.com\nmax_age: 3600\n")
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

	mtasts.HTTPClient.Transport = &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return l.Dial()
		},
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}

	slept := 0
	sleep := func(d time.Duration) {
		slept++
		interval := 3 * time.Hour / 2
		if d < time.Duration(slept)*interval-interval/2 || d > time.Duration(slept)*interval+interval/2 {
			t.Fatalf("bad sleep duration %v", d)
		}
	}
	log := mlog.New("mtastsdb", nil)
	if n, err := refresh1(ctxbg, log, resolver, sleep); err != nil || n != 3 {
		t.Fatalf("refresh1: err %s, n %d, expected no error, 3", err, n)
	}
	if slept != 2 {
		t.Fatalf("bad sleeps, %d instead of 2", slept)
	}
	time.Sleep(time.Second / 10) // Give goroutine time to write result, before we cleanup the database.

	// Should not do any more refreshes and return immediately.
	q := bstore.QueryDB[PolicyRecord](ctxbg, db)
	q.FilterNonzero(PolicyRecord{Domain: "policybad.mox.example"})
	if _, err := q.Delete(); err != nil {
		t.Fatalf("delete record that would be refreshed: %v", err)
	}
	mox.Context = ctxbg
	mox.Shutdown, mox.ShutdownCancel = context.WithCancel(ctxbg)
	mox.ShutdownCancel()
	n := refresh()
	if n != 0 {
		t.Fatalf("refresh found unexpected work, n %d", n)
	}
	mox.Shutdown, mox.ShutdownCancel = context.WithCancel(ctxbg)
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
		DNSNames:     []string{"mta-sts.policybad.mox.example", "mta-sts.policyok.mox.example"},
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
