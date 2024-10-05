package queue

import (
	"bufio"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mjl-/adns"
	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrpt"
	"github.com/mjl-/mox/tlsrptdb"
	"github.com/mjl-/mox/webhook"
)

var ctxbg = context.Background()
var pkglog = mlog.New("queue", nil)

func tcheck(t *testing.T, err error, msg string) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %s", msg, err)
	}
}

func tcompare(t *testing.T, got, exp any) {
	t.Helper()
	if !reflect.DeepEqual(got, exp) {
		t.Fatalf("got:\n%#v\nexpected:\n%#v", got, exp)
	}
}

func setup(t *testing.T) (*store.Account, func()) {
	// Prepare config so email can be delivered to mjl@mox.example.
	os.RemoveAll("../testdata/queue/data")
	log := mlog.New("queue", nil)
	mox.Context = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/queue/mox.conf")
	mox.MustLoadConfig(true, false)
	err := Init()
	tcheck(t, err, "queue init")
	err = mtastsdb.Init(false)
	tcheck(t, err, "mtastsdb init")
	err = tlsrptdb.Init()
	tcheck(t, err, "tlsrptdb init")
	acc, err := store.OpenAccount(log, "mjl")
	tcheck(t, err, "open account")
	err = acc.SetPassword(log, "testtest")
	tcheck(t, err, "set password")
	switchStop := store.Switchboard()
	mox.Shutdown, mox.ShutdownCancel = context.WithCancel(ctxbg)
	return acc, func() {
		acc.Close()
		acc.CheckClosed()
		mox.ShutdownCancel()
		mox.Shutdown, mox.ShutdownCancel = context.WithCancel(ctxbg)
		Shutdown()
		err := mtastsdb.Close()
		tcheck(t, err, "mtastsdb close")
		err = tlsrptdb.Close()
		tcheck(t, err, "tlsrptdb close")
		switchStop()
	}
}

var testmsg = strings.ReplaceAll(`From: <mjl@mox.example>
To: <mjl@mox.example>
Subject: test

test email
`, "\n", "\r\n")

func prepareFile(t *testing.T) *os.File {
	t.Helper()
	msgFile, err := store.CreateMessageTemp(pkglog, "queue")
	tcheck(t, err, "create temp message for delivery to queue")
	_, err = msgFile.Write([]byte(testmsg))
	tcheck(t, err, "write message file")
	return msgFile
}

func TestQueue(t *testing.T) {
	acc, cleanup := setup(t)
	defer cleanup()

	idfilter := func(msgID int64) Filter {
		return Filter{IDs: []int64{msgID}}
	}

	kick := func(expn int, id int64) {
		t.Helper()
		n, err := NextAttemptSet(ctxbg, idfilter(id), time.Now())
		tcheck(t, err, "kick queue")
		if n != expn {
			t.Fatalf("kick changed %d messages, expected %d", n, expn)
		}
	}

	msgs, err := List(ctxbg, Filter{}, Sort{})
	tcheck(t, err, "listing messages in queue")
	if len(msgs) != 0 {
		t.Fatalf("got %d messages in queue, expected 0", len(msgs))
	}

	path := smtp.Path{Localpart: "mjl", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mox.example"}}}
	mf := prepareFile(t)
	defer os.Remove(mf.Name())
	defer mf.Close()

	var qm Msg

	qm = MakeMsg(path, path, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, time.Now(), "test")
	err = Add(ctxbg, pkglog, "mjl", mf, qm)
	tcheck(t, err, "add message to queue for delivery")

	qm = MakeMsg(path, path, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, time.Now(), "test")
	err = Add(ctxbg, pkglog, "mjl", mf, qm)
	tcheck(t, err, "add message to queue for delivery")

	qm = MakeMsg(path, path, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, time.Now(), "test")
	err = Add(ctxbg, pkglog, "mjl", mf, qm)
	tcheck(t, err, "add message to queue for delivery")

	msgs, err = List(ctxbg, Filter{}, Sort{})
	tcheck(t, err, "listing queue")
	if len(msgs) != 3 {
		t.Fatalf("got msgs %v, expected 1", msgs)
	}

	yes := true
	n, err := RequireTLSSet(ctxbg, Filter{IDs: []int64{msgs[2].ID}}, &yes)
	tcheck(t, err, "requiretlsset")
	tcompare(t, n, 1)

	msg := msgs[0]
	if msg.Attempts != 0 {
		t.Fatalf("msg attempts %d, expected 0", msg.Attempts)
	}
	n, err = Drop(ctxbg, pkglog, Filter{IDs: []int64{msgs[1].ID}})
	tcheck(t, err, "drop")
	if n != 1 {
		t.Fatalf("dropped %d, expected 1", n)
	}
	if _, err := os.Stat(msgs[1].MessagePath()); err == nil || !os.IsNotExist(err) {
		t.Fatalf("dropped message not removed from file system")
	}

	// Fail a message, check the account has a message afterwards, the DSN.
	n, err = bstore.QueryDB[store.Message](ctxbg, acc.DB).Count()
	tcheck(t, err, "count messages in account")
	tcompare(t, n, 0)
	n, err = Fail(ctxbg, pkglog, Filter{IDs: []int64{msgs[2].ID}})
	tcheck(t, err, "fail")
	if n != 1 {
		t.Fatalf("failed %d, expected 1", n)
	}
	n, err = bstore.QueryDB[store.Message](ctxbg, acc.DB).Count()
	tcheck(t, err, "count messages in account")
	tcompare(t, n, 1)

	// Check filter through various List calls. Other code uses the same filtering function.
	filter := func(f Filter, expn int) {
		t.Helper()
		l, err := List(ctxbg, f, Sort{})
		tcheck(t, err, "list messages")
		tcompare(t, len(l), expn)
	}
	filter(Filter{}, 1)
	filter(Filter{Account: "mjl"}, 1)
	filter(Filter{Account: "bogus"}, 0)
	filter(Filter{IDs: []int64{msgs[0].ID}}, 1)
	filter(Filter{IDs: []int64{msgs[2].ID}}, 0)     // Removed.
	filter(Filter{IDs: []int64{msgs[2].ID + 1}}, 0) // Never existed.
	filter(Filter{From: "mjl@"}, 1)
	filter(Filter{From: "bogus@"}, 0)
	filter(Filter{To: "mjl@"}, 1)
	filter(Filter{To: "bogus@"}, 0)
	filter(Filter{Hold: &yes}, 0)
	no := false
	filter(Filter{Hold: &no}, 1)
	filter(Filter{Submitted: "<now"}, 1)
	filter(Filter{Submitted: ">now"}, 0)
	filter(Filter{NextAttempt: "<1m"}, 1)
	filter(Filter{NextAttempt: ">1m"}, 0)
	var empty string
	bogus := "bogus"
	filter(Filter{Transport: &empty}, 1)
	filter(Filter{Transport: &bogus}, 0)

	next := nextWork(ctxbg, pkglog, nil)
	if next > 0 {
		t.Fatalf("nextWork in %s, should be now", next)
	}
	busy := map[string]struct{}{"mox.example": {}}
	if x := nextWork(ctxbg, pkglog, busy); x != 24*time.Hour {
		t.Fatalf("nextWork in %s for busy domain, should be in 24 hours", x)
	}
	if nn := launchWork(pkglog, nil, busy); nn != 0 {
		t.Fatalf("launchWork launched %d deliveries, expected 0", nn)
	}

	mailDomain := dns.Domain{ASCII: "mox.example"}
	mailHost := dns.Domain{ASCII: "mail.mox.example"}
	resolver := dns.MockResolver{
		A: map[string][]string{
			"mail.mox.example.":   {"127.0.0.1"},
			"submission.example.": {"127.0.0.1"},
		},
		MX: map[string][]*net.MX{
			"mox.example.":   {{Host: "mail.mox.example", Pref: 10}},
			"other.example.": {{Host: "mail.mox.example", Pref: 10}},
		},
	}

	// Try a failing delivery attempt.
	var ndial int
	smtpclient.DialHook = func(ctx context.Context, dialer smtpclient.Dialer, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
		ndial++
		return nil, fmt.Errorf("failure from test")
	}
	defer func() {
		smtpclient.DialHook = nil
	}()

	n = launchWork(pkglog, resolver, map[string]struct{}{})
	tcompare(t, n, 1)

	// Wait until we see the dial and the failed attempt.
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-deliveryResults:
		tcompare(t, ndial, 1)
		m, err := bstore.QueryDB[Msg](ctxbg, DB).Get()
		tcheck(t, err, "get")
		tcompare(t, m.Attempts, 1)
	case <-timer.C:
		t.Fatalf("no delivery within 1s")
	}

	// OpenMessage.
	_, err = OpenMessage(ctxbg, msg.ID+1)
	if err != bstore.ErrAbsent {
		t.Fatalf("OpenMessage, got %v, expected ErrAbsent", err)
	}
	reader, err := OpenMessage(ctxbg, msg.ID)
	tcheck(t, err, "open message")
	defer reader.Close()
	msgbuf, err := io.ReadAll(reader)
	tcheck(t, err, "read message")
	if string(msgbuf) != testmsg {
		t.Fatalf("message mismatch, got %q, expected %q", string(msgbuf), testmsg)
	}

	// Reduce by more than first attempt interval of 7.5 minutes.
	n, err = NextAttemptAdd(ctxbg, idfilter(msg.ID+1), -10*time.Minute)
	tcheck(t, err, "kick")
	if n != 0 {
		t.Fatalf("kick %d, expected 0", n)
	}
	n, err = NextAttemptAdd(ctxbg, idfilter(msg.ID), -10*time.Minute)
	tcheck(t, err, "kick")
	if n != 1 {
		t.Fatalf("kicked %d, expected 1", n)
	}

	nfakeSMTPServer := func(server net.Conn, rcpts, ntx int, onercpt bool, extensions []string) {
		// We do a minimal fake smtp server. We cannot import smtpserver.Serve due to
		// cyclic dependencies.
		fmt.Fprintf(server, "220 mail.mox.example\r\n")
		br := bufio.NewReader(server)

		readline := func(cmd string) {
			line, err := br.ReadString('\n')
			if err == nil && !strings.HasPrefix(strings.ToLower(line), cmd) {
				panic(fmt.Sprintf("unexpected line %q, expected %q", line, cmd))
			}
		}
		writeline := func(s string) {
			fmt.Fprintf(server, "%s\r\n", s)
		}

		readline("ehlo")
		writeline("250-mail.mox.example")
		for _, ext := range extensions {
			writeline("250-" + ext)
		}
		writeline("250 pipelining")
		for tx := 0; tx < ntx; tx++ {
			readline("mail")
			writeline("250 ok")
			for i := 0; i < rcpts; i++ {
				readline("rcpt")
				if onercpt && i > 0 {
					writeline("552 ok")
				} else {
					writeline("250 ok")
				}
			}
			readline("data")
			writeline("354 continue")
			reader := smtp.NewDataReader(br)
			io.Copy(io.Discard, reader)
			writeline("250 ok")
		}
		readline("quit")
		writeline("221 ok")
	}
	fakeSMTPServer := func(server net.Conn) {
		nfakeSMTPServer(server, 1, 1, false, nil)
	}
	fakeSMTPServer2Rcpts := func(server net.Conn) {
		nfakeSMTPServer(server, 2, 1, false, nil)
	}
	fakeSMTPServerLimitRcpt1 := func(server net.Conn) {
		nfakeSMTPServer(server, 1, 2, false, []string{"LIMITS RCPTMAX=1"})
	}
	// Server that returns an error after first recipient. We expect another
	// transaction to deliver the second message.
	fakeSMTPServerRcpt1 := func(server net.Conn) {
		// We do a minimal fake smtp server. We cannot import smtpserver.Serve due to
		// cyclic dependencies.
		fmt.Fprintf(server, "220 mail.mox.example\r\n")
		br := bufio.NewReader(server)

		readline := func(cmd string) {
			line, err := br.ReadString('\n')
			if err == nil && !strings.HasPrefix(strings.ToLower(line), cmd) {
				panic(fmt.Sprintf("unexpected line %q, expected %q", line, cmd))
			}
		}
		writeline := func(s string) {
			fmt.Fprintf(server, "%s\r\n", s)
		}

		readline("ehlo")
		writeline("250-mail.mox.example")
		writeline("250 pipelining")

		readline("mail")
		writeline("250 ok")
		readline("rcpt")
		writeline("250 ok")
		readline("rcpt")
		writeline("552 ok")
		readline("data")
		writeline("354 continue")
		reader := smtp.NewDataReader(br)
		io.Copy(io.Discard, reader)
		writeline("250 ok")

		readline("mail")
		writeline("250 ok")
		readline("rcpt")
		writeline("250 ok")
		readline("data")
		writeline("354 continue")
		reader = smtp.NewDataReader(br)
		io.Copy(io.Discard, reader)
		writeline("250 ok")

		readline("quit")
		writeline("221 ok")
	}

	moxCert := fakeCert(t, "mail.mox.example", false)
	goodTLSConfig := tls.Config{Certificates: []tls.Certificate{moxCert}}
	makeFakeSMTPSTARTTLSServer := func(tlsConfig *tls.Config, nstarttls int, requiretls bool) func(server net.Conn) {
		attempt := 0
		return func(server net.Conn) {
			attempt++

			// We do a minimal fake smtp server. We cannot import smtpserver.Serve due to
			// cyclic dependencies.
			fmt.Fprintf(server, "220 mail.mox.example\r\n")
			br := bufio.NewReader(server)

			readline := func(cmd string) {
				line, err := br.ReadString('\n')
				if err == nil && !strings.HasPrefix(strings.ToLower(line), cmd) {
					panic(fmt.Sprintf("unexpected line %q, expected %q", line, cmd))
				}
			}
			writeline := func(s string) {
				fmt.Fprintf(server, "%s\r\n", s)
			}

			readline("ehlo")
			writeline("250-mail.mox.example")
			writeline("250 starttls")
			if nstarttls == 0 || attempt <= nstarttls {
				readline("starttls")
				writeline("220 ok")
				tlsConn := tls.Server(server, tlsConfig)
				err := tlsConn.Handshake()
				if err != nil {
					return
				}
				server = tlsConn
				br = bufio.NewReader(server)

				readline("ehlo")
				if requiretls {
					writeline("250-mail.mox.example")
					writeline("250 requiretls")
				} else {
					writeline("250 mail.mox.example")
				}
			}
			readline("mail")
			writeline("250 ok")
			readline("rcpt")
			writeline("250 ok")
			readline("data")
			writeline("354 continue")
			reader := smtp.NewDataReader(br)
			io.Copy(io.Discard, reader)
			writeline("250 ok")
			readline("quit")
			writeline("221 ok")
		}
	}

	fakeSMTPSTARTTLSServer := makeFakeSMTPSTARTTLSServer(&goodTLSConfig, 0, true)
	makeBadFakeSMTPSTARTTLSServer := func(requiretls bool) func(server net.Conn) {
		return makeFakeSMTPSTARTTLSServer(&tls.Config{MaxVersion: tls.VersionTLS10, Certificates: []tls.Certificate{moxCert}}, 1, requiretls)
	}

	nfakeSubmitServer := func(server net.Conn, nrcpt int) {
		// We do a minimal fake smtp server. We cannot import smtpserver.Serve due to
		// cyclic dependencies.
		fmt.Fprintf(server, "220 mail.mox.example\r\n")
		br := bufio.NewReader(server)
		br.ReadString('\n') // Should be EHLO.
		fmt.Fprintf(server, "250-localhost\r\n")
		fmt.Fprintf(server, "250 AUTH PLAIN\r\n")
		br.ReadString('\n') // Should be AUTH PLAIN
		fmt.Fprintf(server, "235 2.7.0 auth ok\r\n")
		br.ReadString('\n') // Should be MAIL FROM.
		fmt.Fprintf(server, "250 ok\r\n")
		for i := 0; i < nrcpt; i++ {
			br.ReadString('\n') // Should be RCPT TO.
			fmt.Fprintf(server, "250 ok\r\n")
		}
		br.ReadString('\n') // Should be DATA.
		fmt.Fprintf(server, "354 continue\r\n")
		reader := smtp.NewDataReader(br)
		io.Copy(io.Discard, reader)
		fmt.Fprintf(server, "250 ok\r\n")
		br.ReadString('\n') // Should be QUIT.
		fmt.Fprintf(server, "221 ok\r\n")
	}
	fakeSubmitServer := func(server net.Conn) {
		nfakeSubmitServer(server, 1)
	}
	fakeSubmitServer2Rcpts := func(server net.Conn) {
		nfakeSubmitServer(server, 2)
	}

	testQueue := func(expectDSN bool, fakeServer func(conn net.Conn), nresults int) (wasNetDialer bool) {
		t.Helper()

		var pipes []net.Conn
		defer func() {
			for _, conn := range pipes {
				conn.Close()
			}
		}()

		var connMu sync.Mutex
		smtpclient.DialHook = func(ctx context.Context, dialer smtpclient.Dialer, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
			connMu.Lock()
			defer connMu.Unlock()

			// Setting up a pipe. We'll start a fake smtp server on the server-side. And return the
			// client-side to the invocation dial, for the attempted delivery from the queue.
			server, client := net.Pipe()
			pipes = append(pipes, server, client)
			go fakeServer(server)

			_, wasNetDialer = dialer.(*net.Dialer)

			return client, nil
		}
		defer func() {
			smtpclient.DialHook = nil
		}()

		inbox, err := bstore.QueryDB[store.Mailbox](ctxbg, acc.DB).FilterNonzero(store.Mailbox{Name: "Inbox"}).Get()
		tcheck(t, err, "get inbox")

		inboxCount, err := bstore.QueryDB[store.Message](ctxbg, acc.DB).FilterNonzero(store.Message{MailboxID: inbox.ID}).Count()
		tcheck(t, err, "querying messages in inbox")

		launchWork(pkglog, resolver, map[string]struct{}{})

		// Wait for all results.
		timer.Reset(time.Second)
		for i := 0; i < nresults; i++ {
			select {
			case <-deliveryResults:
			case <-timer.C:
				t.Fatalf("no dial within 1s")
			}
		}

		// Check that queue is now empty.
		xmsgs, err := List(ctxbg, Filter{}, Sort{})
		tcheck(t, err, "list queue")
		tcompare(t, len(xmsgs), 0)

		// And that we possibly got a DSN delivered.
		ninbox, err := bstore.QueryDB[store.Message](ctxbg, acc.DB).FilterNonzero(store.Message{MailboxID: inbox.ID}).Count()
		tcheck(t, err, "querying messages in inbox")
		if expectDSN && ninbox != inboxCount+1 {
			t.Fatalf("got %d messages in inbox, previously %d, expected 1 additional for dsn", ninbox, inboxCount)
		} else if !expectDSN && ninbox != inboxCount {
			t.Fatalf("got %d messages in inbox, previously %d, expected no additional messages", ninbox, inboxCount)
		}

		return wasNetDialer
	}
	testDeliver := func(fakeServer func(conn net.Conn)) bool {
		t.Helper()
		return testQueue(false, fakeServer, 1)
	}
	testDeliverN := func(fakeServer func(conn net.Conn), nresults int) bool {
		t.Helper()
		return testQueue(false, fakeServer, nresults)
	}
	testDSN := func(fakeServer func(conn net.Conn)) bool {
		t.Helper()
		return testQueue(true, fakeServer, 1)
	}

	// Test direct delivery.
	wasNetDialer := testDeliver(fakeSMTPServer)
	if !wasNetDialer {
		t.Fatalf("expected net.Dialer as dialer")
	}

	// Single delivery to two recipients at same domain, expecting single connection
	// and single transaction.
	qm0 := MakeMsg(path, path, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, time.Now(), "test")
	qml := []Msg{qm0, qm0} // Same NextAttempt.
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add messages to queue for delivery")
	testDeliver(fakeSMTPServer2Rcpts)

	// Single enqueue to two recipients at different domain, expecting two connections.
	otheraddr, _ := smtp.ParseAddress("mjl@other.example")
	otherpath := otheraddr.Path()
	t0 := time.Now()
	qml = []Msg{
		MakeMsg(path, path, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, t0, "test"),
		MakeMsg(path, otherpath, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, t0, "test"),
	}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add messages to queue for delivery")
	conns := ConnectionCounter()
	testDeliverN(fakeSMTPServer, 2)
	nconns := ConnectionCounter()
	if nconns != conns+2 {
		t.Errorf("saw %d connections, expected 2", nconns-conns)
	}

	// Single enqueue with two recipients at same domain, but with smtp server that has
	// LIMITS RCPTMAX=1, so we expect a single connection with two transactions.
	qml = []Msg{qm0, qm0}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add messages to queue for delivery")
	testDeliver(fakeSMTPServerLimitRcpt1)

	// Single enqueue with two recipients at same domain, but smtp server sends 552 for
	// 2nd recipient, so we expect a single connection with two transactions.
	qml = []Msg{qm0, qm0}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add messages to queue for delivery")
	testDeliver(fakeSMTPServerRcpt1)

	// Add a message to be delivered with submit because of its route.
	topath := smtp.Path{Localpart: "mjl", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "submit.example"}}}
	qm = MakeMsg(path, topath, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, time.Now(), "test")
	err = Add(ctxbg, pkglog, "mjl", mf, qm)
	tcheck(t, err, "add message to queue for delivery")
	wasNetDialer = testDeliver(fakeSubmitServer)
	if !wasNetDialer {
		t.Fatalf("expected net.Dialer as dialer")
	}

	// Two messages for submission.
	qml = []Msg{qm, qm}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add messages to queue for delivery")
	wasNetDialer = testDeliver(fakeSubmitServer2Rcpts)
	if !wasNetDialer {
		t.Fatalf("expected net.Dialer as dialer")
	}

	// Add a message to be delivered with submit because of explicitly configured transport, that uses TLS.
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	transportSubmitTLS := "submittls"
	n, err = TransportSet(ctxbg, Filter{IDs: []int64{qml[0].ID}}, transportSubmitTLS)
	tcheck(t, err, "set transport")
	if n != 1 {
		t.Fatalf("TransportSet changed %d messages, expected 1", n)
	}
	// Make fake cert, and make it trusted.
	cert := fakeCert(t, "submission.example", false)
	mox.Conf.Static.TLS.CertPool = x509.NewCertPool()
	mox.Conf.Static.TLS.CertPool.AddCert(cert.Leaf)
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	wasNetDialer = testDeliver(func(conn net.Conn) {
		conn = tls.Server(conn, &tlsConfig)
		fakeSubmitServer(conn)
	})
	if !wasNetDialer {
		t.Fatalf("expected net.Dialer as dialer")
	}

	// Various failure reasons.
	fdNotTrusted := tlsrpt.FailureDetails{
		ResultType:          tlsrpt.ResultCertificateNotTrusted,
		SendingMTAIP:        "", // Missing due to pipe.
		ReceivingMXHostname: "mail.mox.example",
		ReceivingMXHelo:     "mail.mox.example",
		ReceivingIP:         "", // Missing due to pipe.
		FailedSessionCount:  1,
		FailureReasonCode:   "",
	}
	fdTLSAUnusable := tlsrpt.FailureDetails{
		ResultType:          tlsrpt.ResultTLSAInvalid,
		ReceivingMXHostname: "mail.mox.example",
		FailedSessionCount:  0,
		FailureReasonCode:   "all-unusable-records+ignored",
	}
	fdBadProtocol := tlsrpt.FailureDetails{
		ResultType:          tlsrpt.ResultValidationFailure,
		ReceivingMXHostname: "mail.mox.example",
		ReceivingMXHelo:     "mail.mox.example",
		FailedSessionCount:  1,
		FailureReasonCode:   "tls-remote-alert-70-protocol-version-not-supported",
	}

	// Add a message to be delivered with socks.
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<socks@localhost>", nil, nil, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	n, err = TransportSet(ctxbg, idfilter(qml[0].ID), "socks")
	tcheck(t, err, "TransportSet")
	if n != 1 {
		t.Fatalf("TransportSet changed %d messages, expected 1", n)
	}
	kick(1, qml[0].ID)
	wasNetDialer = testDeliver(fakeSMTPServer)
	if wasNetDialer {
		t.Fatalf("expected non-net.Dialer as dialer") // SOCKS5 dialer is a private type, we cannot check for it.
	}

	// Add message to be delivered with opportunistic TLS verification.
	clearTLSResults(t)
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<opportunistictls@localhost>", nil, nil, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	kick(1, qml[0].ID)
	testDeliver(fakeSMTPSTARTTLSServer)
	checkTLSResults(t, "mox.example", "mox.example", false, addCounts(1, 0, tlsrpt.MakeResult(tlsrpt.NoPolicyFound, mailDomain, fdNotTrusted)))
	checkTLSResults(t, "mail.mox.example", "mox.example", true, addCounts(1, 0, tlsrpt.MakeResult(tlsrpt.NoPolicyFound, mailHost)))

	// Test fallback to plain text with TLS handshake fails.
	clearTLSResults(t)
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<badtls@localhost>", nil, nil, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	kick(1, qml[0].ID)
	testDeliver(makeBadFakeSMTPSTARTTLSServer(true))
	checkTLSResults(t, "mox.example", "mox.example", false, addCounts(0, 1, tlsrpt.MakeResult(tlsrpt.NoPolicyFound, mailDomain, fdBadProtocol)))
	checkTLSResults(t, "mail.mox.example", "mox.example", true, addCounts(0, 1, tlsrpt.MakeResult(tlsrpt.NoPolicyFound, mailHost, fdBadProtocol)))

	// Add message to be delivered with DANE verification.
	clearTLSResults(t)
	resolver.AllAuthentic = true
	resolver.TLSA = map[string][]adns.TLSA{
		"_25._tcp.mail.mox.example.": {
			{Usage: adns.TLSAUsageDANEEE, Selector: adns.TLSASelectorSPKI, MatchType: adns.TLSAMatchTypeFull, CertAssoc: moxCert.Leaf.RawSubjectPublicKeyInfo},
		},
	}
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<dane@localhost>", nil, nil, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	kick(1, qml[0].ID)
	testDeliver(fakeSMTPSTARTTLSServer)
	checkTLSResults(t, "mox.example", "mox.example", false, addCounts(1, 0, tlsrpt.MakeResult(tlsrpt.NoPolicyFound, mailDomain, fdNotTrusted)))
	checkTLSResults(t, "mail.mox.example", "mox.example", true, addCounts(1, 0, tlsrpt.Result{Policy: tlsrpt.TLSAPolicy(resolver.TLSA["_25._tcp.mail.mox.example."], mailHost), FailureDetails: []tlsrpt.FailureDetails{}}))

	// We should know starttls/requiretls by now.
	rdt := store.RecipientDomainTLS{Domain: "mox.example"}
	err = acc.DB.Get(ctxbg, &rdt)
	tcheck(t, err, "get recipientdomaintls")
	tcompare(t, rdt.STARTTLS, true)
	tcompare(t, rdt.RequireTLS, true)

	// Add message to be delivered with verified TLS and REQUIRETLS.
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<opportunistictls@localhost>", nil, &yes, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	kick(1, qml[0].ID)
	testDeliver(fakeSMTPSTARTTLSServer)

	// Check that message is delivered with all unusable DANE records.
	clearTLSResults(t)
	resolver.TLSA = map[string][]adns.TLSA{
		"_25._tcp.mail.mox.example.": {
			{},
		},
	}
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<daneunusable@localhost>", nil, nil, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	kick(1, qml[0].ID)
	testDeliver(fakeSMTPSTARTTLSServer)
	checkTLSResults(t, "mox.example", "mox.example", false, addCounts(1, 0, tlsrpt.MakeResult(tlsrpt.NoPolicyFound, mailDomain, fdNotTrusted)))
	checkTLSResults(t, "mail.mox.example", "mox.example", true, addCounts(1, 0, tlsrpt.Result{Policy: tlsrpt.TLSAPolicy([]adns.TLSA{}, mailHost), FailureDetails: []tlsrpt.FailureDetails{fdTLSAUnusable}}))

	// Check that message is delivered with insecure TLSA records. They should be
	// ignored and regular STARTTLS tried.
	clearTLSResults(t)
	resolver.Inauthentic = []string{"tlsa _25._tcp.mail.mox.example."}
	resolver.TLSA = map[string][]adns.TLSA{
		"_25._tcp.mail.mox.example.": {
			{Usage: adns.TLSAUsageDANEEE, Selector: adns.TLSASelectorSPKI, MatchType: adns.TLSAMatchTypeFull, CertAssoc: make([]byte, sha256.Size)},
		},
	}
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<daneinsecure@localhost>", nil, nil, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	kick(1, qml[0].ID)
	testDeliver(makeBadFakeSMTPSTARTTLSServer(true))
	resolver.Inauthentic = nil
	checkTLSResults(t, "mox.example", "mox.example", false, addCounts(0, 1, tlsrpt.MakeResult(tlsrpt.NoPolicyFound, mailDomain, fdBadProtocol)))
	checkTLSResults(t, "mail.mox.example", "mox.example", true, addCounts(0, 1, tlsrpt.MakeResult(tlsrpt.NoPolicyFound, mailHost, fdBadProtocol)))

	// STARTTLS failed, so not known supported.
	rdt = store.RecipientDomainTLS{Domain: "mox.example"}
	err = acc.DB.Get(ctxbg, &rdt)
	tcheck(t, err, "get recipientdomaintls")
	tcompare(t, rdt.STARTTLS, false)
	tcompare(t, rdt.RequireTLS, false)

	// Check that message is delivered with TLS-Required: No and non-matching DANE record.
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<tlsrequirednostarttls@localhost>", nil, &no, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	kick(1, qml[0].ID)
	testDeliver(fakeSMTPSTARTTLSServer)

	// Check that message is delivered with TLS-Required: No and bad TLS, falling back to plain text.
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<tlsrequirednoplaintext@localhost>", nil, &no, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	kick(1, qml[0].ID)
	testDeliver(makeBadFakeSMTPSTARTTLSServer(true))

	// Add message with requiretls that fails immediately due to no REQUIRETLS support in all servers.
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<tlsrequiredunsupported@localhost>", nil, &yes, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	kick(1, qml[0].ID)
	testDSN(makeBadFakeSMTPSTARTTLSServer(false))

	// Restore pre-DANE behaviour.
	resolver.AllAuthentic = false
	resolver.TLSA = nil

	// Add message with requiretls that fails immediately due to no verification policy for recipient domain.
	qml = []Msg{MakeMsg(path, path, false, false, int64(len(testmsg)), "<tlsrequirednopolicy@localhost>", nil, &yes, time.Now(), "test")}
	err = Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add message to queue for delivery")
	kick(1, qml[0].ID)
	// Based on DNS lookups, there won't be any dialing or SMTP connection.
	testDSN(func(conn net.Conn) {})

	// Add another message that we'll fail to deliver entirely.
	qm = MakeMsg(path, path, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, time.Now(), "test")
	err = Add(ctxbg, pkglog, "mjl", mf, qm)
	tcheck(t, err, "add message to queue for delivery")

	msgs, err = List(ctxbg, Filter{}, Sort{})
	tcheck(t, err, "list queue")
	if len(msgs) != 1 {
		t.Fatalf("queue has %d messages, expected 1", len(msgs))
	}
	msg = msgs[0]

	prepServer := func(fn func(c net.Conn)) (net.Conn, func()) {
		server, client := net.Pipe()
		go func() {
			fn(server)
			server.Close()
		}()
		return client, func() {
			server.Close()
			client.Close()
		}
	}

	conn2, cleanup2 := prepServer(func(conn net.Conn) { fmt.Fprintf(conn, "220 mail.mox.example\r\n") })
	conn3, cleanup3 := prepServer(func(conn net.Conn) { fmt.Fprintf(conn, "451 mail.mox.example\r\n") })
	conn4, cleanup4 := prepServer(fakeSMTPSTARTTLSServer)
	defer func() {
		cleanup2()
		cleanup3()
		cleanup4()
	}()

	seq := 0
	smtpclient.DialHook = func(ctx context.Context, dialer smtpclient.Dialer, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
		seq++
		switch seq {
		default:
			return nil, fmt.Errorf("connect error from test")
		case 2:
			return conn2, nil
		case 3:
			return conn3, nil
		case 4:
			return conn4, nil
		}
	}
	defer func() {
		smtpclient.DialHook = nil
	}()

	comm := store.RegisterComm(acc)
	defer comm.Unregister()

	for i := 1; i < 8; i++ {
		if i == 4 {
			resolver.AllAuthentic = true
			resolver.TLSA = map[string][]adns.TLSA{
				"_25._tcp.mail.mox.example.": {
					// Non-matching zero CertAssoc, should cause failure.
					{Usage: adns.TLSAUsageDANEEE, Selector: adns.TLSASelectorSPKI, MatchType: adns.TLSAMatchTypeSHA256, CertAssoc: make([]byte, sha256.Size)},
				},
			}
		} else {
			resolver.AllAuthentic = false
			resolver.TLSA = nil
		}
		go deliver(pkglog, resolver, msg)
		<-deliveryResults
		err = DB.Get(ctxbg, &msg)
		tcheck(t, err, "get msg")
		if msg.Attempts != i {
			t.Fatalf("got attempt %d, expected %d", msg.Attempts, i)
		}
		if msg.Attempts == 5 {
			timer.Reset(time.Second)
			changes := make(chan struct{}, 1)
			go func() {
				comm.Get()
				changes <- struct{}{}
			}()
			select {
			case <-changes:
			case <-timer.C:
				t.Fatalf("no dsn in 1s")
			}
		}
	}

	// Trigger final failure.
	go deliver(pkglog, resolver, msg)
	<-deliveryResults
	err = DB.Get(ctxbg, &msg)
	if err != bstore.ErrAbsent {
		t.Fatalf("attempt to fetch delivered and removed message from queue, got err %v, expected ErrAbsent", err)
	}

	timer.Reset(time.Second)
	changes := make(chan struct{}, 1)
	go func() {
		comm.Get()
		changes <- struct{}{}
	}()
	select {
	case <-changes:
	case <-timer.C:
		t.Fatalf("no dsn in 1s")
	}

	// We shouldn't have any more work to do.
	msgs, err = List(ctxbg, Filter{}, Sort{})
	tcheck(t, err, "list messages at end of test")
	tcompare(t, len(msgs), 0)
}

func addCounts(success, failure int64, result tlsrpt.Result) tlsrpt.Result {
	result.Summary.TotalSuccessfulSessionCount += success
	result.Summary.TotalFailureSessionCount += failure
	return result
}

func clearTLSResults(t *testing.T) {
	_, err := bstore.QueryDB[tlsrptdb.TLSResult](ctxbg, tlsrptdb.ResultDB).Delete()
	tcheck(t, err, "delete tls results")
}

func checkTLSResults(t *testing.T, policyDomain, expRecipientDomain string, expIsHost bool, expResults ...tlsrpt.Result) {
	t.Helper()
	q := bstore.QueryDB[tlsrptdb.TLSResult](ctxbg, tlsrptdb.ResultDB)
	q.FilterNonzero(tlsrptdb.TLSResult{PolicyDomain: policyDomain})
	result, err := q.Get()
	tcheck(t, err, "get tls result")
	tcompare(t, result.RecipientDomain, expRecipientDomain)
	tcompare(t, result.IsHost, expIsHost)

	// Before comparing, compensate for go1.20 vs go1.21 difference.
	for i, r := range result.Results {
		for j, fd := range r.FailureDetails {
			if fd.FailureReasonCode == "tls-remote-alert-70" {
				result.Results[i].FailureDetails[j].FailureReasonCode = "tls-remote-alert-70-protocol-version-not-supported"
			}
		}
	}
	tcompare(t, result.Results, expResults)
}

// Test delivered/permfailed/suppressed/canceled/dropped messages are stored in the
// retired list if configured, with a proper result, that webhooks are scheduled,
// and that cleaning up works.
func TestRetiredHooks(t *testing.T) {
	_, cleanup := setup(t)
	defer cleanup()

	addr, err := smtp.ParseAddress("mjl@mox.example")
	tcheck(t, err, "parse address")
	path := addr.Path()

	mf := prepareFile(t)
	defer os.Remove(mf.Name())
	defer mf.Close()

	resolver := dns.MockResolver{
		A:  map[string][]string{"mox.example.": {"127.0.0.1"}},
		MX: map[string][]*net.MX{"mox.example.": {{Host: "mox.example", Pref: 10}}},
	}

	testAction := func(account string, action func(), expResult *MsgResult, expEvent string, expSuppressing bool) {
		t.Helper()

		_, err := bstore.QueryDB[MsgRetired](ctxbg, DB).Delete()
		tcheck(t, err, "clearing retired messages")
		_, err = bstore.QueryDB[Hook](ctxbg, DB).Delete()
		tcheck(t, err, "clearing hooks")

		qm := MakeMsg(path, path, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, time.Now(), "test")
		qm.Extra = map[string]string{"a": "123"}
		err = Add(ctxbg, pkglog, account, mf, qm)
		tcheck(t, err, "add to queue")

		action()

		// Should be no messages left in queue.
		msgs, err := List(ctxbg, Filter{}, Sort{})
		tcheck(t, err, "list messages")
		tcompare(t, len(msgs), 0)

		retireds, err := RetiredList(ctxbg, RetiredFilter{}, RetiredSort{})
		tcheck(t, err, "list retired messages")
		hooks, err := HookList(ctxbg, HookFilter{}, HookSort{})
		tcheck(t, err, "list hooks")
		if expResult == nil {
			tcompare(t, len(retireds), 0)
			tcompare(t, len(hooks), 0)
		} else {
			tcompare(t, len(retireds), 1)
			mr := retireds[0]
			tcompare(t, len(mr.Results) > 0, true)
			lr := mr.LastResult()
			lr.Start = time.Time{}
			lr.Duration = 0
			tcompare(t, lr.Error == "", expResult.Error == "")
			lr.Error = expResult.Error
			tcompare(t, lr, *expResult)

			// Compare added webhook.
			tcompare(t, len(hooks), 1)
			h := hooks[0]
			var out webhook.Outgoing
			dec := json.NewDecoder(strings.NewReader(h.Payload))
			dec.DisallowUnknownFields()
			err := dec.Decode(&out)
			tcheck(t, err, "unmarshal outgoing webhook payload")
			tcompare(t, out.Error == "", expResult.Error == "")
			out.WebhookQueued = time.Time{}
			out.Error = ""
			var ecode string
			if expResult.Secode != "" {
				ecode = fmt.Sprintf("%d.%s", expResult.Code/100, expResult.Secode)
			}
			var code int // Only set for errors.
			if expResult.Code != 250 {
				code = expResult.Code
			}
			expOut := webhook.Outgoing{
				Event:            webhook.OutgoingEvent(expEvent),
				Suppressing:      expSuppressing,
				QueueMsgID:       mr.ID,
				FromID:           mr.FromID,
				MessageID:        mr.MessageID,
				Subject:          mr.Subject,
				SMTPCode:         code,
				SMTPEnhancedCode: ecode,
				Extra:            mr.Extra,
			}
			tcompare(t, out, expOut)
			h.ID = 0
			h.Payload = ""
			h.Submitted = time.Time{}
			h.NextAttempt = time.Time{}
			exph := Hook{0, mr.ID, "", mr.MessageID, mr.Subject, mr.Extra, mr.SenderAccount, "http://localhost:1234/outgoing", "Basic dXNlcm5hbWU6cGFzc3dvcmQ=", false, expEvent, "", time.Time{}, 0, time.Time{}, nil}
			tcompare(t, h, exph)
		}
	}

	makeLaunchAction := func(handler func(conn net.Conn)) func() {
		return func() {
			server, client := net.Pipe()
			defer server.Close()

			smtpclient.DialHook = func(ctx context.Context, dialer smtpclient.Dialer, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
				go handler(server)
				return client, nil
			}
			defer func() {
				smtpclient.DialHook = nil
			}()

			// Trigger delivery attempt.
			n := launchWork(pkglog, resolver, map[string]struct{}{})
			tcompare(t, n, 1)

			// Wait until delivery has finished.
			tm := time.NewTimer(5 * time.Second)
			defer tm.Stop()
			select {
			case <-tm.C:
				t.Fatalf("delivery didn't happen within 5s")
			case <-deliveryResults:
			}
		}
	}

	smtpAccept := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		readline := func(cmd string) {
			line, err := br.ReadString('\n')
			if err == nil && !strings.HasPrefix(strings.ToLower(line), cmd) {
				panic(fmt.Sprintf("unexpected line %q, expected %q", line, cmd))
			}
		}
		writeline := func(s string) {
			fmt.Fprintf(conn, "%s\r\n", s)
		}

		writeline("220 mail.mox.example")
		readline("ehlo")
		writeline("250 mail.mox.example")

		readline("mail")
		writeline("250 ok")
		readline("rcpt")
		writeline("250 ok")
		readline("data")
		writeline("354 continue")
		reader := smtp.NewDataReader(br)
		io.Copy(io.Discard, reader)
		writeline("250 ok")
		readline("quit")
		writeline("250 ok")
	}
	smtpReject := func(code int) func(conn net.Conn) {
		return func(conn net.Conn) {
			br := bufio.NewReader(conn)
			readline := func(cmd string) {
				line, err := br.ReadString('\n')
				if err == nil && !strings.HasPrefix(strings.ToLower(line), cmd) {
					panic(fmt.Sprintf("unexpected line %q, expected %q", line, cmd))
				}
			}
			writeline := func(s string) {
				fmt.Fprintf(conn, "%s\r\n", s)
			}

			writeline("220 mail.mox.example")
			readline("ehlo")
			writeline("250-mail.mox.example")
			writeline("250 enhancedstatuscodes")

			readline("mail")
			writeline(fmt.Sprintf("%d 5.1.0 nok", code))
			readline("quit")
			writeline("250 ok")
		}
	}

	testAction("mjl", makeLaunchAction(smtpAccept), nil, "", false)
	testAction("retired", makeLaunchAction(smtpAccept), &MsgResult{Code: 250, Success: true}, string(webhook.EventDelivered), false)
	// 554 is generic, doesn't immediately cause suppression.
	testAction("mjl", makeLaunchAction(smtpReject(554)), nil, "", false)
	testAction("retired", makeLaunchAction(smtpReject(554)), &MsgResult{Code: 554, Secode: "1.0", Error: "nonempty"}, string(webhook.EventFailed), false)
	// 550 causes immediate suppression, check for it in webhook.
	testAction("mjl", makeLaunchAction(smtpReject(550)), nil, "", true)
	testAction("retired", makeLaunchAction(smtpReject(550)), &MsgResult{Code: 550, Secode: "1.0", Error: "nonempty"}, string(webhook.EventFailed), true)
	// Try to deliver to suppressed addresses.
	launch := func() {
		n := launchWork(pkglog, resolver, map[string]struct{}{})
		tcompare(t, n, 1)
		<-deliveryResults
	}
	testAction("mjl", launch, nil, "", false)
	testAction("retired", launch, &MsgResult{Error: "nonempty"}, string(webhook.EventSuppressed), false)

	queueFail := func() {
		n, err := Fail(ctxbg, pkglog, Filter{})
		tcheck(t, err, "cancel delivery with failure dsn")
		tcompare(t, n, 1)
	}
	queueDrop := func() {
		n, err := Drop(ctxbg, pkglog, Filter{})
		tcheck(t, err, "cancel delivery without failure dsn")
		tcompare(t, n, 1)
	}
	testAction("mjl", queueFail, nil, "", false)
	testAction("retired", queueFail, &MsgResult{Error: "nonempty"}, string(webhook.EventFailed), false)
	testAction("mjl", queueDrop, nil, "", false)
	testAction("retired", queueDrop, &MsgResult{Error: "nonempty"}, string(webhook.EventCanceled), false)

	retireds, err := RetiredList(ctxbg, RetiredFilter{}, RetiredSort{})
	tcheck(t, err, "list retired messages")
	tcompare(t, len(retireds), 1)

	cleanupMsgRetiredSingle(pkglog)
	retireds, err = RetiredList(ctxbg, RetiredFilter{}, RetiredSort{})
	tcheck(t, err, "list retired messages")
	tcompare(t, len(retireds), 0)
}

// test Start and that it attempts to deliver.
func TestQueueStart(t *testing.T) {
	// Override dial function. We'll make connecting fail and check the attempt.
	resolver := dns.MockResolver{
		A:  map[string][]string{"mox.example.": {"127.0.0.1"}},
		MX: map[string][]*net.MX{"mox.example.": {{Host: "mox.example", Pref: 10}}},
	}
	dialed := make(chan struct{}, 1)
	smtpclient.DialHook = func(ctx context.Context, dialer smtpclient.Dialer, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
		dialed <- struct{}{}
		return nil, fmt.Errorf("failure from test")
	}
	defer func() {
		smtpclient.DialHook = nil
	}()

	_, cleanup := setup(t)
	defer cleanup()

	done := make(chan struct{})
	defer func() {
		mox.ShutdownCancel()
		// Wait for message and hooks deliverers and cleaners.
		<-done
		<-done
		<-done
		<-done
		mox.Shutdown, mox.ShutdownCancel = context.WithCancel(ctxbg)
	}()
	Shutdown() // DB was opened already. Start will open it again. Just close it before.
	err := Start(resolver, done)
	tcheck(t, err, "queue start")

	checkDialed := func(need bool) {
		t.Helper()
		d := time.Second / 10
		if need {
			d = time.Second
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-dialed:
			if !need {
				t.Fatalf("unexpected dial attempt")
			}
		case <-timer.C:
			if need {
				t.Fatalf("expected to see a dial attempt")
			}
		}
	}

	// HoldRule to mark mark all messages sent by mjl on hold, including existing
	// messages.
	hr0, err := HoldRuleAdd(ctxbg, pkglog, HoldRule{Account: "mjl"})
	tcheck(t, err, "add hold rule")

	// All zero HoldRule holds all deliveries, and marks all on hold.
	hr1, err := HoldRuleAdd(ctxbg, pkglog, HoldRule{})
	tcheck(t, err, "add hold rule")

	hrl, err := HoldRuleList(ctxbg)
	tcheck(t, err, "listing hold rules")
	tcompare(t, hrl, []HoldRule{hr0, hr1})

	path := smtp.Path{Localpart: "mjl", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mox.example"}}}
	mf := prepareFile(t)
	defer os.Remove(mf.Name())
	defer mf.Close()
	qm := MakeMsg(path, path, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, time.Now(), "test")
	err = Add(ctxbg, pkglog, "mjl", mf, qm)
	tcheck(t, err, "add message to queue for delivery")
	checkDialed(false) // No delivery attempt yet.

	n, err := Count(ctxbg)
	tcheck(t, err, "count messages in queue")
	tcompare(t, n, 1)

	// Take message off hold.
	n, err = HoldSet(ctxbg, Filter{}, false)
	tcheck(t, err, "taking message off hold")
	tcompare(t, n, 1)
	checkDialed(true)

	// Remove hold rules.
	err = HoldRuleRemove(ctxbg, pkglog, hr1.ID)
	tcheck(t, err, "removing hold rule")
	err = HoldRuleRemove(ctxbg, pkglog, hr0.ID)
	tcheck(t, err, "removing hold rule")
	// Check it is gone.
	hrl, err = HoldRuleList(ctxbg)
	tcheck(t, err, "listing hold rules")
	tcompare(t, len(hrl), 0)

	// Don't change message nextattempt time, but kick queue. Message should not be delivered.
	msgqueueKick()
	checkDialed(false)

	// Set new next attempt, should see another attempt.
	n, err = NextAttemptSet(ctxbg, Filter{From: "@mox.example"}, time.Now())
	tcheck(t, err, "kick queue")
	if n != 1 {
		t.Fatalf("kick changed %d messages, expected 1", n)
	}
	checkDialed(true)

	// Submit another, should be delivered immediately without HoldRule.
	path = smtp.Path{Localpart: "mjl", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mox.example"}}}
	mf = prepareFile(t)
	defer os.Remove(mf.Name())
	defer mf.Close()
	qm = MakeMsg(path, path, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, time.Now(), "test")
	err = Add(ctxbg, pkglog, "mjl", mf, qm)
	tcheck(t, err, "add message to queue for delivery")
	checkDialed(true) // Immediate.
}

func TestListFilterSort(t *testing.T) {
	_, cleanup := setup(t)
	defer cleanup()

	// insert Msgs. insert RetiredMsgs based on that. call list with filters and sort. filter to select a single. filter to paginate one by one, and in reverse.

	path := smtp.Path{Localpart: "mjl", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mox.example"}}}
	mf := prepareFile(t)
	defer os.Remove(mf.Name())
	defer mf.Close()

	now := time.Now().Round(0)
	qm := MakeMsg(path, path, false, false, int64(len(testmsg)), "<test@localhost>", nil, nil, now, "test")
	qm.Queued = now
	qm1 := qm
	qm1.Queued = now.Add(-time.Second)
	qm1.NextAttempt = now.Add(time.Minute)
	qml := []Msg{qm, qm, qm, qm, qm, qm1}
	err := Add(ctxbg, pkglog, "mjl", mf, qml...)
	tcheck(t, err, "add messages to queue")
	qm1 = qml[len(qml)-1]

	qmlrev := slices.Clone(qml)
	slices.Reverse(qmlrev)

	// Ascending by nextattempt,id.
	l, err := List(ctxbg, Filter{}, Sort{Asc: true})
	tcheck(t, err, "list messages")
	tcompare(t, l, qml)

	// Descending by nextattempt,id.
	l, err = List(ctxbg, Filter{}, Sort{})
	tcheck(t, err, "list messages")
	tcompare(t, l, qmlrev)

	// Descending by queued,id.
	l, err = List(ctxbg, Filter{}, Sort{Field: "Queued"})
	tcheck(t, err, "list messages")
	ql := append(append([]Msg{}, qmlrev[1:]...), qml[5])
	tcompare(t, l, ql)

	// Filter by all fields to get a single.
	no := false
	allfilters := Filter{
		Max:         2,
		IDs:         []int64{qm1.ID},
		Account:     "mjl",
		From:        path.XString(true),
		To:          path.XString(true),
		Hold:        &no,
		Submitted:   "<1s",
		NextAttempt: ">1s",
	}
	l, err = List(ctxbg, allfilters, Sort{})
	tcheck(t, err, "list single")
	tcompare(t, l, []Msg{qm1})

	// Paginated NextAttmpt asc.
	var lastID int64
	var last any
	l = nil
	for {
		nl, err := List(ctxbg, Filter{Max: 1}, Sort{Asc: true, LastID: lastID, Last: last})
		tcheck(t, err, "list paginated")
		l = append(l, nl...)
		if len(nl) == 0 {
			break
		}
		tcompare(t, len(nl), 1)
		lastID, last = nl[0].ID, nl[0].NextAttempt.Format(time.RFC3339Nano)
	}
	tcompare(t, l, qml)

	// Paginated NextAttempt desc.
	l = nil
	lastID = 0
	last = ""
	for {
		nl, err := List(ctxbg, Filter{Max: 1}, Sort{LastID: lastID, Last: last})
		tcheck(t, err, "list paginated")
		l = append(l, nl...)
		if len(nl) == 0 {
			break
		}
		tcompare(t, len(nl), 1)
		lastID, last = nl[0].ID, nl[0].NextAttempt.Format(time.RFC3339Nano)
	}
	tcompare(t, l, qmlrev)

	// Paginated Queued desc.
	l = nil
	lastID = 0
	last = ""
	for {
		nl, err := List(ctxbg, Filter{Max: 1}, Sort{Field: "Queued", LastID: lastID, Last: last})
		tcheck(t, err, "list paginated")
		l = append(l, nl...)
		if len(nl) == 0 {
			break
		}
		tcompare(t, len(nl), 1)
		lastID, last = nl[0].ID, nl[0].Queued.Format(time.RFC3339Nano)
	}
	tcompare(t, l, ql)

	// Paginated Queued asc.
	l = nil
	lastID = 0
	last = ""
	for {
		nl, err := List(ctxbg, Filter{Max: 1}, Sort{Field: "Queued", Asc: true, LastID: lastID, Last: last})
		tcheck(t, err, "list paginated")
		l = append(l, nl...)
		if len(nl) == 0 {
			break
		}
		tcompare(t, len(nl), 1)
		lastID, last = nl[0].ID, nl[0].Queued.Format(time.RFC3339Nano)
	}
	qlrev := slices.Clone(ql)
	slices.Reverse(qlrev)
	tcompare(t, l, qlrev)

	// Retire messages and do similar but more basic tests. The code is similar.
	var mrl []MsgRetired
	err = DB.Write(ctxbg, func(tx *bstore.Tx) error {
		for _, m := range qml {
			mr := m.Retired(false, m.NextAttempt, time.Now().Add(time.Minute).Round(0))
			err := tx.Insert(&mr)
			tcheck(t, err, "inserting retired message")
			mrl = append(mrl, mr)
		}
		return nil
	})
	tcheck(t, err, "adding retired messages")

	// Paginated LastActivity desc.
	var lr []MsgRetired
	lastID = 0
	last = ""
	l = nil
	for {
		nl, err := RetiredList(ctxbg, RetiredFilter{Max: 1}, RetiredSort{LastID: lastID, Last: last})
		tcheck(t, err, "list paginated")
		lr = append(lr, nl...)
		if len(nl) == 0 {
			break
		}
		tcompare(t, len(nl), 1)
		lastID, last = nl[0].ID, nl[0].LastActivity.Format(time.RFC3339Nano)
	}
	mrlrev := slices.Clone(mrl)
	slices.Reverse(mrlrev)
	tcompare(t, lr, mrlrev)

	// Filter by all fields to get a single.
	allretiredfilters := RetiredFilter{
		Max:          2,
		IDs:          []int64{mrlrev[0].ID},
		Account:      "mjl",
		From:         path.XString(true),
		To:           path.XString(true),
		Submitted:    "<1s",
		LastActivity: ">1s",
	}
	lr, err = RetiredList(ctxbg, allretiredfilters, RetiredSort{})
	tcheck(t, err, "list single")
	tcompare(t, lr, []MsgRetired{mrlrev[0]})
}

// Just a cert that appears valid.
func fakeCert(t *testing.T, name string, expired bool) tls.Certificate {
	notAfter := time.Now()
	if expired {
		notAfter = notAfter.Add(-time.Hour)
	} else {
		notAfter = notAfter.Add(time.Hour)
	}

	privKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Fake key, don't use this for real!
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field...
		DNSNames:     []string{name},
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
