package queue

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

var ctxbg = context.Background()

func tcheck(t *testing.T, err error, msg string) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %s", msg, err)
	}
}

func setup(t *testing.T) (*store.Account, func()) {
	// Prepare config so email can be delivered to mjl@mox.example.
	os.RemoveAll("../testdata/queue/data")
	mox.Context = ctxbg
	mox.ConfigStaticPath = "../testdata/queue/mox.conf"
	mox.MustLoadConfig(false)
	acc, err := store.OpenAccount("mjl")
	tcheck(t, err, "open account")
	err = acc.SetPassword("testtest")
	tcheck(t, err, "set password")
	switchDone := store.Switchboard()
	mox.Shutdown, mox.ShutdownCancel = context.WithCancel(ctxbg)
	return acc, func() {
		acc.Close()
		mox.ShutdownCancel()
		mox.Shutdown, mox.ShutdownCancel = context.WithCancel(ctxbg)
		Shutdown()
		close(switchDone)
	}
}

var testmsg = strings.ReplaceAll(`From: <mjl@mox.example>
To: <mjl@mox.example>
Subject: test

test email
`, "\n", "\r\n")

func prepareFile(t *testing.T) *os.File {
	t.Helper()
	msgFile, err := store.CreateMessageTemp("queue")
	tcheck(t, err, "create temp message for delivery to queue")
	_, err = msgFile.Write([]byte(testmsg))
	tcheck(t, err, "write message file")
	return msgFile
}

func TestQueue(t *testing.T) {
	acc, cleanup := setup(t)
	defer cleanup()
	err := Init()
	tcheck(t, err, "queue init")

	msgs, err := List(ctxbg)
	tcheck(t, err, "listing messages in queue")
	if len(msgs) != 0 {
		t.Fatalf("got %d messages in queue, expected 0", len(msgs))
	}

	path := smtp.Path{Localpart: "mjl", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mox.example"}}}
	err = Add(ctxbg, xlog, "mjl", path, path, false, false, int64(len(testmsg)), nil, prepareFile(t), nil, true)
	tcheck(t, err, "add message to queue for delivery")

	mf2 := prepareFile(t)
	err = Add(ctxbg, xlog, "mjl", path, path, false, false, int64(len(testmsg)), nil, mf2, nil, false)
	tcheck(t, err, "add message to queue for delivery")
	os.Remove(mf2.Name())

	msgs, err = List(ctxbg)
	tcheck(t, err, "listing queue")
	if len(msgs) != 2 {
		t.Fatalf("got msgs %v, expected 1", msgs)
	}
	msg := msgs[0]
	if msg.Attempts != 0 {
		t.Fatalf("msg attempts %d, expected 0", msg.Attempts)
	}
	n, err := Drop(ctxbg, msgs[1].ID, "", "")
	tcheck(t, err, "drop")
	if n != 1 {
		t.Fatalf("dropped %d, expected 1", n)
	}

	next := nextWork(ctxbg, nil)
	if next > 0 {
		t.Fatalf("nextWork in %s, should be now", next)
	}
	busy := map[string]struct{}{"mox.example": {}}
	if x := nextWork(ctxbg, busy); x != 24*time.Hour {
		t.Fatalf("nextWork in %s for busy domain, should be in 24 hours", x)
	}
	if nn := launchWork(nil, busy); nn != 0 {
		t.Fatalf("launchWork launched %d deliveries, expected 0", nn)
	}

	// Override dial function. We'll make connecting fail for now.
	resolver := dns.MockResolver{
		A:  map[string][]string{"mox.example.": {"127.0.0.1"}},
		MX: map[string][]*net.MX{"mox.example.": {{Host: "mox.example", Pref: 10}}},
	}
	dialed := make(chan struct{}, 1)
	dial = func(ctx context.Context, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
		dialed <- struct{}{}
		return nil, fmt.Errorf("failure from test")
	}

	launchWork(resolver, map[string]struct{}{})

	// Wait until we see the dial and the failed attempt.
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-dialed:
		i := 0
		for {
			m, err := bstore.QueryDB[Msg](ctxbg, queueDB).Get()
			tcheck(t, err, "get")
			if m.Attempts == 1 {
				break
			}
			i++
			if i == 10 {
				t.Fatalf("message in queue not updated")
			}
			time.Sleep(100 * time.Millisecond)
		}
	case <-timer.C:
		t.Fatalf("no dial within 1s")
	}
	<-deliveryResult // Deliver sends here.

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

	n, err = Kick(ctxbg, msg.ID+1, "", "")
	tcheck(t, err, "kick")
	if n != 0 {
		t.Fatalf("kick %d, expected 0", n)
	}
	n, err = Kick(ctxbg, msg.ID, "", "")
	tcheck(t, err, "kick")
	if n != 1 {
		t.Fatalf("kicked %d, expected 1", n)
	}

	// Setting up a pipe. We'll start a fake smtp server on the server-side. And return the
	// client-side to the invocation dial, for the attempted delivery from the queue.
	// The delivery should succeed.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	smtpdone := make(chan struct{})
	go func() {
		// We do a minimal fake smtp server. We cannot import smtpserver.Serve due to cyclic dependencies.
		fmt.Fprintf(server, "220 mox.example\r\n")
		br := bufio.NewReader(server)
		br.ReadString('\n') // Should be EHLO.
		fmt.Fprintf(server, "250 ok\r\n")
		br.ReadString('\n') // Should be MAIL FROM.
		fmt.Fprintf(server, "250 ok\r\n")
		br.ReadString('\n') // Should be RCPT TO.
		fmt.Fprintf(server, "250 ok\r\n")
		br.ReadString('\n') // Should be DATA.
		fmt.Fprintf(server, "354 continue\r\n")
		reader := smtp.NewDataReader(br)
		io.Copy(io.Discard, reader)
		fmt.Fprintf(server, "250 ok\r\n")
		br.ReadString('\n') // Should be QUIT.
		fmt.Fprintf(server, "221 ok\r\n")

		smtpdone <- struct{}{}
	}()

	dial = func(ctx context.Context, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
		dialed <- struct{}{}
		return client, nil
	}
	launchWork(resolver, map[string]struct{}{})

	timer.Reset(time.Second)
	select {
	case <-dialed:
		select {
		case <-smtpdone:
			i := 0
			for {
				xmsgs, err := List(ctxbg)
				tcheck(t, err, "list queue")
				if len(xmsgs) == 0 {
					break
				}
				i++
				if i == 10 {
					t.Fatalf("%d messages in queue, expected 0", len(xmsgs))
				}
				time.Sleep(100 * time.Millisecond)
			}
		case <-timer.C:
			t.Fatalf("no deliver within 1s")
		}
	case <-timer.C:
		t.Fatalf("no dial within 1s")
	}
	<-deliveryResult // Deliver sends here.

	// Add another message that we'll fail to deliver entirely.
	err = Add(ctxbg, xlog, "mjl", path, path, false, false, int64(len(testmsg)), nil, prepareFile(t), nil, true)
	tcheck(t, err, "add message to queue for delivery")

	msgs, err = List(ctxbg)
	tcheck(t, err, "list queue")
	if len(msgs) != 1 {
		t.Fatalf("queue has %d messages, expected 1", len(msgs))
	}
	msg = msgs[0]

	prepServer := func(code string) (net.Conn, func()) {
		server, client := net.Pipe()
		go func() {
			fmt.Fprintf(server, "%s mox.example\r\n", code)
			server.Close()
		}()
		return client, func() {
			server.Close()
			client.Close()
		}
	}

	conn2, cleanup2 := prepServer("220")
	conn3, cleanup3 := prepServer("451")
	defer func() {
		cleanup2()
		cleanup3()
	}()

	seq := 0
	dial = func(ctx context.Context, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
		seq++
		switch seq {
		default:
			return nil, fmt.Errorf("connect error from test")
		case 2:
			return conn2, nil
		case 3:
			return conn3, nil
		}
	}

	comm := store.RegisterComm(acc)
	defer comm.Unregister()

	for i := 1; i < 8; i++ {
		go func() { <-deliveryResult }() // Deliver sends here.
		deliver(resolver, msg)
		err = queueDB.Get(ctxbg, &msg)
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
	go func() { <-deliveryResult }() // Deliver sends here.
	deliver(resolver, msg)
	err = queueDB.Get(ctxbg, &msg)
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
}

// test Start and that it attempts to deliver.
func TestQueueStart(t *testing.T) {
	// Override dial function. We'll make connecting fail and check the attempt.
	resolver := dns.MockResolver{
		A:  map[string][]string{"mox.example.": {"127.0.0.1"}},
		MX: map[string][]*net.MX{"mox.example.": {{Host: "mox.example", Pref: 10}}},
	}
	dialed := make(chan struct{}, 1)
	dial = func(ctx context.Context, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
		dialed <- struct{}{}
		return nil, fmt.Errorf("failure from test")
	}

	_, cleanup := setup(t)
	defer cleanup()
	done := make(chan struct{}, 1)
	defer func() {
		mox.ShutdownCancel()
		<-done
		mox.Shutdown, mox.ShutdownCancel = context.WithCancel(ctxbg)
	}()
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

	path := smtp.Path{Localpart: "mjl", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mox.example"}}}
	err = Add(ctxbg, xlog, "mjl", path, path, false, false, int64(len(testmsg)), nil, prepareFile(t), nil, true)
	tcheck(t, err, "add message to queue for delivery")
	checkDialed(true)

	// Don't change message nextattempt time, but kick queue. Message should not be delivered.
	queuekick()
	checkDialed(false)

	// Kick for real, should see another attempt.
	n, err := Kick(ctxbg, 0, "mox.example", "")
	tcheck(t, err, "kick queue")
	if n != 1 {
		t.Fatalf("kick changed %d messages, expected 1", n)
	}
	checkDialed(true)
	time.Sleep(100 * time.Millisecond) // Racy... we won't get notified when work is done...
}

func TestWriteFile(t *testing.T) {
	name := "../testdata/queue.test"
	os.Remove(name)
	defer os.Remove(name)
	err := writeFile(name, strings.NewReader("test"))
	if err != nil {
		t.Fatalf("writeFile, unexpected error %v", err)
	}
	buf, err := os.ReadFile(name)
	if err != nil || string(buf) != "test" {
		t.Fatalf("writeFile, read file, got err %v, data %q", err, buf)
	}
}

func TestGatherHosts(t *testing.T) {
	mox.Context = ctxbg

	// Test basic MX lookup case, but also following CNAME, detecting CNAME loops and
	// having a CNAME limit, connecting directly to a host, and domain that does not
	// exist or has temporary error.

	resolver := dns.MockResolver{
		MX: map[string][]*net.MX{
			"basic.example.":        {{Host: "mail.basic.example.", Pref: 10}},
			"multimx.example.":      {{Host: "mail1.multimx.example.", Pref: 10}, {Host: "mail2.multimx.example.", Pref: 10}},
			"nullmx.example.":       {{Host: ".", Pref: 10}},
			"temperror-mx.example.": {{Host: "absent.example.", Pref: 10}},
		},
		A: map[string][]string{
			"mail.basic.example":   {"10.0.0.1"},
			"justhost.example.":    {"10.0.0.1"}, // No MX record for domain, only an A record.
			"temperror-a.example.": {"10.0.0.1"},
		},
		AAAA: map[string][]string{
			"justhost6.example.": {"2001:db8::1"}, // No MX record for domain, only an AAAA record.
		},
		CNAME: map[string]string{
			"cname.example.":           "basic.example.",
			"cnameloop.example.":       "cnameloop2.example.",
			"cnameloop2.example.":      "cnameloop.example.",
			"danglingcname.example.":   "absent.example.", // Points to missing name.
			"temperror-cname.example.": "absent.example.",
		},
		Fail: map[dns.Mockreq]struct{}{
			{Type: "mx", Name: "temperror-mx.example."}:       {},
			{Type: "host", Name: "temperror-a.example."}:      {},
			{Type: "cname", Name: "temperror-cname.example."}: {},
		},
	}
	for i := 0; i <= 16; i++ {
		s := fmt.Sprintf("cnamelimit%d.example.", i)
		next := fmt.Sprintf("cnamelimit%d.example.", i+1)
		resolver.CNAME[s] = next
	}

	test := func(ipd dns.IPDomain, expHosts []dns.IPDomain, expDomain dns.Domain, expPerm bool, expErr error) {
		t.Helper()

		m := Msg{RecipientDomain: ipd}
		hosts, ed, perm, err := gatherHosts(resolver, m, 1, xlog)
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			// todo: could also check the individual errors? code currently does not have structured errors.
			t.Fatalf("gather hosts: %v", err)
		}
		if err != nil {
			return
		}
		if !reflect.DeepEqual(hosts, expHosts) || ed != expDomain || perm != expPerm {
			t.Fatalf("got hosts %#v, effectiveDomain %#v, permanent %#v, expected %#v %#v %#v", hosts, ed, perm, expHosts, expDomain, expPerm)
		}
	}

	domain := func(s string) dns.Domain {
		d, err := dns.ParseDomain(s)
		if err != nil {
			t.Fatalf("parse domain: %v", err)
		}
		return d
	}
	ipdomain := func(s string) dns.IPDomain {
		ip := net.ParseIP(s)
		if ip != nil {
			return dns.IPDomain{IP: ip}
		}
		d, err := dns.ParseDomain(s)
		if err != nil {
			t.Fatalf("parse domain %q: %v", s, err)
		}
		return dns.IPDomain{Domain: d}
	}

	ipdomains := func(s ...string) (l []dns.IPDomain) {
		for _, e := range s {
			l = append(l, ipdomain(e))
		}
		return
	}

	var zerodom dns.Domain

	test(ipdomain("10.0.0.1"), ipdomains("10.0.0.1"), zerodom, false, nil)
	test(ipdomain("basic.example"), ipdomains("mail.basic.example"), domain("basic.example"), false, nil)                                 // Basic with simple MX.
	test(ipdomain("multimx.example"), ipdomains("mail1.multimx.example", "mail2.multimx.example"), domain("multimx.example"), false, nil) // Basic with simple MX.
	test(ipdomain("justhost.example"), ipdomains("justhost.example"), domain("justhost.example"), false, nil)                             // Only an A record.
	test(ipdomain("justhost6.example"), ipdomains("justhost6.example"), domain("justhost6.example"), false, nil)                          // Only an AAAA record.
	test(ipdomain("cname.example"), ipdomains("mail.basic.example"), domain("basic.example"), false, nil)                                 // Follow CNAME.
	test(ipdomain("cnamelimit1.example"), nil, zerodom, true, errCNAMELimit)
	test(ipdomain("cnameloop.example"), nil, zerodom, true, errCNAMELoop)
	test(ipdomain("absent.example"), nil, zerodom, true, errNoRecord)
	test(ipdomain("danglingcname.example"), nil, zerodom, true, errNoRecord)
	test(ipdomain("nullmx.example"), nil, zerodom, true, errNoMail)
	test(ipdomain("temperror-mx.example"), nil, zerodom, false, errDNS)
	test(ipdomain("temperror-cname.example"), nil, zerodom, false, errDNS)
	test(ipdomain("temperror-a.example"), nil, zerodom, false, errDNS)
}

func TestDialHost(t *testing.T) {
	// We mostly want to test that dialing a second time switches to the other address family.

	resolver := dns.MockResolver{
		A: map[string][]string{
			"dualstack.example.": {"10.0.0.1"},
		},
		AAAA: map[string][]string{
			"dualstack.example.": {"2001:db8::1"},
		},
	}

	dial = func(ctx context.Context, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
		return nil, nil // No error, nil connection isn't used.
	}

	ipdomain := func(s string) dns.IPDomain {
		return dns.IPDomain{Domain: dns.Domain{ASCII: s}}
	}

	m := Msg{DialedIPs: map[string][]net.IP{}}
	_, ip, dualstack, err := dialHost(ctxbg, xlog, resolver, ipdomain("dualstack.example"), &m)
	if err != nil || ip.String() != "10.0.0.1" || !dualstack {
		t.Fatalf("expected err nil, address 10.0.0.1, dualstack true, got %v %v %v", err, ip, dualstack)
	}
	_, ip, dualstack, err = dialHost(ctxbg, xlog, resolver, ipdomain("dualstack.example"), &m)
	if err != nil || ip.String() != "2001:db8::1" || !dualstack {
		t.Fatalf("expected err nil, address 2001:db8::1, dualstack true, got %v %v %v", err, ip, dualstack)
	}
}
