//go:build integration

// todo: set up a test for dane, mta-sts, etc.

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtpclient"
)

func tcheck(t *testing.T, err error, errmsg string) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %s", errmsg, err)
	}
}

func TestDeliver(t *testing.T) {
	xlog := mlog.New("integration")
	mlog.Logfmt = true

	hostname, err := os.Hostname()
	tcheck(t, err, "hostname")
	ourHostname, err := dns.ParseDomain(hostname)
	tcheck(t, err, "parse hostname")

	// Single update from IMAP IDLE.
	type idleResponse struct {
		untagged imapclient.Untagged
		err      error
	}

	// Deliver submits a message over submissions, and checks with imap idle if the
	// message is received by the destination mail server.
	deliver := func(checkTime bool, dialtls bool, imaphost, imapuser, imappassword string, send func()) {
		t.Helper()

		// Connect to IMAP, execute IDLE command, which will return on deliver message.
		// TLS certificates work because the container has the CA certificates configured.
		var imapconn net.Conn
		var err error
		if dialtls {
			imapconn, err = tls.Dial("tcp", imaphost, nil)
		} else {
			imapconn, err = net.Dial("tcp", imaphost)
		}
		tcheck(t, err, "dial imap")
		defer imapconn.Close()

		imapc, err := imapclient.New(imapconn, false)
		tcheck(t, err, "new imapclient")

		_, _, err = imapc.Login(imapuser, imappassword)
		tcheck(t, err, "imap login")

		_, _, err = imapc.Select("Inbox")
		tcheck(t, err, "imap select inbox")

		err = imapc.Commandf("", "idle")
		tcheck(t, err, "write imap idle command")

		_, _, _, err = imapc.ReadContinuation()
		tcheck(t, err, "read imap continuation")

		idle := make(chan idleResponse)
		go func() {
			for {
				untagged, err := imapc.ReadUntagged()
				idle <- idleResponse{untagged, err}
				if err != nil {
					return
				}
			}
		}()
		defer func() {
			err := imapc.Writelinef("done")
			tcheck(t, err, "aborting idle")
		}()

		t0 := time.Now()
		send()

		// Wait for notification of delivery.
		select {
		case resp := <-idle:
			tcheck(t, resp.err, "idle notification")
			_, ok := resp.untagged.(imapclient.UntaggedExists)
			if !ok {
				t.Fatalf("got idle %#v, expected untagged exists", resp.untagged)
			}
			if d := time.Since(t0); checkTime && d < 1*time.Second {
				t.Fatalf("delivery took %v, but should have taken at least 1 second, the first-time sender delay", d)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("timeout after 5s waiting for IMAP IDLE notification of new message, should take about 1 second")
		}
	}

	submit := func(dialtls bool, mailfrom, password, desthost, rcptto string) {
		var conn net.Conn
		var err error
		if dialtls {
			conn, err = tls.Dial("tcp", desthost, nil)
		} else {
			conn, err = net.Dial("tcp", desthost)
		}
		tcheck(t, err, "dial submission")
		defer conn.Close()

		msg := fmt.Sprintf(`From: <%s>
To: <%s>
Subject: test message

This is the message.
`, mailfrom, rcptto)
		msg = strings.ReplaceAll(msg, "\n", "\r\n")
		auth := []sasl.Client{sasl.NewClientPlain(mailfrom, password)}
		c, err := smtpclient.New(mox.Context, xlog, conn, smtpclient.TLSSkip, false, ourHostname, dns.Domain{ASCII: desthost}, smtpclient.Opts{Auth: auth})
		tcheck(t, err, "smtp hello")
		err = c.Deliver(mox.Context, mailfrom, rcptto, int64(len(msg)), strings.NewReader(msg), false, false, false)
		tcheck(t, err, "deliver with smtp")
		err = c.Close()
		tcheck(t, err, "close smtpclient")
	}

	// Make sure moxacmepebble has a TLS certificate.
	conn, err := tls.Dial("tcp", "moxacmepebble.mox1.example:465", nil)
	tcheck(t, err, "dial submission")
	defer conn.Close()

	xlog.Print("submitting email to moxacmepebble, waiting for imap notification at moxmail2")
	t0 := time.Now()
	deliver(true, true, "moxmail2.mox2.example:993", "moxtest2@mox2.example", "accountpass4321", func() {
		submit(true, "moxtest1@mox1.example", "accountpass1234", "moxacmepebble.mox1.example:465", "moxtest2@mox2.example")
	})
	xlog.Print("success", mlog.Field("duration", time.Since(t0)))

	xlog.Print("submitting email to moxmail2, waiting for imap notification at moxacmepebble")
	t0 = time.Now()
	deliver(true, true, "moxacmepebble.mox1.example:993", "moxtest1@mox1.example", "accountpass1234", func() {
		submit(true, "moxtest2@mox2.example", "accountpass4321", "moxmail2.mox2.example:465", "moxtest1@mox1.example")
	})
	xlog.Print("success", mlog.Field("duration", time.Since(t0)))

	xlog.Print("submitting email to postfix, waiting for imap notification at moxacmepebble")
	t0 = time.Now()
	deliver(true, true, "moxacmepebble.mox1.example:993", "moxtest1@mox1.example", "accountpass1234", func() {
		submit(true, "moxtest1@mox1.example", "accountpass1234", "moxacmepebble.mox1.example:465", "root@postfix.example")
	})
	xlog.Print("success", mlog.Field("duration", time.Since(t0)))

	xlog.Print("submitting email to localserve")
	t0 = time.Now()
	deliver(false, false, "localserve.mox1.example:1143", "mox@localhost", "moxmoxmox", func() {
		submit(false, "mox@localhost", "moxmoxmox", "localserve.mox1.example:1587", "moxtest1@mox1.example")
	})
	xlog.Print("success", mlog.Field("duration", time.Since(t0)))

	xlog.Print("submitting email to localserve")
	t0 = time.Now()
	deliver(false, false, "localserve.mox1.example:1143", "mox@localhost", "moxmoxmox", func() {
		cmd := exec.Command("go", "run", ".", "sendmail", "mox@localhost")
		const msg = `Subject: test

a message.
`
		cmd.Stdin = strings.NewReader(msg)
		var out strings.Builder
		cmd.Stdout = &out
		err := cmd.Run()
		xlog.Print("sendmail", mlog.Field("output", out.String()))
		tcheck(t, err, "sendmail")
	})
	xlog.Print("success", mlog.Field("duration", time.Since(t0)))
}
