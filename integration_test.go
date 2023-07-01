//go:build integration

// Run this using docker-compose.yml, see Makefile.

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
)

var ctxbg = context.Background()

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

// Submit a message to mox, which sends it to postfix, which forwards back to mox.
// We check if we receive the message.
func TestDeliver(t *testing.T) {
	mlog.Logfmt = true
	log := mlog.New("test")

	// Remove state.
	os.RemoveAll("testdata/integration/data")
	os.MkdirAll("testdata/integration/data", 0750)

	// Cleanup afterwards, these are owned by root, annoying to have around due to
	// permission errors.
	defer os.RemoveAll("testdata/integration/data")

	// Load mox config.
	mox.ConfigStaticPath = "testdata/integration/config/mox.conf"
	filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	if errs := mox.LoadConfig(ctxbg, true, false); len(errs) > 0 {
		t.Fatalf("loading mox config: %v", errs)
	}

	// Create new accounts
	createAccount := func(email, password string) {
		t.Helper()
		acc, _, err := store.OpenEmail(email)
		tcheck(t, err, "open account")
		err = acc.SetPassword(password)
		tcheck(t, err, "setting password")
		err = acc.Close()
		tcheck(t, err, "closing account")
	}

	createAccount("moxtest1@mox1.example", "pass1234")
	createAccount("moxtest2@mox2.example", "pass1234")
	createAccount("moxtest3@mox3.example", "pass1234")

	// Start mox.
	const mtastsdbRefresher = false
	const skipForkExec = true
	err := start(mtastsdbRefresher, skipForkExec)
	tcheck(t, err, "starting mox")

	// Single update from IMAP IDLE.
	type idleResponse struct {
		untagged imapclient.Untagged
		err      error
	}

	testDeliver := func(checkTime bool, imapaddr, imapuser, imappass string, fn func()) {
		t.Helper()

		// Make IMAP connection, we'll wait for a delivery notification with IDLE.
		imapconn, err := net.Dial("tcp", imapaddr)
		tcheck(t, err, "dial imap server")
		defer imapconn.Close()
		client, err := imapclient.New(imapconn, false)
		tcheck(t, err, "new imapclient")
		_, _, err = client.Login(imapuser, imappass)
		tcheck(t, err, "imap client login")
		_, _, err = client.Select("inbox")
		tcheck(t, err, "imap select inbox")

		err = client.Commandf("", "idle")
		tcheck(t, err, "imap idle command")

		_, _, _, err = client.ReadContinuation()
		tcheck(t, err, "read imap continuation")

		idle := make(chan idleResponse)
		go func() {
			for {
				untagged, err := client.ReadUntagged()
				idle <- idleResponse{untagged, err}
				if err != nil {
					return
				}
			}
		}()
		defer func() {
			err := client.Writelinef("done")
			tcheck(t, err, "aborting idle")
		}()

		t0 := time.Now()
		fn()

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
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout after 5s waiting for IMAP IDLE notification of new message, should take about 1 second")
		}
	}

	submit := func(smtphost, smtpport, mailfrom, password, rcptto string) {
		conn, err := net.Dial("tcp", net.JoinHostPort(smtphost, smtpport))
		tcheck(t, err, "dial submission")
		defer conn.Close()

		msg := fmt.Sprintf(`From: <%s>
To: <%s>
Subject: test message

This is the message.
`, mailfrom, rcptto)
		msg = strings.ReplaceAll(msg, "\n", "\r\n")
		auth := []sasl.Client{sasl.NewClientPlain(mailfrom, password)}
		c, err := smtpclient.New(mox.Context, log, conn, smtpclient.TLSOpportunistic, mox.Conf.Static.HostnameDomain, dns.Domain{ASCII: smtphost}, auth)
		tcheck(t, err, "smtp hello")
		err = c.Deliver(mox.Context, mailfrom, rcptto, int64(len(msg)), strings.NewReader(msg), false, false)
		tcheck(t, err, "deliver with smtp")
		err = c.Close()
		tcheck(t, err, "close smtpclient")
	}

	testDeliver(true, "moxmail1.mox1.example:143", "moxtest1@mox1.example", "pass1234", func() {
		submit("moxmail1.mox1.example", "587", "moxtest1@mox1.example", "pass1234", "root@postfix.example")
	})
	testDeliver(true, "moxmail1.mox1.example:143", "moxtest3@mox3.example", "pass1234", func() {
		submit("moxmail2.mox2.example", "587", "moxtest2@mox2.example", "pass1234", "moxtest3@mox3.example")
	})

	testDeliver(false, "localserve.mox1.example:1143", "mox@localhost", "moxmoxmox", func() {
		submit("localserve.mox1.example", "1587", "mox@localhost", "moxmoxmox", "any@any.example")
	})

	testDeliver(false, "localserve.mox1.example:1143", "mox@localhost", "moxmoxmox", func() {
		cmd := exec.Command("go", "run", ".", "sendmail", "mox@localhost")
		const msg = `Subject: test

a message.
`
		cmd.Stdin = strings.NewReader(msg)
		var out strings.Builder
		cmd.Stdout = &out
		err := cmd.Run()
		log.Print("sendmail", mlog.Field("output", out.String()))
		tcheck(t, err, "sendmail")
	})
}
