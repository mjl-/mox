//go:build quickstart

// Run this using docker-compose.yml, see Makefile.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtpclient"
)

var xlog = mlog.New("quickstart")

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

func TestDeliver(t *testing.T) {
	mlog.Logfmt = true

	// smtpclient uses the hostname for outgoing connections.
	var err error
	mox.Conf.Static.HostnameDomain.ASCII, err = os.Hostname()
	tcheck(t, err, "hostname")

	// Deliver submits a message over submissions, and checks with imap idle if the
	// message is received by the destination mail server.
	deliver := func(desthost, mailfrom, password, rcptto, imaphost, imapuser, imappassword string) {
		t.Helper()

		// Connect to IMAP, execute IDLE command, which will return on deliver message.
		// TLS certificates work because the container has the CA certificates configured.
		imapconn, err := tls.Dial("tcp", imaphost+":993", nil)
		tcheck(t, err, "dial imap")
		defer imapconn.Close()

		imaperr := make(chan error, 1)
		go func() {
			go func() {
				x := recover()
				if x == nil {
					return
				}
				imaperr <- x.(error)
			}()
			xcheck := func(err error, format string) {
				if err != nil {
					panic(fmt.Errorf("%s: %w", format, err))
				}
			}

			imapc, err := imapclient.New(imapconn, false)
			xcheck(err, "new imapclient")

			_, _, err = imapc.Login(imapuser, imappassword)
			xcheck(err, "imap login")

			_, _, err = imapc.Select("Inbox")
			xcheck(err, "imap select inbox")

			err = imapc.Commandf("", "idle")
			xcheck(err, "write imap idle command")
			_, _, _, err = imapc.ReadContinuation()
			xcheck(err, "read imap continuation")

			done := make(chan error)
			go func() {
				defer func() {
					x := recover()
					if x != nil {
						done <- fmt.Errorf("%v", x)
					}
				}()
				untagged, err := imapc.ReadUntagged()
				if err != nil {
					done <- err
					return
				}
				if _, ok := untagged.(imapclient.UntaggedExists); !ok {
					done <- fmt.Errorf("expected imapclient.UntaggedExists, got %#v", untagged)
					return
				}
				done <- nil
			}()

			period := 30 * time.Second
			timer := time.NewTimer(period)
			defer timer.Stop()
			select {
			case err = <-done:
			case <-timer.C:
				err = fmt.Errorf("nothing within %v", period)
			}
			xcheck(err, "waiting for imap untagged repsonse to idle")
			imaperr <- nil
		}()

		conn, err := tls.Dial("tcp", desthost+":465", nil)
		tcheck(t, err, "dial submission")
		defer conn.Close()

		msg := fmt.Sprintf(`From: <%s>
To: <%s>
Subject: test message

This is the message.
`, mailfrom, rcptto)
		msg = strings.ReplaceAll(msg, "\n", "\r\n")
		auth := bytes.Join([][]byte{nil, []byte(mailfrom), []byte(password)}, []byte{0})
		authLine := fmt.Sprintf("AUTH PLAIN %s", base64.StdEncoding.EncodeToString(auth))
		c, err := smtpclient.New(mox.Context, xlog, conn, smtpclient.TLSSkip, desthost, authLine)
		tcheck(t, err, "smtp hello")
		err = c.Deliver(mox.Context, mailfrom, rcptto, int64(len(msg)), strings.NewReader(msg), false, false)
		tcheck(t, err, "deliver with smtp")
		err = c.Close()
		tcheck(t, err, "close smtpclient")

		err = <-imaperr
		tcheck(t, err, "imap idle")
	}

	xlog.Print("submitting email to moxacmepebble, waiting for imap notification at moxmail2, takes time because first-time sender")
	t0 := time.Now()
	deliver("moxacmepebble.mox1.example", "moxtest1@mox1.example", "accountpass1234", "moxtest2@mox2.example", "moxmail2.mox2.example", "moxtest2@mox2.example", "accountpass4321")
	xlog.Print("success", mlog.Field("duration", time.Since(t0)))

	xlog.Print("submitting email to moxmail2, waiting for imap notification at moxacmepebble, takes time because first-time sender")
	t0 = time.Now()
	deliver("moxmail2.mox2.example", "moxtest2@mox2.example", "accountpass4321", "moxtest1@mox1.example", "moxacmepebble.mox1.example", "moxtest1@mox1.example", "accountpass1234")
	xlog.Print("success", mlog.Field("duration", time.Since(t0)))
}
