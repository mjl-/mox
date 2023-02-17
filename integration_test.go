//go:build integration

// Run this using docker-compose.yml, see Makefile.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
)

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
	mox.Context, mox.ContextCancel = context.WithCancel(context.Background())
	mox.Shutdown, mox.ShutdownCancel = context.WithCancel(context.Background())

	// Remove state.
	os.RemoveAll("testdata/integration/run")
	os.MkdirAll("testdata/integration/run", 0750)

	// Load mox config.
	mox.ConfigStaticPath = "testdata/integration/mox.conf"
	filepath.Join(filepath.Dir(mox.ConfigStaticPath), "domains.conf")
	if errs := mox.LoadConfig(mox.Context); len(errs) > 0 {
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
	mtastsdbRefresher := false
	err := start(mtastsdbRefresher)
	tcheck(t, err, "starting mox")

	// todo: we should probably hook store.Comm to get updates.
	latestMsgID := func(username string) int64 {
		// We open the account index database created by mox for the test user. And we keep looking for the email we sent.
		dbpath := fmt.Sprintf("testdata/integration/run/accounts/%s/index.db", username)
		db, err := bstore.Open(dbpath, &bstore.Options{Timeout: 3 * time.Second}, store.Message{}, store.Recipient{}, store.Mailbox{}, store.Password{})
		if err != nil && errors.Is(err, bolt.ErrTimeout) {
			log.Printf("db open timeout (normal delay for new sender with account and db file kept open)")
			return 0
		}
		tcheck(t, err, "open test account database")
		defer db.Close()

		q := bstore.QueryDB[store.Mailbox](db)
		q.FilterNonzero(store.Mailbox{Name: "Inbox"})
		inbox, err := q.Get()
		if err != nil {
			log.Printf("inbox for finding latest message id: %v", err)
			return 0
		}

		qm := bstore.QueryDB[store.Message](db)
		qm.FilterNonzero(store.Message{MailboxID: inbox.ID})
		qm.SortDesc("ID")
		qm.Limit(1)
		m, err := qm.Get()
		if err != nil {
			log.Printf("finding latest message id: %v", err)
			return 0
		}
		return m.ID
	}

	waitForMsg := func(prevMsgID int64, username string) int64 {
		t.Helper()

		for i := 0; i < 10; i++ {
			msgID := latestMsgID(username)
			if msgID > prevMsgID {
				return msgID
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for message")
		return 0 // not reached
	}

	deliver := func(username, desthost, mailfrom, password, rcptto string) {
		t.Helper()

		prevMsgID := latestMsgID(username)

		conn, err := net.Dial("tcp", desthost+":587")
		tcheck(t, err, "dial submission")
		defer conn.Close()

		// todo: this is "aware" (hopefully) of the config smtpclient/client.go sets up... tricky
		mox.Conf.Static.HostnameDomain.ASCII = desthost
		msg := fmt.Sprintf(`From: <%s>
To: <%s>
Subject: test message

This is the message.
`, mailfrom, rcptto)
		msg = strings.ReplaceAll(msg, "\n", "\r\n")
		auth := bytes.Join([][]byte{nil, []byte(mailfrom), []byte(password)}, []byte{0})
		authLine := fmt.Sprintf("AUTH PLAIN %s", base64.StdEncoding.EncodeToString(auth))
		c, err := smtpclient.New(mox.Context, mlog.New("test"), conn, smtpclient.TLSOpportunistic, desthost, authLine)
		tcheck(t, err, "smtp hello")
		err = c.Deliver(mox.Context, mailfrom, rcptto, int64(len(msg)), strings.NewReader(msg), false, false)
		tcheck(t, err, "deliver with smtp")
		err = c.Close()
		tcheck(t, err, "close smtpclient")

		waitForMsg(prevMsgID, username)
	}

	deliver("moxtest1", "moxmail1.mox1.example", "moxtest1@mox1.example", "pass1234", "root@postfix.example")
	deliver("moxtest3", "moxmail2.mox2.example", "moxtest2@mox2.example", "pass1234", "moxtest3@mox3.example")
}
