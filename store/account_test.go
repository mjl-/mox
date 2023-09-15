package store

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sconf"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

var ctxbg = context.Background()

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

func TestMailbox(t *testing.T) {
	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = "../testdata/store/mox.conf"
	mox.MustLoadConfig(true, false)
	acc, err := OpenAccount("mjl")
	tcheck(t, err, "open account")
	defer func() {
		err = acc.Close()
		tcheck(t, err, "closing account")
	}()
	defer Switchboard()()

	log := mlog.New("store")

	msgFile, err := CreateMessageTemp("account-test")
	if err != nil {
		t.Fatalf("creating temp msg file: %s", err)
	}
	defer msgFile.Close()
	msgWriter := message.NewWriter(msgFile)
	if _, err := msgWriter.Write([]byte(" message")); err != nil {
		t.Fatalf("writing to temp message: %s", err)
	}

	msgPrefix := []byte("From: <mjl@mox.example\r\nTo: <mjl@mox.example>\r\nCc: <mjl@mox.example>Subject: test\r\nMessage-Id: <m01@mox.example>\r\n\r\n")
	msgPrefixCatchall := []byte("Subject: catchall\r\n\r\n")
	m := Message{
		Received:  time.Now(),
		Size:      int64(len(msgPrefix)) + msgWriter.Size,
		MsgPrefix: msgPrefix,
	}
	msent := m
	m.ThreadMuted = true
	m.ThreadCollapsed = true
	var mbsent Mailbox
	mbrejects := Mailbox{Name: "Rejects", UIDValidity: 1, UIDNext: 1, HaveCounts: true}
	mreject := m
	mconsumed := Message{
		Received:  m.Received,
		Size:      int64(len(msgPrefixCatchall)) + msgWriter.Size,
		MsgPrefix: msgPrefixCatchall,
	}
	acc.WithWLock(func() {
		conf, _ := acc.Conf()
		err := acc.DeliverDestination(xlog, conf.Destinations["mjl"], &m, msgFile, false)
		tcheck(t, err, "deliver without consume")

		err = acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
			var err error
			mbsent, err = bstore.QueryTx[Mailbox](tx).FilterNonzero(Mailbox{Name: "Sent"}).Get()
			tcheck(t, err, "sent mailbox")
			msent.MailboxID = mbsent.ID
			msent.MailboxOrigID = mbsent.ID
			err = acc.DeliverMessage(xlog, tx, &msent, msgFile, false, true, false, false)
			tcheck(t, err, "deliver message")
			if !msent.ThreadMuted || !msent.ThreadCollapsed {
				t.Fatalf("thread muted & collapsed should have been copied from parent (duplicate message-id) m")
			}

			err = tx.Get(&mbsent)
			tcheck(t, err, "get mbsent")
			mbsent.Add(msent.MailboxCounts())
			err = tx.Update(&mbsent)
			tcheck(t, err, "update mbsent")

			err = tx.Insert(&mbrejects)
			tcheck(t, err, "insert rejects mailbox")
			mreject.MailboxID = mbrejects.ID
			mreject.MailboxOrigID = mbrejects.ID
			err = acc.DeliverMessage(xlog, tx, &mreject, msgFile, false, true, false, false)
			tcheck(t, err, "deliver message")

			err = tx.Get(&mbrejects)
			tcheck(t, err, "get mbrejects")
			mbrejects.Add(mreject.MailboxCounts())
			err = tx.Update(&mbrejects)
			tcheck(t, err, "update mbrejects")

			return nil
		})
		tcheck(t, err, "deliver as sent and rejects")

		err = acc.DeliverDestination(xlog, conf.Destinations["mjl"], &mconsumed, msgFile, true)
		tcheck(t, err, "deliver with consume")

		err = acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
			m.Junk = true
			l := []Message{m}
			err = acc.RetrainMessages(ctxbg, log, tx, l, false)
			tcheck(t, err, "train as junk")
			m = l[0]
			return nil
		})
		tcheck(t, err, "train messages")
	})

	m.Junk = false
	m.Notjunk = true
	jf, _, err := acc.OpenJunkFilter(ctxbg, log)
	tcheck(t, err, "open junk filter")
	err = acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
		return acc.RetrainMessage(ctxbg, log, tx, jf, &m, false)
	})
	tcheck(t, err, "retraining as non-junk")
	err = jf.Close()
	tcheck(t, err, "close junk filter")

	m.Notjunk = false
	err = acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
		return acc.RetrainMessages(ctxbg, log, tx, []Message{m}, false)
	})
	tcheck(t, err, "untraining non-junk")

	err = acc.SetPassword("testtest")
	tcheck(t, err, "set password")

	key0, err := acc.Subjectpass("test@localhost")
	tcheck(t, err, "subjectpass")
	key1, err := acc.Subjectpass("test@localhost")
	tcheck(t, err, "subjectpass")
	if key0 != key1 {
		t.Fatalf("different keys for same address")
	}
	key2, err := acc.Subjectpass("test2@localhost")
	tcheck(t, err, "subjectpass")
	if key2 == key0 {
		t.Fatalf("same key for different address")
	}

	acc.WithWLock(func() {
		err := acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
			_, _, err := acc.MailboxEnsure(tx, "Testbox", true)
			return err
		})
		tcheck(t, err, "ensure mailbox exists")
		err = acc.DB.Read(ctxbg, func(tx *bstore.Tx) error {
			_, _, err := acc.MailboxEnsure(tx, "Testbox", true)
			return err
		})
		tcheck(t, err, "ensure mailbox exists")

		err = acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
			_, _, err := acc.MailboxEnsure(tx, "Testbox2", false)
			tcheck(t, err, "create mailbox")

			exists, err := acc.MailboxExists(tx, "Testbox2")
			tcheck(t, err, "checking that mailbox exists")
			if !exists {
				t.Fatalf("mailbox does not exist")
			}

			exists, err = acc.MailboxExists(tx, "Testbox3")
			tcheck(t, err, "checking that mailbox does not exist")
			if exists {
				t.Fatalf("mailbox does exist")
			}

			xmb, err := acc.MailboxFind(tx, "Testbox3")
			tcheck(t, err, "finding non-existing mailbox")
			if xmb != nil {
				t.Fatalf("did find Testbox3: %v", xmb)
			}
			xmb, err = acc.MailboxFind(tx, "Testbox2")
			tcheck(t, err, "finding existing mailbox")
			if xmb == nil {
				t.Fatalf("did not find Testbox2")
			}

			changes, err := acc.SubscriptionEnsure(tx, "Testbox2")
			tcheck(t, err, "ensuring new subscription")
			if len(changes) == 0 {
				t.Fatalf("new subscription did not result in changes")
			}
			changes, err = acc.SubscriptionEnsure(tx, "Testbox2")
			tcheck(t, err, "ensuring already present subscription")
			if len(changes) != 0 {
				t.Fatalf("already present subscription resulted in changes")
			}

			return nil
		})
		tcheck(t, err, "write tx")

		// todo: check that messages are removed and changes sent.
		hasSpace, err := acc.TidyRejectsMailbox(log, "Rejects")
		tcheck(t, err, "tidy rejects mailbox")
		if !hasSpace {
			t.Fatalf("no space for more rejects")
		}

		acc.RejectsRemove(log, "Rejects", "m01@mox.example")
	})

	// Run the auth tests twice for possible cache effects.
	for i := 0; i < 2; i++ {
		_, err := OpenEmailAuth("mjl@mox.example", "bogus")
		if err != ErrUnknownCredentials {
			t.Fatalf("got %v, expected ErrUnknownCredentials", err)
		}
	}

	for i := 0; i < 2; i++ {
		acc2, err := OpenEmailAuth("mjl@mox.example", "testtest")
		tcheck(t, err, "open for email with auth")
		err = acc2.Close()
		tcheck(t, err, "close account")
	}

	acc2, err := OpenEmailAuth("other@mox.example", "testtest")
	tcheck(t, err, "open for email with auth")
	err = acc2.Close()
	tcheck(t, err, "close account")

	_, err = OpenEmailAuth("bogus@mox.example", "testtest")
	if err != ErrUnknownCredentials {
		t.Fatalf("got %v, expected ErrUnknownCredentials", err)
	}

	_, err = OpenEmailAuth("mjl@test.example", "testtest")
	if err != ErrUnknownCredentials {
		t.Fatalf("got %v, expected ErrUnknownCredentials", err)
	}
}

func TestMessageRuleset(t *testing.T) {
	f, err := os.Open("/dev/null")
	tcheck(t, err, "open")
	defer f.Close()
	msgBuf := []byte(strings.ReplaceAll(`List-ID:  <test.mox.example>

test
`, "\n", "\r\n"))

	const destConf = `
Rulesets:
	-
		HeadersRegexp:
			list-id: <test\.mox\.example>
		Mailbox: test
`
	var dest config.Destination
	err = sconf.Parse(strings.NewReader(destConf), &dest)
	tcheck(t, err, "parse config")
	// todo: should use regular config initialization functions for this.
	var hdrs [][2]*regexp.Regexp
	for k, v := range dest.Rulesets[0].HeadersRegexp {
		rk, err := regexp.Compile(k)
		tcheck(t, err, "compile key")
		rv, err := regexp.Compile(v)
		tcheck(t, err, "compile value")
		hdrs = append(hdrs, [...]*regexp.Regexp{rk, rv})
	}
	dest.Rulesets[0].HeadersRegexpCompiled = hdrs

	c := MessageRuleset(xlog, dest, &Message{}, msgBuf, f)
	if c == nil {
		t.Fatalf("expected ruleset match")
	}

	msg2Buf := []byte(strings.ReplaceAll(`From: <mjl@mox.example>

test
`, "\n", "\r\n"))
	c = MessageRuleset(xlog, dest, &Message{}, msg2Buf, f)
	if c != nil {
		t.Fatalf("expected no ruleset match")
	}

	// todo: test the SMTPMailFrom and VerifiedDomains rule.
}
