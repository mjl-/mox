package store

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
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
var pkglog = mlog.New("store", nil)

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

func tcompare(t *testing.T, got, expect any) {
	t.Helper()
	if !reflect.DeepEqual(got, expect) {
		t.Fatalf("got:\n%#v\nexpected:\n%#v", got, expect)
	}
}

func TestMailbox(t *testing.T) {
	log := mlog.New("store", nil)
	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/store/mox.conf")
	mox.MustLoadConfig(true, false)
	err := Init(ctxbg)
	tcheck(t, err, "init")
	defer func() {
		err := Close()
		tcheck(t, err, "close")
	}()
	defer Switchboard()()
	acc, err := OpenAccount(log, "mjl", false)
	tcheck(t, err, "open account")
	defer func() {
		err = acc.Close()
		tcheck(t, err, "closing account")
		acc.WaitClosed()
	}()

	msgFile, err := CreateMessageTemp(log, "account-test")
	tcheck(t, err, "create temp message file")
	defer CloseRemoveTempFile(log, msgFile, "temp message file")
	msgWriter := message.NewWriter(msgFile)
	_, err = msgWriter.Write([]byte(" message"))
	tcheck(t, err, "write message")

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
	mreject := m
	mconsumed := Message{
		Received:  m.Received,
		Size:      int64(len(msgPrefixCatchall)) + msgWriter.Size,
		MsgPrefix: msgPrefixCatchall,
	}
	acc.WithWLock(func() {
		conf, _ := acc.Conf()
		err := acc.DeliverDestination(log, conf.Destinations["mjl"], &m, msgFile)
		tcheck(t, err, "deliver without consume")

		err = acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
			var err error
			mbsent, err = bstore.QueryTx[Mailbox](tx).FilterNonzero(Mailbox{Name: "Sent"}).Get()
			tcheck(t, err, "sent mailbox")
			msent.MailboxID = mbsent.ID
			msent.MailboxOrigID = mbsent.ID
			err = acc.MessageAdd(log, tx, &mbsent, &msent, msgFile, AddOpts{SkipSourceFileSync: true, SkipDirSync: true})
			tcheck(t, err, "deliver message")
			if !msent.ThreadMuted || !msent.ThreadCollapsed {
				t.Fatalf("thread muted & collapsed should have been copied from parent (duplicate message-id) m")
			}
			err = tx.Update(&mbsent)
			tcheck(t, err, "update mbsent")

			modseq, err := acc.NextModSeq(tx)
			tcheck(t, err, "get next modseq")
			mbrejects := Mailbox{Name: "Rejects", UIDValidity: 1, UIDNext: 1, ModSeq: modseq, CreateSeq: modseq, HaveCounts: true}
			err = tx.Insert(&mbrejects)
			tcheck(t, err, "insert rejects mailbox")
			mreject.MailboxID = mbrejects.ID
			mreject.MailboxOrigID = mbrejects.ID
			err = acc.MessageAdd(log, tx, &mbrejects, &mreject, msgFile, AddOpts{SkipSourceFileSync: true, SkipDirSync: true})
			tcheck(t, err, "deliver message")
			err = tx.Update(&mbrejects)
			tcheck(t, err, "update mbrejects")

			return nil
		})
		tcheck(t, err, "deliver as sent and rejects")

		err = acc.DeliverDestination(log, conf.Destinations["mjl"], &mconsumed, msgFile)
		tcheck(t, err, "deliver with consume")

		err = acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
			m.Junk = true
			l := []Message{m}
			err = acc.RetrainMessages(ctxbg, log, tx, l)
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
		return acc.RetrainMessage(ctxbg, log, tx, jf, &m)
	})
	tcheck(t, err, "retraining as non-junk")
	err = jf.Close()
	tcheck(t, err, "close junk filter")

	m.Notjunk = false
	err = acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
		return acc.RetrainMessages(ctxbg, log, tx, []Message{m})
	})
	tcheck(t, err, "untraining non-junk")

	err = acc.SetPassword(log, "testtest")
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

	var modseq ModSeq
	acc.WithWLock(func() {
		var changes []Change

		err := acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
			_, _, err := acc.MailboxEnsure(tx, "Testbox", true, SpecialUse{}, &modseq)
			return err
		})
		tcheck(t, err, "ensure mailbox exists")
		err = acc.DB.Read(ctxbg, func(tx *bstore.Tx) error {
			_, _, err := acc.MailboxEnsure(tx, "Testbox", true, SpecialUse{}, &modseq)
			return err
		})
		tcheck(t, err, "ensure mailbox exists")

		err = acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
			_, _, err := acc.MailboxEnsure(tx, "Testbox2", false, SpecialUse{}, &modseq)
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

			nchanges, err := acc.SubscriptionEnsure(tx, "Testbox2")
			tcheck(t, err, "ensuring new subscription")
			if len(nchanges) == 0 {
				t.Fatalf("new subscription did not result in changes")
			}
			changes = append(changes, nchanges...)
			nchanges, err = acc.SubscriptionEnsure(tx, "Testbox2")
			tcheck(t, err, "ensuring already present subscription")
			if len(nchanges) != 0 {
				t.Fatalf("already present subscription resulted in changes")
			}

			// todo: check that messages are removed.
			mbRej, err := bstore.QueryTx[Mailbox](tx).FilterNonzero(Mailbox{Name: "Rejects"}).Get()
			tcheck(t, err, "get rejects mailbox")
			nchanges, hasSpace, err := acc.TidyRejectsMailbox(log, tx, &mbRej)
			tcheck(t, err, "tidy rejects mailbox")
			changes = append(changes, nchanges...)
			if !hasSpace {
				t.Fatalf("no space for more rejects")
			}

			return nil
		})
		tcheck(t, err, "write tx")

		BroadcastChanges(acc, changes)

		acc.RejectsRemove(log, "Rejects", "m01@mox.example")
	})

	// Run the auth tests twice for possible cache effects.
	for range 2 {
		_, _, err := OpenEmailAuth(log, "mjl@mox.example", "bogus", false)
		if err != ErrUnknownCredentials {
			t.Fatalf("got %v, expected ErrUnknownCredentials", err)
		}
	}

	for range 2 {
		acc2, _, err := OpenEmailAuth(log, "mjl@mox.example", "testtest", false)
		tcheck(t, err, "open for email with auth")
		err = acc2.Close()
		tcheck(t, err, "close account")
	}

	acc2, _, err := OpenEmailAuth(log, "other@mox.example", "testtest", false)
	tcheck(t, err, "open for email with auth")
	err = acc2.Close()
	tcheck(t, err, "close account")

	_, _, err = OpenEmailAuth(log, "bogus@mox.example", "testtest", false)
	if err != ErrUnknownCredentials {
		t.Fatalf("got %v, expected ErrUnknownCredentials", err)
	}

	_, _, err = OpenEmailAuth(log, "mjl@test.example", "testtest", false)
	if err != ErrUnknownCredentials {
		t.Fatalf("got %v, expected ErrUnknownCredentials", err)
	}
}

func TestMessageRuleset(t *testing.T) {
	log := mlog.New("store", nil)
	f, err := CreateMessageTemp(log, "msgruleset")
	tcheck(t, err, "creating temp msg file")
	defer CloseRemoveTempFile(log, f, "temp message file")

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

	c := MessageRuleset(log, dest, &Message{}, msgBuf, f)
	if c == nil {
		t.Fatalf("expected ruleset match")
	}

	msg2Buf := []byte(strings.ReplaceAll(`From: <mjl@mox.example>

test
`, "\n", "\r\n"))
	c = MessageRuleset(log, dest, &Message{}, msg2Buf, f)
	if c != nil {
		t.Fatalf("expected no ruleset match")
	}

	// todo: test the SMTPMailFrom and VerifiedDomains rule.
}

// Check that opening an account forwards the Message.ID used for new additions if
// message files already exist in the file system.
func TestNextMessageID(t *testing.T) {
	log := mlog.New("store", nil)
	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/store/mox.conf")
	mox.MustLoadConfig(true, false)
	err := Init(ctxbg)
	tcheck(t, err, "init")
	defer func() {
		err := Close()
		tcheck(t, err, "close")
	}()
	defer Switchboard()()

	// Ensure account exists.
	acc, err := OpenAccount(log, "mjl", false)
	tcheck(t, err, "open account")
	err = acc.Close()
	tcheck(t, err, "closing account")
	acc.WaitClosed()
	acc = nil

	// Create file on disk to occupy the first Message.ID that would otherwise be used for deliveries..
	msgData := []byte("a: b\r\n\r\ntest\r\n")
	msgDir := filepath.FromSlash("../testdata/store/data/accounts/mjl/msg")
	os.MkdirAll(filepath.Join(msgDir, "a"), 0700)
	msgPath := filepath.Join(msgDir, "a", "1")
	err = os.WriteFile(msgPath, msgData, 0700)
	tcheck(t, err, "write message file")

	msgPathBogus := filepath.Join(msgDir, "a", "bogus")
	err = os.WriteFile(msgPathBogus, []byte("test"), 0700)
	tcheck(t, err, "create message file")
	msgPathBadID := filepath.Join(msgDir, "a", "10000") // Out of range.
	err = os.WriteFile(msgPathBadID, []byte("test"), 0700)
	tcheck(t, err, "create message file")

	// Open account. This should increase the next message ID.
	acc, err = OpenAccount(log, "mjl", false)
	tcheck(t, err, "open account")

	// Deliver a message. It should get ID 2.
	mf, err := CreateMessageTemp(log, "account-test")
	tcheck(t, err, "creating temp message file")
	_, err = mf.Write(msgData)
	tcheck(t, err, "write file")
	defer CloseRemoveTempFile(log, mf, "temp message file")
	m := Message{
		Size: int64(len(msgData)),
	}
	err = acc.DeliverMailbox(log, "Inbox", &m, mf)
	tcheck(t, err, "deliver mailbox")
	if m.ID != 2 {
		t.Fatalf("got message id %d, expected 2", m.ID)
	}

	// Ensure account consistency check won't complain.
	err = os.Remove(msgPath)
	tcheck(t, err, "removing message path")
	err = os.Remove(msgPathBogus)
	tcheck(t, err, "removing message path")
	err = os.Remove(msgPathBadID)
	tcheck(t, err, "removing message path")

	err = acc.Close()
	tcheck(t, err, "closing account")
	acc.WaitClosed()

	// Try again, but also create next message directory, but no file.
	os.MkdirAll(filepath.Join(msgDir, "b"), 0700)
	os.MkdirAll(filepath.Join(msgDir, "d"), 0700) // Not used.

	// Open account again, increasing next message ID.
	acc, err = OpenAccount(log, "mjl", false)
	tcheck(t, err, "open account")

	// Deliver a message. It should get ID 8*1024+1.
	mf, err = CreateMessageTemp(log, "account-test")
	tcheck(t, err, "creating temp message file")
	_, err = mf.Write(msgData)
	tcheck(t, err, "write file")
	defer CloseRemoveTempFile(log, mf, "temp message file")
	m = Message{
		Size: int64(len(msgData)),
	}
	err = acc.DeliverMailbox(log, "Inbox", &m, mf)
	tcheck(t, err, "deliver mailbox")
	if m.ID != 8*1024+1 {
		t.Fatalf("got message id %d, expected 8*1024+1", m.ID)
	}

	err = acc.Close()
	tcheck(t, err, "closing account")
	acc.WaitClosed()
}

func TestRemove(t *testing.T) {
	log := mlog.New("store", nil)
	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/store/mox.conf")
	mox.MustLoadConfig(true, false)
	err := Init(ctxbg)
	tcheck(t, err, "init")
	defer func() {
		err := Close()
		tcheck(t, err, "close")
	}()
	defer Switchboard()()

	// Note: we are not removing the account from the config file. Nothing currently
	// has a problem with that.

	// Ensure account exists.
	acc, err := OpenAccount(log, "mjl", false)
	tcheck(t, err, "open account")

	// Mark account removed. It will only be removed when we close the account.
	err = acc.Remove(context.Background())
	tcheck(t, err, "remove account")

	p := filepath.Join(mox.DataDirPath("accounts"), "mjl")
	_, err = os.Stat(p)
	tcheck(t, err, "stat account dir")

	err = acc.Close()
	tcheck(t, err, "closing account")
	acc.WaitClosed()
	acc = nil

	if _, err := os.Stat(p); err == nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf(`got stat err %v for account directory, expected "does not exist"`, err)
	}

	// Recreate files and directories. We will reinitialize store/ without closing our
	// account reference. This will apply the account removal. We only drop our (now
	// broken) account reference when done.
	acc, err = OpenAccount(log, "mjl", false)
	tcheck(t, err, "open account")
	defer func() {
		acc.Close() // Ignore errors.
		acc.WaitClosed()
		CheckConsistencyOnClose = true
	}()

	// Init below will remove the directory, we are no longer consistent.
	CheckConsistencyOnClose = false

	err = acc.Remove(context.Background())
	tcheck(t, err, "remove account")

	_, err = os.Stat(p)
	tcheck(t, err, "stat account dir")

	err = Close()
	tcheck(t, err, "close store")
	err = Init(ctxbg)
	tcheck(t, err, "init store")
	if _, err := os.Stat(p); err == nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf(`got stat err %v for account directory, expected "does not exist"`, err)
	}
	exists, err := bstore.QueryDB[AccountRemove](ctxbg, AuthDB).Exists()
	tcheck(t, err, "checking for account removals")
	tcompare(t, exists, false)
}
