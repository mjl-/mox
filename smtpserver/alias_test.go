package smtpserver

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
)

// Check user can submit message with message From address they are member of.
func TestAliasSubmitMsgFrom(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()

	ts.submission = true
	ts.user = "mjl@mox.example"
	ts.pass = password0

	var msg = strings.ReplaceAll(`From: <public@mox.example>
To: <public@mox.example>
Subject: test

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@mox.example"
		rcptTo := "public@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, nil)
	})

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "public@mox.example" // List address as smtp mail from.
		rcptTo := "public@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, nil)
	})

	msg = strings.ReplaceAll(`From: <private@mox.example>
To: <private@mox.example>
Subject: test

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@mox.example"
		rcptTo := "private@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7DeliveryUnauth1})
	})

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "private@mox.example" // List address as smtp mail from.
		rcptTo := "private@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7DeliveryUnauth1})
	})
}

// Non-member cannot submit as alias that allows it for members.
func TestAliasSubmitMsgFromDenied(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()

	// Trying to open account by alias should result in proper error.
	_, _, _, err := store.OpenEmail(pkglog, "public@mox.example", false)
	if err == nil || !errors.Is(err, store.ErrUnknownCredentials) {
		t.Fatalf("opening alias, got err %v, expected store.ErrUnknownCredentials", err)
	}

	acc, err := store.OpenAccount(pkglog, "☺", false)
	tcheck(t, err, "open account")
	err = acc.SetPassword(pkglog, password0)
	tcheck(t, err, "set password")
	err = acc.Close()
	tcheck(t, err, "close account")
	acc.WaitClosed()

	ts.submission = true
	ts.user = "☺@mox.example"
	ts.pass = password0

	var msg = strings.ReplaceAll(`From: <public@mox.example>
To: <public@mox.example>
Subject: test

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "☺@mox.example"
		rcptTo := "public@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), true, true, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7DeliveryUnauth1})
	})

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "public@mox.example" // List address as message from.
		rcptTo := "public@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), true, true, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7DeliveryUnauth1})
	})
}

// Non-member can deliver to public list, not to private list.
func TestAliasDeliverNonMember(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."}, // To get passed junk filter.
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	var msg = strings.ReplaceAll(`From: <other@example.org>
To: <private@mox.example>

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "other@example.org"
		rcptTo := "private@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7ExpnProhibited2})
	})

	msg = strings.ReplaceAll(`From: <private@mox.example>
To: <private@mox.example>

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "private@example.org"
		rcptTo := "private@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7ExpnProhibited2})
	})

	msg = strings.ReplaceAll(`From: <other@example.org>
To: <public@mox.example>
Subject: test

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "other@example.org"
		rcptTo := "public@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, nil)

		ts.checkCount("Inbox", 2) // Receiving for both mjl@ and móx@.
	})

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "public@example.org" // List address as message from.
		rcptTo := "public@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, nil)

		ts.checkCount("Inbox", 4) // Receiving for both mjl@ and móx@.
	})
}

// Member can deliver to private list, but still not with alias address as message
// from. Message with alias from address as message from is allowed.
func TestAliasDeliverMember(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"mox.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"mox.example."}, // To get passed junk filter.
		},
		TXT: map[string][]string{
			"mox.example.": {"v=spf1 ip4:127.0.0.10 -all"}, // To allow multiple recipients in transaction.
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	var msg = strings.ReplaceAll(`From: <mjl@mox.example>
To: <private@mox.example>

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@mox.example"
		rcptTo := []string{"private@mox.example", "móx@mox.example"}
		_, err := client.DeliverMultiple(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), true, true, false)
		// assuming there wasn't a per-recipient error
		ts.smtpErr(err, nil)

		ts.checkCount("Inbox", 1) // Receiving once. For explicit móx@ recipient, not for mjl@ due to msgfrom, and another again for móx@ due to rcpt to.
	})

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@mox.example"
		rcptTo := "private@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, nil)

		ts.checkCount("Inbox", 2) // Only receiving 1 new message compared to previous, for móx@mox.example, not mjl@.
	})

	msg = strings.ReplaceAll(`From: <private@mox.example>
To: <private@mox.example>
Subject: test

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "other@mox.example"
		rcptTo := "private@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7ExpnProhibited2})
	})

	msg = strings.ReplaceAll(`From: <public@mox.example>
To: <public@mox.example>
Subject: test

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@mox.example"
		rcptTo := "public@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, nil)
	})
}

// Message is rejected if no member accepts it.
func TestAliasDeliverReject(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"mox.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"mox.example."}, // To get passed junk filter.
		},
		TXT: map[string][]string{
			"mox.example.": {"v=spf1 ip4:127.0.0.10 -all"}, // To allow multiple recipients in transaction.
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	var msg = strings.ReplaceAll(`From: <mjl@mox.example>
To: <private@mox.example>

test email
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@mox.example"
		rcptTo := "private@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, nil)

		ts.checkCount("Inbox", 1) // Only receiving for móx@mox.example, not mjl@.
	})

	// Mark message as junk.
	ts.xops.MessageFlagsAdd(ctxbg, pkglog, ts.acc, []int64{1}, []string{"$Junk"})

	ts.run(func(client *smtpclient.Client) {
		mailFrom := "mjl@mox.example"
		rcptTo := "private@mox.example"
		err := client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0})
	})
}
