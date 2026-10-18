package smtpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
)

// setChatmail enables chatmail mode for the test config, and marks the mjl
// account as chatmail.
func setChatmail(t *testing.T, incomingEncryptedOnly bool) {
	t.Helper()
	mox.Conf.Dynamic.Chatmail.Enabled = true
	mox.Conf.Dynamic.Chatmail.IncomingEncryptedOnly = incomingEncryptedOnly
	acc := mox.Conf.Dynamic.Accounts["mjl"]
	acc.Chatmail = true
	mox.Conf.Dynamic.Accounts["mjl"] = acc
}

// chatmailMessage returns a chatmail testdata message, with the placeholder
// subject filled in and the given string replacements applied.
func chatmailMessage(t *testing.T, name string, repl ...string) string {
	t.Helper()
	buf, err := os.ReadFile(filepath.Join("..", "chatmail", "testdata", name))
	if err != nil {
		t.Fatalf("reading chatmail testdata %s: %v", name, err)
	}
	s := strings.ReplaceAll(string(buf), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")
	s = strings.ReplaceAll(s, "{subject}", "...")
	return strings.NewReplacer(repl...).Replace(s)
}

func TestChatmailSubmission(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()
	ts.submission = true
	ts.user = "mjl@mox.example"
	ts.pass = password0

	submit := func(t *testing.T, msg string, expErr *smtpclient.Error) {
		t.Helper()
		ts.run(func(client *smtpclient.Client) {
			err := client.Deliver(ctxbg, "mjl@mox.example", "remote@example.org", int64(len(msg)), strings.NewReader(msg), false, false, false)
			ts.smtpErr(err, expErr)
		})
	}

	// Without chatmail mode, unencrypted messages are accepted.
	submit(t, submitMessage, nil)

	// With chatmail mode and a chatmail account, unencrypted messages are rejected.
	setChatmail(t, false)
	submit(t, submitMessage, &smtpclient.Error{Permanent: true, Code: smtp.C523EncryptionNeeded, Secode: smtp.SePol7EncNeeded10})
	checkEvaluationCount(t, 0)

	// Encrypted messages are accepted.
	encrypted := chatmailMessage(t, "encrypted.eml", "one@example.org", "mjl@mox.example", "two@example.org", "remote@example.org")
	submit(t, encrypted, nil)

	// Secure-Join requests are accepted.
	secureJoin := chatmailMessage(t, "securejoin-vc.eml", "one@example.org", "mjl@mox.example", "two@example.org", "remote@example.org")
	submit(t, secureJoin, nil)

	// Autocrypt Setup Messages are accepted when sent by a user to themselves.
	asm := chatmailMessage(t, "asm.eml", "one@example.org", "mjl@mox.example", "two@example.org", "mjl@mox.example")
	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "mjl@mox.example", "mjl@mox.example", int64(len(asm)), strings.NewReader(asm), false, false, false)
		tcheck(t, err, "deliver autocrypt setup message")
	})

	// But not to another recipient.
	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "mjl@mox.example", "remote@example.org", int64(len(asm)), strings.NewReader(asm), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C523EncryptionNeeded, Secode: smtp.SePol7EncNeeded10})
	})

	// A non-chatmail account may still send unencrypted messages.
	acc := mox.Conf.Dynamic.Accounts["mjl"]
	acc.Chatmail = false
	mox.Conf.Dynamic.Accounts["mjl"] = acc
	submit(t, submitMessage, nil)

	checkEvaluationCount(t, 0)
}

func TestChatmailIncoming(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."},
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	setChatmail(t, true)

	// Unencrypted incoming messages for a chatmail account are rejected.
	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C523EncryptionNeeded, Secode: smtp.SePol7EncNeeded10})
	})

	// The same applies when delivering to an alias that expands to a chatmail
	// account.
	ts.run(func(client *smtpclient.Client) {
		msg := strings.ReplaceAll(deliverMessage, "mjl@mox.example", "public@mox.example")
		err := client.Deliver(ctxbg, "remote@example.org", "public@mox.example", int64(len(msg)), strings.NewReader(msg), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C523EncryptionNeeded, Secode: smtp.SePol7EncNeeded10})
	})

	// Encrypted incoming messages are delivered.
	ts.run(func(client *smtpclient.Client) {
		msg := chatmailMessage(t, "encrypted.eml", "one@example.org", "remote@example.org", "two@example.org", "mjl@mox.example")
		err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, true, false)
		tcheck(t, err, "deliver encrypted message")
	})

	// Secure-Join requests are delivered.
	ts.run(func(client *smtpclient.Client) {
		msg := chatmailMessage(t, "securejoin-vc.eml", "one@example.org", "remote@example.org", "two@example.org", "mjl@mox.example")
		err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, true, false)
		tcheck(t, err, "deliver secure-join message")
	})

	// Mailer-daemon reports, e.g. delivery status notifications, are delivered.
	ts.run(func(client *smtpclient.Client) {
		msg := chatmailMessage(t, "mailer-daemon.eml", "owner-ups-mib@CS.UTK.EDU", "mjl@mox.example")
		err := client.Deliver(ctxbg, "MAILER-DAEMON@example.org", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, true, false)
		tcheck(t, err, "deliver mailer-daemon message")
	})

	checkEvaluationCount(t, 0)
}

// newChatmailAutoregServer copies the smtp testdata config to a temporary
// directory, so automatic account creation can write domains.conf.
func newChatmailAutoregServer(t *testing.T, resolver dns.Resolver) *testserver {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"mox.conf", "domains.conf"} {
		buf, err := os.ReadFile(filepath.Join("..", "testdata", "smtp", name))
		if err != nil {
			t.Fatalf("reading testdata %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), buf, 0660); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	mox.ConfigDynamicPath = filepath.Join(dir, "domains.conf")
	return newTestServer(t, filepath.Join(dir, "mox.conf"), resolver)
}

func TestChatmailAutoCreate(t *testing.T) {
	ts := newChatmailAutoregServer(t, dns.MockResolver{})
	defer ts.close()
	ts.submission = true

	// Enable chatmail mode and mark the domain as chatmail.
	mox.Conf.Dynamic.Chatmail.Enabled = true
	dom := mox.Conf.Dynamic.Domains["mox.example"]
	dom.Chatmail = true
	mox.Conf.Dynamic.Domains["mox.example"] = dom

	// First login with an unknown address at a chatmail domain creates the
	// account, after which the (encrypted) message can be submitted.
	msg := chatmailMessage(t, "encrypted.eml", "one@example.org", "newuser@mox.example", "two@example.org", "remote@example.org")
	ts.user = "newuser@mox.example"
	ts.pass = "testpassword"
	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "newuser@mox.example", "remote@example.org", int64(len(msg)), strings.NewReader(msg), false, false, false)
		tcheck(t, err, "submit as new chatmail account")
	})
	if acc, ok := mox.Conf.Account("newuser"); !ok || !acc.Chatmail {
		t.Fatalf("account not created as chatmail: %#v, ok %t", acc, ok)
	}

	// Logging in with the password authenticates.
	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "newuser@mox.example", "remote@example.org", int64(len(msg)), strings.NewReader(msg), false, false, false)
		tcheck(t, err, "submit as created account")
	})

	// A wrong password for the now-existing account does not authenticate.
	ts.pass = "wrongpassword"
	ts.runx(func(err error, client *smtpclient.Client) {
		if err == nil {
			err = client.Deliver(ctxbg, "newuser@mox.example", "remote@example.org", int64(len(msg)), strings.NewReader(msg), false, false, false)
		}
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C535AuthBadCreds, Secode: smtp.SePol7AuthBadCreds8})
	})

	// With automatic registration disabled, new accounts are not created.
	mox.Conf.Dynamic.Chatmail.AutoregistrationDisabled = true
	ts.user = "third@mox.example"
	ts.pass = "testpassword"
	ts.runx(func(err error, client *smtpclient.Client) {
		if err == nil {
			err = client.Deliver(ctxbg, "third@mox.example", "remote@example.org", int64(len(msg)), strings.NewReader(msg), false, false, false)
		}
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C535AuthBadCreds, Secode: smtp.SePol7AuthBadCreds8})
	})
	if _, ok := mox.Conf.Account("third"); ok {
		t.Fatal("account created while autoregistration is disabled")
	}

	checkEvaluationCount(t, 0)
}
