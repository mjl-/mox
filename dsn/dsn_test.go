package dsn

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
)

func xparseDomain(s string) dns.Domain {
	d, err := dns.ParseDomain(s)
	if err != nil {
		panic(fmt.Sprintf("parsing domain %q: %v", s, err))
	}
	return d
}

func xparseIPDomain(s string) dns.IPDomain {
	return dns.IPDomain{Domain: xparseDomain(s)}
}

func tparseMessage(t *testing.T, data []byte, nparts int) (*Message, *message.Part) {
	t.Helper()
	m, p, err := Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parsing dsn: %v", err)
	}
	if len(p.Parts) != nparts {
		t.Fatalf("got %d parts, expected %d", len(p.Parts), nparts)
	}
	return m, p
}

func tcheckType(t *testing.T, p *message.Part, mt, mst, cte string) {
	t.Helper()
	if !strings.EqualFold(p.MediaType, mt) {
		t.Fatalf("got mediatype %q, expected %q", p.MediaType, mt)
	}
	if !strings.EqualFold(p.MediaSubType, mst) {
		t.Fatalf("got mediasubtype %q, expected %q", p.MediaSubType, mst)
	}
	if !strings.EqualFold(p.ContentTransferEncoding, cte) {
		t.Fatalf("got content-transfer-encoding %q, expected %q", p.ContentTransferEncoding, cte)
	}
}

func tcompare(t *testing.T, got, exp any) {
	t.Helper()
	if !reflect.DeepEqual(got, exp) {
		t.Fatalf("got %#v, expected %#v", got, exp)
	}
}

func tcompareReader(t *testing.T, r io.Reader, exp []byte) {
	t.Helper()
	buf, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("data read, got %q, expected %q", buf, exp)
	}
}

func TestDSN(t *testing.T) {
	log := mlog.New("dsn")

	now := time.Now()

	// An ascii-only message.
	m := Message{
		SMTPUTF8: false,

		From:     smtp.Path{Localpart: "postmaster", IPDomain: xparseIPDomain("mox.example")},
		To:       smtp.Path{Localpart: "mjl", IPDomain: xparseIPDomain("remote.example")},
		Subject:  "dsn",
		TextBody: "delivery failure\n",

		ReportingMTA:    "mox.example",
		ReceivedFromMTA: smtp.Ehlo{Name: xparseIPDomain("relay.example"), ConnIP: net.ParseIP("10.10.10.10")},
		ArrivalDate:     now,

		Recipients: []Recipient{
			{
				FinalRecipient:  smtp.Path{Localpart: "mjl", IPDomain: xparseIPDomain("remote.example")},
				Action:          Failed,
				Status:          "5.0.0",
				LastAttemptDate: now,
			},
		},

		Original: []byte("Subject: test\r\n"),
	}
	msgbuf, err := m.Compose(log, false)
	if err != nil {
		t.Fatalf("composing dsn: %v", err)
	}
	pmsg, part := tparseMessage(t, msgbuf, 3)
	tcheckType(t, part, "multipart", "report", "")
	tcheckType(t, &part.Parts[0], "text", "plain", "7bit")
	tcheckType(t, &part.Parts[1], "message", "delivery-status", "7bit")
	tcheckType(t, &part.Parts[2], "text", "rfc822-headers", "7bit")
	tcompare(t, part.Parts[2].ContentTypeParams["charset"], "")
	tcompareReader(t, part.Parts[2].Reader(), m.Original)
	tcompare(t, pmsg.Recipients[0].FinalRecipient, m.Recipients[0].FinalRecipient)
	// todo: test more fields

	msgbufutf8, err := m.Compose(log, true)
	if err != nil {
		t.Fatalf("composing dsn with utf-8: %v", err)
	}
	pmsg, part = tparseMessage(t, msgbufutf8, 3)
	tcheckType(t, part, "multipart", "report", "")
	tcheckType(t, &part.Parts[0], "text", "plain", "7bit")
	tcheckType(t, &part.Parts[1], "message", "delivery-status", "7bit")
	tcheckType(t, &part.Parts[2], "text", "rfc822-headers", "7bit")
	tcompare(t, part.Parts[2].ContentTypeParams["charset"], "")
	tcompareReader(t, part.Parts[2].Reader(), m.Original)
	tcompare(t, pmsg.Recipients[0].FinalRecipient, m.Recipients[0].FinalRecipient)

	// Test for valid DKIM signature.
	mox.Context = context.Background()
	mox.ConfigStaticPath = "../testdata/dsn/mox.conf"
	mox.MustLoadConfig(true, false)
	msgbuf, err = m.Compose(log, false)
	if err != nil {
		t.Fatalf("composing utf-8 dsn with utf-8 support: %v", err)
	}
	resolver := &dns.MockResolver{
		TXT: map[string][]string{
			"testsel._domainkey.mox.example.": {"v=DKIM1;h=sha256;t=s;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3ZId3ys70VFspp/VMFaxMOrNjHNPg04NOE1iShih16b3Ex7hHBOgC1UvTGSmrMlbCB1OxTXkvf6jW6S4oYRnZYVNygH6zKUwYYhaSaGIg1xA/fDn+IgcTRyLoXizMUgUgpTGyxhNrwIIWv+i7jjbs3TKpP3NU4owQ/rxowmSNqg+fHIF1likSvXvljYS" + "jaFXXnWfYibW7TdDCFFpN4sB5o13+as0u4vLw6MvOi59B1tLype1LcHpi1b9PfxNtznTTdet3kL0paxIcWtKHT0LDPUos8YYmiPa5nGbUqlC7d+4YT2jQPvwGxCws1oo2Tw6nj1UaihneYGAyvEky49FBwIDAQAB"},
		},
	}
	results, err := dkim.Verify(context.Background(), resolver, false, func(*dkim.Sig) error { return nil }, bytes.NewReader(msgbuf), false)
	if err != nil {
		t.Fatalf("dkim verify: %v", err)
	}
	if len(results) != 1 || results[0].Status != dkim.StatusPass {
		t.Fatalf("dkim result not pass, %#v", results)
	}

	// An utf-8 message.
	m = Message{
		SMTPUTF8: true,

		From:     smtp.Path{Localpart: "postmæster", IPDomain: xparseIPDomain("møx.example")},
		To:       smtp.Path{Localpart: "møx", IPDomain: xparseIPDomain("remøte.example")},
		Subject:  "dsn¡",
		TextBody: "delivery failure¿\n",

		ReportingMTA:    "mox.example",
		ReceivedFromMTA: smtp.Ehlo{Name: xparseIPDomain("reläy.example"), ConnIP: net.ParseIP("10.10.10.10")},
		ArrivalDate:     now,

		Recipients: []Recipient{
			{
				Action:          Failed,
				FinalRecipient:  smtp.Path{Localpart: "møx", IPDomain: xparseIPDomain("remøte.example")},
				Status:          "5.0.0",
				LastAttemptDate: now,
			},
		},

		Original: []byte("Subject: tést\r\n"),
	}
	msgbuf, err = m.Compose(log, false)
	if err != nil {
		t.Fatalf("composing utf-8 dsn without utf-8 support: %v", err)
	}
	pmsg, part = tparseMessage(t, msgbuf, 3)
	tcheckType(t, part, "multipart", "report", "")
	tcheckType(t, &part.Parts[0], "text", "plain", "7bit")
	tcheckType(t, &part.Parts[1], "message", "delivery-status", "7bit")
	tcheckType(t, &part.Parts[2], "text", "rfc822-headers", "base64")
	tcompare(t, part.Parts[2].ContentTypeParams["charset"], "utf-8")
	tcompareReader(t, part.Parts[2].Reader(), m.Original)
	tcompare(t, pmsg.Recipients[0].FinalRecipient, m.Recipients[0].FinalRecipient)

	msgbufutf8, err = m.Compose(log, true)
	if err != nil {
		t.Fatalf("composing utf-8 dsn with utf-8 support: %v", err)
	}
	pmsg, part = tparseMessage(t, msgbufutf8, 3)
	tcheckType(t, part, "multipart", "report", "")
	tcheckType(t, &part.Parts[0], "text", "plain", "8bit")
	tcheckType(t, &part.Parts[1], "message", "global-delivery-status", "8bit")
	tcheckType(t, &part.Parts[2], "message", "global-headers", "8bit")
	tcompare(t, part.Parts[2].ContentTypeParams["charset"], "")
	tcompareReader(t, part.Parts[2].Reader(), m.Original)
	tcompare(t, pmsg.Recipients[0].FinalRecipient, m.Recipients[0].FinalRecipient)

	// Now a message without 3rd multipart.
	m.Original = nil
	msgbufutf8, err = m.Compose(log, true)
	if err != nil {
		t.Fatalf("composing utf-8 dsn with utf-8 support: %v", err)
	}
	pmsg, part = tparseMessage(t, msgbufutf8, 2)
	tcheckType(t, part, "multipart", "report", "")
	tcheckType(t, &part.Parts[0], "text", "plain", "8bit")
	tcheckType(t, &part.Parts[1], "message", "global-delivery-status", "8bit")
	tcompare(t, pmsg.Recipients[0].FinalRecipient, m.Recipients[0].FinalRecipient)
}

func TestCode(t *testing.T) {
	testCodeLine := func(line, ecode, rest string) {
		t.Helper()
		e, r := codeLine(line)
		if e != ecode || r != rest {
			t.Fatalf("codeLine %q: got %q %q, expected %q %q", line, e, r, ecode, rest)
		}
	}
	testCodeLine("4.0.0", "4.0.0", "")
	testCodeLine("4.0.0 more", "4.0.0", "more")
	testCodeLine("other", "", "other")
	testCodeLine("other more", "", "other more")

	testHasCode := func(line string, exp bool) {
		t.Helper()
		got := HasCode(line)
		if got != exp {
			t.Fatalf("HasCode %q: got %v, expected %v", line, got, exp)
		}
	}
	testHasCode("4.0.0", true)
	testHasCode("5.7.28", true)
	testHasCode("10.0.0", false) // first number must be single digit.
	testHasCode("4.1.1 more", true)
	testHasCode("other ", false)
	testHasCode("4.2.", false)
	testHasCode("4.2. ", false)
	testHasCode(" 4.2.4", false)
	testHasCode(" 4.2.4 ", false)
}
