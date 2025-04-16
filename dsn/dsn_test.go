package dsn

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
)

var pkglog = mlog.New("dsn", nil)

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
	m, p, err := Parse(pkglog.Logger, bytes.NewReader(data))
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
	if !(cte == "" && p.ContentTransferEncoding == nil || cte != "" && p.ContentTransferEncoding != nil && strings.EqualFold(cte, *p.ContentTransferEncoding)) {
		t.Fatalf("got content-transfer-encoding %v, expected %v", p.ContentTransferEncoding, cte)
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
	log := mlog.New("dsn", nil)

	now := time.Now()

	// An ascii-only message.
	m := Message{
		SMTPUTF8: false,

		From:      smtp.Path{Localpart: "postmaster", IPDomain: xparseIPDomain("mox.example")},
		To:        smtp.Path{Localpart: "mjl", IPDomain: xparseIPDomain("remote.example")},
		Subject:   "dsn",
		MessageID: "test@localhost",
		TextBody:  "delivery failure\n",

		ReportingMTA:         "mox.example",
		ReceivedFromMTA:      smtp.Ehlo{Name: xparseIPDomain("relay.example"), ConnIP: net.ParseIP("10.10.10.10")},
		ArrivalDate:          now,
		FutureReleaseRequest: "for;123",

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

	// An utf-8 message.
	m = Message{
		SMTPUTF8: true,

		From:      smtp.Path{Localpart: "postmæster", IPDomain: xparseIPDomain("møx.example")},
		To:        smtp.Path{Localpart: "møx", IPDomain: xparseIPDomain("remøte.example")},
		Subject:   "dsn¡",
		MessageID: "test@localhost",
		TextBody:  "delivery failure¿\n",

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
