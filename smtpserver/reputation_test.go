package smtpserver

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

func TestReputation(t *testing.T) {
	boolptr := func(v bool) *bool {
		return &v
	}
	xtrue := boolptr(true)
	xfalse := boolptr(false)

	now := time.Now()
	var uidgen store.UID

	message := func(junk bool, ageDays int, ehlo, mailfrom, msgfrom, rcptto string, msgfromvalidation store.Validation, dkimDomains []string, mailfromValid, ehloValid bool, ip string) store.Message {

		mailFromValidation := store.ValidationNone
		if mailfromValid {
			mailFromValidation = store.ValidationPass
		}
		ehloValidation := store.ValidationNone
		if ehloValid {
			ehloValidation = store.ValidationPass
		}

		msgFrom, err := smtp.ParseAddress(msgfrom)
		if err != nil {
			panic(fmt.Errorf("parsing msgfrom %q: %w", msgfrom, err))
		}

		rcptTo, err := smtp.ParseAddress(rcptto)
		if err != nil {
			panic(fmt.Errorf("parsing rcptto %q: %w", rcptto, err))
		}

		mailFrom := msgFrom
		if mailfrom != "" {
			mailFrom, err = smtp.ParseAddress(mailfrom)
			if err != nil {
				panic(fmt.Errorf("parsing mailfrom %q: %w", mailfrom, err))
			}
		}

		ipmasked1, ipmasked2, ipmasked3 := ipmasked(net.ParseIP(ip))

		uidgen++
		m := store.Message{
			UID:             uidgen, // Not relevant here.
			MailboxID:       1,
			MailboxOrigID:   1,
			Received:        now.Add(time.Duration(-ageDays) * 24 * time.Hour),
			RemoteIP:        ip,
			RemoteIPMasked1: ipmasked1,
			RemoteIPMasked2: ipmasked2,
			RemoteIPMasked3: ipmasked3,

			EHLODomain:        ehlo,
			MailFrom:          mailfrom,
			MailFromLocalpart: mailFrom.Localpart,
			MailFromDomain:    mailFrom.Domain.Name(),
			RcptToLocalpart:   rcptTo.Localpart,
			RcptToDomain:      rcptTo.Domain.Name(),

			MsgFromLocalpart: msgFrom.Localpart,
			MsgFromDomain:    msgFrom.Domain.Name(),
			MsgFromOrgDomain: publicsuffix.Lookup(ctxbg, msgFrom.Domain).Name(),

			MailFromValidated: mailfromValid,
			EHLOValidated:     ehloValid,
			MsgFromValidated:  msgfromvalidation == store.ValidationStrict || msgfromvalidation == store.ValidationRelaxed || msgfromvalidation == store.ValidationDMARC,

			MailFromValidation: mailFromValidation,
			EHLOValidation:     ehloValidation,
			MsgFromValidation:  msgfromvalidation,

			DKIMDomains: dkimDomains,

			Flags: store.Flags{
				Junk:    junk,
				Notjunk: !junk,
			},
		}
		return m
	}

	check := func(m store.Message, history []store.Message, expJunk *bool, expConclusive bool, expMethod reputationMethod) {
		t.Helper()

		p := "../testdata/smtpserver-reputation.db"
		defer os.Remove(p)

		db, err := bstore.Open(ctxbg, p, &bstore.Options{Timeout: 5 * time.Second}, store.DBTypes...)
		tcheck(t, err, "open db")
		defer db.Close()

		err = db.Write(ctxbg, func(tx *bstore.Tx) error {
			inbox := store.Mailbox{ID: 1, Name: "Inbox", HaveCounts: true}
			err = tx.Insert(&inbox)
			tcheck(t, err, "insert into db")

			for _, hm := range history {
				err := tx.Insert(&hm)
				tcheck(t, err, "insert message")
				inbox.Add(hm.MailboxCounts())

				rcptToDomain, err := dns.ParseDomain(hm.RcptToDomain)
				tcheck(t, err, "parse rcptToDomain")
				rcptToOrgDomain := publicsuffix.Lookup(ctxbg, rcptToDomain)
				r := store.Recipient{MessageID: hm.ID, Localpart: hm.RcptToLocalpart, Domain: hm.RcptToDomain, OrgDomain: rcptToOrgDomain.Name(), Sent: hm.Received}
				err = tx.Insert(&r)
				tcheck(t, err, "insert recipient")
			}
			err = tx.Update(&inbox)
			tcheck(t, err, "update mailbox counts")

			return nil
		})
		tcheck(t, err, "commit")

		var isjunk *bool
		var conclusive bool
		var method reputationMethod
		err = db.Read(ctxbg, func(tx *bstore.Tx) error {
			var err error
			isjunk, conclusive, method, err = reputation(tx, xlog, &m)
			return err
		})
		tcheck(t, err, "read tx")

		if method != expMethod {
			t.Fatalf("got method %q, expected %q", method, expMethod)
		}
		if conclusive != expConclusive {
			t.Fatalf("got conclusive %v, expected %v", conclusive, expConclusive)
		}
		if (isjunk == nil) != (expJunk == nil) || (isjunk != nil && expJunk != nil && *isjunk != *expJunk) {
			t.Fatalf("got isjunk %v, expected %v", isjunk, expJunk)
		}
	}

	var msgs []store.Message
	var m store.Message

	msgs = []store.Message{
		message(false, 4, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationDMARC, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 3, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 2, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"), // causes accept
		message(true, 1, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationRelaxed, []string{"othersite.example"}, true, true, "10.0.0.1"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationDMARC, []string{"othersite.example"}, true, true, "10.0.0.1")
	check(m, msgs, xfalse, true, methodMsgfromFull)

	// Two most recents are spam, reject.
	msgs = []store.Message{
		message(false, 3, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 2, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 1, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationDMARC, []string{"othersite.example"}, true, true, "10.0.0.1"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, true, methodMsgfromFull)

	// If localpart matches, other localsparts are not used.
	msgs = []store.Message{
		message(true, 3, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 2, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationRelaxed, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 1, "host.othersite.example", "", "b@remote.example", "mjl@local.example", store.ValidationDMARC, []string{"othersite.example"}, true, true, "10.0.0.1"), // other localpart, ignored
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationRelaxed, []string{"othersite.example"}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, true, methodMsgfromFull)

	// Incoming message, we have only seen other unverified msgs from sender.
	msgs = []store.Message{
		message(true, 3, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationNone, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 2, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationNone, []string{"othersite.example"}, true, true, "10.0.0.1"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationNone, []string{"othersite.example"}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, false, methodMsgfromFull)

	// Incoming message, we have only seen verified msgs from sender, and at least two, so this is a likely but inconclusive spam.
	msgs = []store.Message{
		message(false, 3, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.1"),
		message(false, 2, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.1"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationNone, []string{}, false, false, "10.10.0.1")
	check(m, msgs, xtrue, false, methodMsgfromFull)

	// Incoming message, we have only seen 1 verified message from sender, so inconclusive for reject.
	msgs = []store.Message{
		message(false, 2, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.1"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationNone, []string{}, false, false, "10.10.0.1")
	check(m, msgs, xtrue, false, methodMsgfromFull)

	// Incoming message, we have only seen 1 verified message from sender, and it was spam, so we can safely reject.
	msgs = []store.Message{
		message(true, 2, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.1"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationNone, []string{}, false, false, "10.10.0.1")
	check(m, msgs, xtrue, true, methodMsgfromFull)

	// We received spam from other senders in the domain, but we sent to msgfrom.
	msgs = []store.Message{
		message(true, 3, "host.othersite.example", "", "a@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.1"), // other localpart
		message(false, 2, "host.local.example", "", "mjl@local.example", "other@remote.example", store.ValidationNone, []string{}, false, false, "127.0.0.1"),               // we sent to remote, accept
		message(true, 1, "host.othersite.example", "", "a@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.1"), // other localpart
		message(true, 1, "host.othersite.example", "", "a@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.1"), // other localpart
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationNone, []string{}, false, false, "10.10.0.1")
	check(m, msgs, xfalse, true, methodMsgtoFull)

	// Other messages in same domain, inconclusive.
	msgs = []store.Message{
		message(true, 7*30, "host.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 3*30, "host.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 3*30, "host.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 3*30, "host.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 3*30, "host.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 8, "host.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 8, "host.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 4, "host.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 2, "host.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 1, "host.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1")
	check(m, msgs, nil, false, methodMsgfromDomain)

	// Mostly ham, so we'll allow it.
	msgs = []store.Message{
		message(false, 7*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 3*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 3*30, "host2.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite3.example"}, true, true, "10.0.0.2"),
		message(false, 3*30, "host2.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite2.example"}, true, true, "10.0.0.2"),
		message(false, 3*30, "host3.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.100"),
		message(false, 8, "host3.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite2.example"}, true, true, "10.0.0.100"),
		message(false, 8, "host4.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite2.example"}, true, true, "10.0.0.4"),
		message(false, 4, "host4.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.4"),
		message(false, 2, "host5.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.10.0.5"),
		message(true, 1, "host5.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"none.example"}, true, true, "10.10.0.5"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example", "othersite3.example"}, true, true, "10.0.0.1")
	check(m, msgs, xfalse, true, methodMsgfromDomain)

	// Not clearly spam, so inconclusive.
	msgs = []store.Message{
		message(true, 3*30, "host3.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.100"),
		message(true, 4, "host4.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.4"),
		message(true, 2, "host5.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.10.0.5"),
		message(false, 1, "host5.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"none.example"}, true, true, "10.10.0.5"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example", "othersite3.example"}, true, true, "10.0.0.1")
	check(m, msgs, nil, false, methodMsgfromDomain)

	// We only received spam from this domain by at least 3 localparts: reject.
	msgs = []store.Message{
		message(true, 3*30, "host3.othersite.example", "", "a@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.100"),
		message(true, 4, "host4.othersite.example", "", "b@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.4"),
		message(true, 2, "host5.othersite.example", "", "c@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.10.0.5"),
		message(true, 1, "host5.othersite.example", "", "c@remote.example", "mjl@local.example", store.ValidationStrict, []string{"none.example"}, true, true, "10.10.0.5"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example", "othersite3.example"}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, true, methodMsgfromDomain)

	// We only received spam from this org domain by at least 3 localparts. so reject.
	msgs = []store.Message{
		message(true, 3*30, "host3.othersite.example", "", "a@a.remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.100"),
		message(true, 4, "host4.othersite.example", "", "b@b.remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.4"),
		message(true, 2, "host5.othersite.example", "", "c@c.remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.10.0.5"),
		message(true, 1, "host5.othersite.example", "", "c@c.remote.example", "mjl@local.example", store.ValidationStrict, []string{"none.example"}, true, true, "10.10.0.5"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@d.remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example", "othersite3.example"}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, true, methodMsgfromOrgDomain)

	// We've only seen spam, but we don"t want to reject an entire domain with only 2 froms, so inconclusive.
	msgs = []store.Message{
		message(true, 2*30, "host3.othersite.example", "", "a@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.100"),
		message(true, 4, "host4.othersite.example", "", "a@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.4"),
		message(true, 2, "host5.othersite.example", "", "b@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.10.0.5"),
		message(true, 1, "host5.othersite.example", "", "b@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.10.0.5"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, false, methodMsgfromDomain)

	// we"ve only seen spam, but we don"t want to reject an entire orgdomain with only 2 froms, so inconclusive.
	msgs = []store.Message{
		message(true, 2*30, "host3.othersite.example", "", "a@a.remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.100"),
		message(true, 4, "host4.othersite.example", "", "a@a.remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.4"),
		message(true, 2, "host5.othersite.example", "", "b@b.remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.10.0.5"),
		message(true, 1, "host5.othersite.example", "", "b@b.remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.10.0.5"),
	}
	m = message(false, 0, "host.othersite.example", "", "other@remote.example", "mjl@local.example", store.ValidationStrict, []string{"remote.example"}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, false, methodMsgfromOrgDomain)

	// All dkim/spf signs are good, so accept.
	msgs = []store.Message{
		message(false, 2*30, "host3.esp.example", "bulk@esp.example", "a@espcustomer1.example", "mjl@local.example", store.ValidationNone, []string{"esp.example"}, true, true, "10.0.0.100"),
		message(false, 4, "host4.esp.example", "bulk@esp.example", "b@espcustomer2.example", "mjl@local.example", store.ValidationNone, []string{"esp.example"}, true, true, "10.0.0.4"),
		message(false, 2, "host5.esp.example", "bulk@esp.example", "c@espcustomer2.example", "mjl@local.example", store.ValidationNone, []string{"esp.example"}, true, true, "10.10.0.5"),
		message(false, 1, "host5.esp.example", "bulk@esp.example", "d@espcustomer2.example", "mjl@local.example", store.ValidationNone, []string{"espcustomer2.example", "esp.example"}, true, true, "10.10.0.5"),
	}
	m = message(false, 0, "host3.esp.example", "bulk@esp.example", "other@espcustomer3.example", "mjl@local.example", store.ValidationNone, []string{"espcustomer3.example", "esp.example"}, true, true, "10.0.0.1")
	check(m, msgs, xfalse, true, "dkimspf")

	// All dkim/spf signs are bad, so reject.
	msgs = []store.Message{
		message(true, 2*30, "host3.esp.example", "bulk@esp.example", "a@espcustomer1.example", "mjl@local.example", store.ValidationNone, []string{"esp.example"}, true, true, "10.0.0.100"),
		message(true, 4, "host4.esp.example", "bulk@esp.example", "b@espcustomer2.example", "mjl@local.example", store.ValidationNone, []string{"esp.example"}, true, true, "10.0.0.4"),
		message(true, 2, "host5.esp.example", "bulk@esp.example", "c@espcustomer2.example", "mjl@local.example", store.ValidationNone, []string{"esp.example"}, true, true, "10.10.0.5"),
		message(true, 1, "host5.esp.example", "bulk@esp.example", "d@espcustomer2.example", "mjl@local.example", store.ValidationNone, []string{"espcustomer2.example", "esp.example"}, true, true, "10.10.0.5"),
	}
	m = message(false, 0, "host3.esp.example", "bulk@esp.example", "other@espcustomer3.example", "mjl@local.example", store.ValidationNone, []string{"espcustomer3.example", "esp.example"}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, true, "dkimspf")

	// Mixed dkim/spf signals, inconclusive.
	msgs = []store.Message{
		message(false, 2*30, "host3.esp.example", "bulk@esp.example", "a@espcustomer1.example", "mjl@local.example", store.ValidationNone, []string{"esp.example"}, true, true, "10.0.0.100"),
		message(false, 4, "host4.esp.example", "bulk@esp.example", "b@espcustomer2.example", "mjl@local.example", store.ValidationNone, []string{"esp.example"}, true, true, "10.0.0.4"),
		message(true, 2, "host5.esp.example", "bulk@esp.example", "c@espcustomer2.example", "mjl@local.example", store.ValidationNone, []string{"esp.example"}, true, true, "10.10.0.5"),
		message(true, 1, "host5.esp.example", "bulk@esp.example", "d@espcustomer2.example", "mjl@local.example", store.ValidationNone, []string{"espcustomer2.example", "esp.example"}, true, true, "10.10.0.5"),
	}
	m = message(false, 0, "host3.esp.example", "bulk@esp.example", "other@espcustomer3.example", "mjl@local.example", store.ValidationNone, []string{"espcustomer3.example", "esp.example"}, true, true, "10.0.0.1")
	check(m, msgs, nil, false, "dkimspf")

	// Just one dkim/spf message, enough for accept.
	msgs = []store.Message{
		message(false, 4, "host4.esp.example", "bulk@esp.example", "b@espcustomer2.example", "mjl@local.example", store.ValidationNone, []string{"esp.example"}, true, true, "10.0.0.4"),
	}
	m = message(false, 0, "host3.esp.example", "bulk@esp.example", "other@espcustomer3.example", "mjl@local.example", store.ValidationNone, []string{"espcustomer3.example", "esp.example"}, true, true, "10.0.0.1")
	check(m, msgs, xfalse, true, "dkimspf")

	// Just one dkim/spf message, not enough for reject.
	msgs = []store.Message{
		message(true, 4, "host4.esp.example", "bulk@esp.example", "b@espcustomer2.example", "mjl@local.example", store.ValidationNone, []string{"esp.example"}, true, true, "10.0.0.4"),
	}
	m = message(false, 0, "host3.esp.example", "bulk@esp.example", "other@espcustomer3.example", "mjl@local.example", store.ValidationNone, []string{"espcustomer3.example", "esp.example"}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, false, "dkimspf")

	// The exact IP is almost bad, but we need 3 msgs. Other IPs don't matter.
	msgs = []store.Message{
		message(false, 7*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"), // too old
		message(true, 4*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 2*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 1*30, "host2.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite3.example"}, true, true, "10.0.0.2"), // irrelevant
	}
	m = message(false, 0, "host.different.example", "sender@different.example", "other@other.example", "mjl@local.example", store.ValidationStrict, []string{}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, false, "ip1")

	// The exact IP is almost ok, so accept.
	msgs = []store.Message{
		message(true, 7*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"), // too old
		message(false, 2*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 2*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 2*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(false, 1*30, "host2.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite3.example"}, true, true, "10.0.0.2"), // irrelevant
	}
	m = message(false, 0, "host.different.example", "sender@different.example", "other@other.example", "mjl@local.example", store.ValidationStrict, []string{}, true, true, "10.0.0.1")
	check(m, msgs, xfalse, true, "ip1")

	// The exact IP is bad, with enough msgs. Other IPs don't matter.
	msgs = []store.Message{
		message(true, 4*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"), // too old
		message(true, 2*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 2*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 1*30, "host1.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.1"),
		message(true, 1*30, "host2.othersite.example", "", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite3.example"}, true, true, "10.0.0.2"), // irrelevant
	}
	m = message(false, 0, "host.different.example", "sender@different.example", "other@other.example", "mjl@local.example", store.ValidationStrict, []string{}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, true, "ip1")

	// No exact ip match, nearby IPs (we need 5) are all bad, so reject.
	msgs = []store.Message{
		message(true, 2*30, "host2.othersite.example", "sender3@othersite3.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite3.example"}, true, true, "10.0.0.2"),
		message(true, 2*30, "host2.othersite.example", "sender@othersite2.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite2.example"}, true, true, "10.0.0.2"),
		message(false, 2*30, "host3.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.100"), // other ip
		message(false, 8, "host3.othersite.example", "sender@othersite2.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite2.example"}, true, true, "10.0.0.100"),  // other ip
		message(true, 8, "host4.othersite.example", "sender@othersite2.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite2.example"}, true, true, "10.0.0.4"),
		message(true, 4, "host4.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.4"),
		message(true, 2, "host4.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.4"),
		message(false, 2, "host5.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.10.0.5"), // other ip
		message(false, 1, "host5.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"none.example"}, true, true, "10.10.0.5"),      // other ip
	}
	m = message(false, 0, "host.different.example", "sender@different.example", "other@other.example", "mjl@local.example", store.ValidationStrict, []string{}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, true, "ip2")

	// IPs further away are bad (we need 10), reject.
	msgs = []store.Message{
		message(true, 2*30, "host2.othersite.example", "sender3@othersite3.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite3.example"}, true, true, "10.0.0.100"),
		message(true, 2*30, "host2.othersite.example", "sender@othersite2.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite2.example"}, true, true, "10.0.0.100"),
		message(true, 2*30, "host2.othersite.example", "sender@othersite2.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite2.example"}, true, true, "10.0.0.100"),
		message(true, 2*30, "host3.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.100"),
		message(true, 8, "host3.othersite.example", "sender@othersite2.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite2.example"}, true, true, "10.0.0.100"),
		message(true, 8, "host4.othersite.example", "sender@othersite2.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite2.example"}, true, true, "10.0.0.100"),
		message(true, 4, "host4.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.100"),
		message(true, 4, "host4.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.100"),
		message(true, 4, "host4.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.100"),
		message(true, 4, "host4.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.0.0.100"),
		message(false, 2, "host5.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"othersite.example"}, true, true, "10.10.0.5"),
		message(false, 1, "host5.othersite.example", "sender@othersite.example", "second@remote.example", "mjl@local.example", store.ValidationStrict, []string{"none.example"}, true, true, "10.10.0.5"),
	}
	m = message(false, 0, "host.different.example", "sender@different.example", "other@other.example", "mjl@local.example", store.ValidationStrict, []string{}, true, true, "10.0.0.1")
	check(m, msgs, xtrue, true, "ip3")
}
