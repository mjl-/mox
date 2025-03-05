package queue

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/webhook"
)

// Test webhooks for incoming message that is not related to outgoing deliveries.
func TestHookIncoming(t *testing.T) {
	acc, cleanup := setup(t)
	defer cleanup()

	accret, err := store.OpenAccount(pkglog, "retired", false)
	tcheck(t, err, "open account for retired")
	defer func() {
		accret.Close()
		accret.WaitClosed()
	}()

	testIncoming := func(a *store.Account, expIn bool) {
		t.Helper()

		_, err := bstore.QueryDB[Hook](ctxbg, DB).Delete()
		tcheck(t, err, "clean up hooks")

		mr := bytes.NewReader([]byte(testmsg))
		now := time.Now().Round(0)
		m := store.Message{
			ID:                 123,
			RemoteIP:           "::1",
			MailFrom:           "sender@remote.example",
			MailFromLocalpart:  "sender",
			MailFromDomain:     "remote.example",
			RcptToLocalpart:    "rcpt",
			RcptToDomain:       "mox.example",
			MsgFromLocalpart:   "mjl",
			MsgFromDomain:      "mox.example",
			MsgFromOrgDomain:   "mox.example",
			EHLOValidated:      true,
			MailFromValidated:  true,
			MsgFromValidated:   true,
			EHLOValidation:     store.ValidationPass,
			MailFromValidation: store.ValidationPass,
			MsgFromValidation:  store.ValidationDMARC,
			DKIMDomains:        []string{"remote.example"},
			Received:           now,
			Size:               int64(len(testmsg)),
		}
		part, err := message.EnsurePart(pkglog.Logger, true, mr, int64(len(testmsg)))
		tcheck(t, err, "parsing message")

		err = Incoming(ctxbg, pkglog, a, "<random@localhost>", m, part, "Inbox")
		tcheck(t, err, "pass incoming message")

		hl, err := bstore.QueryDB[Hook](ctxbg, DB).List()
		tcheck(t, err, "list hooks")
		if !expIn {
			tcompare(t, len(hl), 0)
			return
		}
		tcompare(t, len(hl), 1)
		h := hl[0]
		tcompare(t, h.IsIncoming, true)
		var in webhook.Incoming
		dec := json.NewDecoder(strings.NewReader(h.Payload))
		err = dec.Decode(&in)
		tcheck(t, err, "decode incoming webhook")
		in.Meta.Received = in.Meta.Received.Local() // For TZ UTC.

		structure, err := PartStructure(pkglog, &part)
		tcheck(t, err, "part structure")

		expIncoming := webhook.Incoming{
			From:       []webhook.NameAddress{{Address: "mjl@mox.example"}},
			To:         []webhook.NameAddress{{Address: "mjl@mox.example"}},
			CC:         []webhook.NameAddress{},
			BCC:        []webhook.NameAddress{},
			ReplyTo:    []webhook.NameAddress{},
			References: []string{},
			Subject:    "test",
			Text:       "test email\n",

			Structure: structure,
			Meta: webhook.IncomingMeta{
				MsgID:               m.ID,
				MailFrom:            m.MailFrom,
				MailFromValidated:   m.MailFromValidated,
				MsgFromValidated:    m.MsgFromValidated,
				RcptTo:              "rcpt@mox.example",
				DKIMVerifiedDomains: []string{"remote.example"},
				RemoteIP:            "::1",
				Received:            m.Received,
				MailboxName:         "Inbox",
				Automated:           false,
			},
		}
		tcompare(t, in, expIncoming)
	}

	testIncoming(acc, false)
	testIncoming(accret, true)
}

// Test with fromid and various DSNs, and delivery.
func TestFromIDIncomingDelivery(t *testing.T) {
	acc, cleanup := setup(t)
	defer cleanup()

	accret, err := store.OpenAccount(pkglog, "retired", false)
	tcheck(t, err, "open account for retired")
	defer func() {
		accret.Close()
		accret.WaitClosed()
	}()

	// Account that only gets webhook calls, but no retired webhooks.
	acchook, err := store.OpenAccount(pkglog, "hook", false)
	tcheck(t, err, "open account for hook")
	defer func() {
		acchook.Close()
		acchook.WaitClosed()
	}()

	addr, err := smtp.ParseAddress("mjl@mox.example")
	tcheck(t, err, "parse address")
	path := addr.Path()

	now := time.Now().Round(0)
	m := store.Message{
		ID:                 123,
		RemoteIP:           "::1",
		MailFrom:           "sender@remote.example",
		MailFromLocalpart:  "sender",
		MailFromDomain:     "remote.example",
		RcptToLocalpart:    "rcpt",
		RcptToDomain:       "mox.example",
		MsgFromLocalpart:   "mjl",
		MsgFromDomain:      "mox.example",
		MsgFromOrgDomain:   "mox.example",
		EHLOValidated:      true,
		MailFromValidated:  true,
		MsgFromValidated:   true,
		EHLOValidation:     store.ValidationPass,
		MailFromValidation: store.ValidationPass,
		MsgFromValidation:  store.ValidationDMARC,
		DKIMDomains:        []string{"remote.example"},
		Received:           now,
		DSN:                true,
	}

	testIncoming := func(a *store.Account, rawmsg []byte, retiredFromID string, expIn bool, expOut *webhook.Outgoing) {
		t.Helper()

		_, err := bstore.QueryDB[Hook](ctxbg, DB).Delete()
		tcheck(t, err, "clean up hooks")
		_, err = bstore.QueryDB[MsgRetired](ctxbg, DB).Delete()
		tcheck(t, err, "clean up retired messages")

		qmr := MsgRetired{
			SenderAccount:      a.Name,
			SenderLocalpart:    "sender",
			SenderDomainStr:    "remote.example",
			RecipientLocalpart: "rcpt",
			RecipientDomain:    path.IPDomain,
			RecipientDomainStr: "mox.example",
			RecipientAddress:   "rcpt@mox.example",
			Success:            true,
			KeepUntil:          now.Add(time.Minute),
		}
		m.RcptToLocalpart = "mjl"
		qmr.FromID = retiredFromID
		m.Size = int64(len(rawmsg))
		m.RcptToLocalpart += smtp.Localpart("+unique")

		err = DB.Insert(ctxbg, &qmr)
		tcheck(t, err, "insert retired message to match")

		if expOut != nil {
			expOut.QueueMsgID = qmr.ID
		}

		mr := bytes.NewReader(rawmsg)
		part, err := message.EnsurePart(pkglog.Logger, true, mr, int64(len(rawmsg)))
		tcheck(t, err, "parsing message")

		err = Incoming(ctxbg, pkglog, a, "<random@localhost>", m, part, "Inbox")
		tcheck(t, err, "pass incoming message")

		hl, err := bstore.QueryDB[Hook](ctxbg, DB).List()
		tcheck(t, err, "list hooks")
		if !expIn && expOut == nil {
			tcompare(t, len(hl), 0)
			return
		}
		tcompare(t, len(hl), 1)
		h := hl[0]
		tcompare(t, h.IsIncoming, expIn)
		if expIn {
			return
		}
		var out webhook.Outgoing
		dec := json.NewDecoder(strings.NewReader(h.Payload))
		err = dec.Decode(&out)
		tcheck(t, err, "decode outgoing webhook")

		out.WebhookQueued = time.Time{}
		tcompare(t, &out, expOut)
	}

	dsncompose := func(m *dsn.Message) []byte {
		buf, err := m.Compose(pkglog, false)
		tcheck(t, err, "compose dsn")
		return buf
	}
	makedsn := func(action dsn.Action) *dsn.Message {
		return &dsn.Message{
			From:         path,
			To:           path,
			TextBody:     "explanation",
			MessageID:    "<dsnmsgid@localhost>",
			ReportingMTA: "localhost",
			Recipients: []dsn.Recipient{
				{
					FinalRecipient:     path,
					Action:             action,
					Status:             "5.0.0.",
					DiagnosticCodeSMTP: "554 5.0.0 error",
				},
			},
		}
	}

	msgfailed := dsncompose(makedsn(dsn.Failed))

	// No FromID to match against, so we get a webhook for a new incoming message.
	testIncoming(acc, msgfailed, "", false, nil)
	testIncoming(accret, msgfailed, "mismatch", true, nil)

	// DSN with multiple recipients are treated as unrecognized dsns.
	multidsn := makedsn(dsn.Delivered)
	multidsn.Recipients = append(multidsn.Recipients, multidsn.Recipients[0])
	msgmultidsn := dsncompose(multidsn)
	testIncoming(acc, msgmultidsn, "unique", false, nil)
	testIncoming(accret, msgmultidsn, "unique", false, &webhook.Outgoing{
		Event:  webhook.EventUnrecognized,
		DSN:    true,
		FromID: "unique",
	})

	msgdelayed := dsncompose(makedsn(dsn.Delayed))
	testIncoming(acc, msgdelayed, "unique", false, nil)
	testIncoming(accret, msgdelayed, "unique", false, &webhook.Outgoing{
		Event:            webhook.EventDelayed,
		DSN:              true,
		FromID:           "unique",
		SMTPCode:         554,
		SMTPEnhancedCode: "5.0.0",
	})

	msgrelayed := dsncompose(makedsn(dsn.Relayed))
	testIncoming(acc, msgrelayed, "unique", false, nil)
	testIncoming(accret, msgrelayed, "unique", false, &webhook.Outgoing{
		Event:            webhook.EventRelayed,
		DSN:              true,
		FromID:           "unique",
		SMTPCode:         554,
		SMTPEnhancedCode: "5.0.0",
	})

	msgunrecognized := dsncompose(makedsn(dsn.Action("bogus")))
	testIncoming(acc, msgunrecognized, "unique", false, nil)
	testIncoming(accret, msgunrecognized, "unique", false, &webhook.Outgoing{
		Event:  webhook.EventUnrecognized,
		DSN:    true,
		FromID: "unique",
	})

	// Not a DSN but to fromid address also causes "unrecognized".
	msgunrecognized2 := []byte(testmsg)
	testIncoming(acc, msgunrecognized2, "unique", false, nil)
	testIncoming(accret, msgunrecognized2, "unique", false, &webhook.Outgoing{
		Event:  webhook.EventUnrecognized,
		DSN:    false,
		FromID: "unique",
	})

	msgdelivered := dsncompose(makedsn(dsn.Delivered))
	testIncoming(acc, msgdelivered, "unique", false, nil)
	testIncoming(accret, msgdelivered, "unique", false, &webhook.Outgoing{
		Event:  webhook.EventDelivered,
		DSN:    true,
		FromID: "unique",
		// This is what DSN claims.
		SMTPCode:         554,
		SMTPEnhancedCode: "5.0.0",
	})

	testIncoming(acc, msgfailed, "unique", false, nil)
	testIncoming(accret, msgfailed, "unique", false, &webhook.Outgoing{
		Event:            webhook.EventFailed,
		DSN:              true,
		FromID:           "unique",
		SMTPCode:         554,
		SMTPEnhancedCode: "5.0.0",
	})

	// We still have a webhook in the queue from the test above.
	// Try to get the hook delivered. We'll try various error handling cases and superseding.

	qsize, err := HookQueueSize(ctxbg)
	tcheck(t, err, "hook queue size")
	tcompare(t, qsize, 1)

	var handler http.HandlerFunc
	handleError := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "server error")
	})
	handleOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic dXNlcm5hbWU6cGFzc3dvcmQ=" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Mox-Webhook-ID") == "" {
			http.Error(w, "missing header x-mox-webhook-id", http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Mox-Webhook-Attempt") == "" {
			http.Error(w, "missing header x-mox-webhook-attempt", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	defer hs.Close()

	h, err := bstore.QueryDB[Hook](ctxbg, DB).Get()
	tcheck(t, err, "get hook from queue")

	next := hookNextWork(ctxbg, pkglog, map[string]struct{}{"https://other.example/": {}})
	if next > 0 {
		t.Fatalf("next scheduled work should be immediate, is %v", next)
	}

	// Respond with an error and see a retry is scheduled.
	h.URL = hs.URL
	// Update hook URL in database, so we can call hookLaunchWork. We'll call
	// hookDeliver for later attempts.
	err = DB.Update(ctxbg, &h)
	tcheck(t, err, "update hook url")
	handler = handleError
	hookLaunchWork(pkglog, map[string]struct{}{"https://other.example/": {}})
	<-hookDeliveryResults
	err = DB.Get(ctxbg, &h)
	tcheck(t, err, "get hook after failed delivery attempt")
	tcompare(t, h.Attempts, 1)
	tcompare(t, len(h.Results), 1)
	tcompare(t, h.LastResult().Success, false)
	tcompare(t, h.LastResult().Code, http.StatusInternalServerError)
	tcompare(t, h.LastResult().Response, "server error\n")

	next = hookNextWork(ctxbg, pkglog, map[string]struct{}{})
	if next <= 0 {
		t.Fatalf("next scheduled work is immediate, shoud be in the future")
	}

	n, err := HookNextAttemptSet(ctxbg, HookFilter{}, time.Now().Add(time.Minute))
	tcheck(t, err, "schedule hook to now")
	tcompare(t, n, 1)
	n, err = HookNextAttemptAdd(ctxbg, HookFilter{}, -time.Minute)
	tcheck(t, err, "schedule hook to now")
	tcompare(t, n, 1)
	next = hookNextWork(ctxbg, pkglog, map[string]struct{}{})
	if next > 0 {
		t.Fatalf("next scheduled work should be immediate, is %v", next)
	}

	handler = handleOK
	hookDeliver(pkglog, h)
	<-hookDeliveryResults
	err = DB.Get(ctxbg, &h)
	tcompare(t, err, bstore.ErrAbsent)
	hr := HookRetired{ID: h.ID}
	err = DB.Get(ctxbg, &hr)
	tcheck(t, err, "get retired hook after delivery")
	tcompare(t, hr.Attempts, 2)
	tcompare(t, len(hr.Results), 2)
	tcompare(t, hr.LastResult().Success, true)
	tcompare(t, hr.LastResult().Code, http.StatusOK)
	tcompare(t, hr.LastResult().Response, "ok\n")

	// Check that cleaning up retired webhooks works.
	cleanupHookRetiredSingle(pkglog)
	hrl, err := bstore.QueryDB[HookRetired](ctxbg, DB).List()
	tcheck(t, err, "listing retired hooks")
	tcompare(t, len(hrl), 0)

	// Helper to get a representative webhook added to the queue.
	addHook := func(a *store.Account) {
		testIncoming(a, msgfailed, "unique", false, &webhook.Outgoing{
			Event:            webhook.EventFailed,
			DSN:              true,
			FromID:           "unique",
			SMTPCode:         554,
			SMTPEnhancedCode: "5.0.0",
		})
	}

	// Keep attempting and failing delivery until we give up.
	addHook(accret)
	h, err = bstore.QueryDB[Hook](ctxbg, DB).Get()
	tcheck(t, err, "get added hook")
	h.URL = hs.URL
	handler = handleError
	for i := 0; i < len(hookIntervals); i++ {
		hookDeliver(pkglog, h)
		<-hookDeliveryResults
		err := DB.Get(ctxbg, &h)
		tcheck(t, err, "get hook")
		tcompare(t, h.Attempts, i+1)
	}
	// Final attempt.
	hookDeliver(pkglog, h)
	<-hookDeliveryResults
	err = DB.Get(ctxbg, &h)
	tcompare(t, err, bstore.ErrAbsent)
	hr = HookRetired{ID: h.ID}
	err = DB.Get(ctxbg, &hr)
	tcheck(t, err, "get retired hook after failure")
	tcompare(t, hr.Attempts, len(hookIntervals)+1)
	tcompare(t, len(hr.Results), len(hookIntervals)+1)
	tcompare(t, hr.LastResult().Success, false)
	tcompare(t, hr.LastResult().Code, http.StatusInternalServerError)
	tcompare(t, hr.LastResult().Response, "server error\n")

	// Check account "hook" doesn't get retired webhooks.
	addHook(acchook)
	h, err = bstore.QueryDB[Hook](ctxbg, DB).Get()
	tcheck(t, err, "get added hook")
	handler = handleOK
	h.URL = hs.URL
	hookDeliver(pkglog, h)
	<-hookDeliveryResults
	err = DB.Get(ctxbg, &h)
	tcompare(t, err, bstore.ErrAbsent)
	hr = HookRetired{ID: h.ID}
	err = DB.Get(ctxbg, &hr)
	tcompare(t, err, bstore.ErrAbsent)

	// HookCancel
	addHook(accret)
	h, err = bstore.QueryDB[Hook](ctxbg, DB).Get()
	tcheck(t, err, "get added hook")
	n, err = HookCancel(ctxbg, pkglog, HookFilter{})
	tcheck(t, err, "canceling hook")
	tcompare(t, n, 1)
	l, err := HookList(ctxbg, HookFilter{}, HookSort{})
	tcheck(t, err, "list hook")
	tcompare(t, len(l), 0)

	// Superseding: When a webhook is scheduled for a message that already has a
	// pending webhook, the previous webhook should be removed/retired.
	_, err = bstore.QueryDB[HookRetired](ctxbg, DB).Delete()
	tcheck(t, err, "clean up retired webhooks")
	_, err = bstore.QueryDB[MsgRetired](ctxbg, DB).Delete()
	tcheck(t, err, "clean up retired messages")
	qmr := MsgRetired{
		SenderAccount:      accret.Name,
		SenderLocalpart:    "sender",
		SenderDomainStr:    "remote.example",
		RecipientLocalpart: "rcpt",
		RecipientDomain:    path.IPDomain,
		RecipientDomainStr: "mox.example",
		RecipientAddress:   "rcpt@mox.example",
		Success:            true,
		KeepUntil:          now.Add(time.Minute),
		FromID:             "unique",
	}
	err = DB.Insert(ctxbg, &qmr)
	tcheck(t, err, "insert retired message to match")
	m.RcptToLocalpart = "mjl"
	m.Size = int64(len(msgdelayed))
	m.RcptToLocalpart += smtp.Localpart("+unique")

	mr := bytes.NewReader(msgdelayed)
	part, err := message.EnsurePart(pkglog.Logger, true, mr, int64(len(msgdelayed)))
	tcheck(t, err, "parsing message")

	// Cause first webhook.
	err = Incoming(ctxbg, pkglog, accret, "<random@localhost>", m, part, "Inbox")
	tcheck(t, err, "pass incoming message")
	h, err = bstore.QueryDB[Hook](ctxbg, DB).Get()
	tcheck(t, err, "get hook")

	// Cause second webhook for same message. First should now be retired and marked as superseded.
	err = Incoming(ctxbg, pkglog, accret, "<random@localhost>", m, part, "Inbox")
	tcheck(t, err, "pass incoming message again")
	h2, err := bstore.QueryDB[Hook](ctxbg, DB).Get()
	tcheck(t, err, "get hook")
	hr, err = bstore.QueryDB[HookRetired](ctxbg, DB).Get()
	tcheck(t, err, "get retired hook")
	tcompare(t, h.ID, hr.ID)
	tcompare(t, hr.SupersededByID, h2.ID)
	tcompare(t, h2.ID > h.ID, true)
}

func TestHookListFilterSort(t *testing.T) {
	_, cleanup := setup(t)
	defer cleanup()

	now := time.Now().Round(0)
	h := Hook{0, 0, "fromid", "messageid", "subj", nil, "mjl", "http://localhost", "", false, "delivered", "", now, 0, now, []HookResult{}}
	h1 := h
	h1.Submitted = now.Add(-time.Second)
	h1.NextAttempt = now.Add(time.Minute)
	hl := []Hook{h, h, h, h, h, h1}
	err := DB.Write(ctxbg, func(tx *bstore.Tx) error {
		for i := range hl {
			err := hookInsert(tx, &hl[i], now, time.Minute)
			tcheck(t, err, "insert hook")
		}
		return nil
	})
	tcheck(t, err, "inserting hooks")
	h1 = hl[len(hl)-1]

	hlrev := slices.Clone(hl)
	slices.Reverse(hlrev)

	// Ascending by nextattempt,id.
	l, err := HookList(ctxbg, HookFilter{}, HookSort{Asc: true})
	tcheck(t, err, "list")
	tcompare(t, l, hl)

	// Descending by nextattempt,id.
	l, err = HookList(ctxbg, HookFilter{}, HookSort{})
	tcheck(t, err, "list")
	tcompare(t, l, hlrev)

	// Descending by submitted,id.
	l, err = HookList(ctxbg, HookFilter{}, HookSort{Field: "Submitted"})
	tcheck(t, err, "list")
	ll := append(append([]Hook{}, hlrev[1:]...), hl[5])
	tcompare(t, l, ll)

	// Filter by all fields to get a single.
	allfilters := HookFilter{
		Max:         2,
		IDs:         []int64{h1.ID},
		Account:     "mjl",
		Submitted:   "<1s",
		NextAttempt: ">1s",
		Event:       "delivered",
	}
	l, err = HookList(ctxbg, allfilters, HookSort{})
	tcheck(t, err, "list single")
	tcompare(t, l, []Hook{h1})

	// Paginated NextAttmpt asc.
	var lastID int64
	var last any
	l = nil
	for {
		nl, err := HookList(ctxbg, HookFilter{Max: 1}, HookSort{Asc: true, LastID: lastID, Last: last})
		tcheck(t, err, "list paginated")
		l = append(l, nl...)
		if len(nl) == 0 {
			break
		}
		tcompare(t, len(nl), 1)
		lastID, last = nl[0].ID, nl[0].NextAttempt.Format(time.RFC3339Nano)
	}
	tcompare(t, l, hl)

	// Paginated NextAttempt desc.
	l = nil
	lastID = 0
	last = ""
	for {
		nl, err := HookList(ctxbg, HookFilter{Max: 1}, HookSort{LastID: lastID, Last: last})
		tcheck(t, err, "list paginated")
		l = append(l, nl...)
		if len(nl) == 0 {
			break
		}
		tcompare(t, len(nl), 1)
		lastID, last = nl[0].ID, nl[0].NextAttempt.Format(time.RFC3339Nano)
	}
	tcompare(t, l, hlrev)

	// Paginated Submitted desc.
	l = nil
	lastID = 0
	last = ""
	for {
		nl, err := HookList(ctxbg, HookFilter{Max: 1}, HookSort{Field: "Submitted", LastID: lastID, Last: last})
		tcheck(t, err, "list paginated")
		l = append(l, nl...)
		if len(nl) == 0 {
			break
		}
		tcompare(t, len(nl), 1)
		lastID, last = nl[0].ID, nl[0].Submitted.Format(time.RFC3339Nano)
	}
	tcompare(t, l, ll)

	// Paginated Submitted asc.
	l = nil
	lastID = 0
	last = ""
	for {
		nl, err := HookList(ctxbg, HookFilter{Max: 1}, HookSort{Field: "Submitted", Asc: true, LastID: lastID, Last: last})
		tcheck(t, err, "list paginated")
		l = append(l, nl...)
		if len(nl) == 0 {
			break
		}
		tcompare(t, len(nl), 1)
		lastID, last = nl[0].ID, nl[0].Submitted.Format(time.RFC3339Nano)
	}
	llrev := slices.Clone(ll)
	slices.Reverse(llrev)
	tcompare(t, l, llrev)

	// Retire messages and do similar but more basic tests. The code is similar.
	var hrl []HookRetired
	err = DB.Write(ctxbg, func(tx *bstore.Tx) error {
		for _, h := range hl {
			hr := h.Retired(false, h.NextAttempt, time.Now().Add(time.Minute).Round(0))
			err := tx.Insert(&hr)
			tcheck(t, err, "inserting retired")
			hrl = append(hrl, hr)
		}
		return nil
	})
	tcheck(t, err, "adding retired")

	// Paginated LastActivity desc.
	var lr []HookRetired
	lastID = 0
	last = ""
	l = nil
	for {
		nl, err := HookRetiredList(ctxbg, HookRetiredFilter{Max: 1}, HookRetiredSort{LastID: lastID, Last: last})
		tcheck(t, err, "list paginated")
		lr = append(lr, nl...)
		if len(nl) == 0 {
			break
		}
		tcompare(t, len(nl), 1)
		lastID, last = nl[0].ID, nl[0].LastActivity.Format(time.RFC3339Nano)
	}
	hrlrev := slices.Clone(hrl)
	slices.Reverse(hrlrev)
	tcompare(t, lr, hrlrev)

	// Filter by all fields to get a single.
	allretiredfilters := HookRetiredFilter{
		Max:          2,
		IDs:          []int64{hrlrev[0].ID},
		Account:      "mjl",
		Submitted:    "<1s",
		LastActivity: ">1s",
		Event:        "delivered",
	}
	lr, err = HookRetiredList(ctxbg, allretiredfilters, HookRetiredSort{})
	tcheck(t, err, "list single")
	tcompare(t, lr, []HookRetired{hrlrev[0]})
}
