package webmail

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"golang.org/x/exp/slices"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sherpa"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/store"
)

func tneedErrorCode(t *testing.T, code string, fn func()) {
	t.Helper()
	defer func() {
		t.Helper()
		x := recover()
		if x == nil {
			debug.PrintStack()
			t.Fatalf("expected sherpa user error, saw success")
		}
		if err, ok := x.(*sherpa.Error); !ok {
			debug.PrintStack()
			t.Fatalf("expected sherpa error, saw %#v", x)
		} else if err.Code != code {
			debug.PrintStack()
			t.Fatalf("expected sherpa error code %q, saw other sherpa error %#v", code, err)
		}
	}()

	fn()
}

func tneedError(t *testing.T, fn func()) {
	tneedErrorCode(t, "user:error", fn)
}

// Test API calls.
// todo: test that the actions make the changes they claim to make. we currently just call the functions and have only limited checks that state changed.
func TestAPI(t *testing.T) {
	mox.LimitersInit()
	os.RemoveAll("../testdata/webmail/data")
	mox.Context = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/webmail/mox.conf")
	mox.MustLoadConfig(true, false)
	defer store.Switchboard()()

	log := mlog.New("webmail", nil)
	acc, err := store.OpenAccount(log, "mjl")
	tcheck(t, err, "open account")
	err = acc.SetPassword(log, "test1234")
	tcheck(t, err, "set password")
	defer func() {
		err := acc.Close()
		pkglog.Check(err, "closing account")
	}()

	var zerom store.Message
	var (
		inboxMinimal     = &testmsg{"Inbox", store.Flags{}, nil, msgMinimal, zerom, 0}
		inboxText        = &testmsg{"Inbox", store.Flags{}, nil, msgText, zerom, 0}
		inboxHTML        = &testmsg{"Inbox", store.Flags{}, nil, msgHTML, zerom, 0}
		inboxAlt         = &testmsg{"Inbox", store.Flags{}, nil, msgAlt, zerom, 0}
		inboxAltRel      = &testmsg{"Inbox", store.Flags{}, nil, msgAltRel, zerom, 0}
		inboxAttachments = &testmsg{"Inbox", store.Flags{}, nil, msgAttachments, zerom, 0}
		testbox1Alt      = &testmsg{"Testbox1", store.Flags{}, nil, msgAlt, zerom, 0}
		rejectsMinimal   = &testmsg{"Rejects", store.Flags{Junk: true}, nil, msgMinimal, zerom, 0}
	)
	var testmsgs = []*testmsg{inboxMinimal, inboxText, inboxHTML, inboxAlt, inboxAltRel, inboxAttachments, testbox1Alt, rejectsMinimal}

	for _, tm := range testmsgs {
		tdeliver(t, acc, tm)
	}

	api := Webmail{maxMessageSize: 1024 * 1024, cookiePath: "/webmail/"}

	// Test login, and rate limiter.
	loginReqInfo := requestInfo{"mjl@mox.example", "mjl", "", httptest.NewRecorder(), &http.Request{RemoteAddr: "1.1.1.1:1234"}}
	loginctx := context.WithValue(ctxbg, requestInfoCtxKey, loginReqInfo)

	// Missing login token.
	tneedErrorCode(t, "user:error", func() { api.Login(loginctx, "", "mjl@mox.example", "test1234") })

	// Login with loginToken.
	loginCookie := &http.Cookie{Name: "webmaillogin"}
	loginCookie.Value = api.LoginPrep(loginctx)
	loginReqInfo.Request.Header = http.Header{"Cookie": []string{loginCookie.String()}}

	testLogin := func(username, password string, expErrCodes ...string) {
		t.Helper()

		defer func() {
			x := recover()
			expErr := len(expErrCodes) > 0
			if (x != nil) != expErr {
				t.Fatalf("got %v, expected codes %v", x, expErrCodes)
			}
			if x == nil {
				return
			} else if err, ok := x.(*sherpa.Error); !ok {
				t.Fatalf("got %#v, expected at most *sherpa.Error", x)
			} else if !slices.Contains(expErrCodes, err.Code) {
				t.Fatalf("got error code %q, expected %v", err.Code, expErrCodes)
			}
		}()

		api.Login(loginctx, loginCookie.Value, username, password)
	}
	testLogin("mjl@mox.example", "test1234")
	testLogin("mjl@mox.example", "bad", "user:loginFailed")
	testLogin("nouser@mox.example", "test1234", "user:loginFailed")
	testLogin("nouser@bad.example", "test1234", "user:loginFailed")
	for i := 3; i < 10; i++ {
		testLogin("bad@bad.example", "test1234", "user:loginFailed")
	}
	// Ensure rate limiter is triggered, also for slow tests.
	for i := 0; i < 10; i++ {
		testLogin("bad@bad.example", "test1234", "user:loginFailed", "user:error")
	}
	testLogin("bad@bad.example", "test1234", "user:error")

	// Context with different IP, for clear rate limit history.
	reqInfo := requestInfo{"mjl@mox.example", "mjl", "", nil, &http.Request{RemoteAddr: "127.0.0.1:1234"}}
	ctx := context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)

	// FlagsAdd
	api.FlagsAdd(ctx, []int64{inboxText.ID}, []string{`\seen`, `customlabel`})
	api.FlagsAdd(ctx, []int64{inboxText.ID, inboxHTML.ID}, []string{`\seen`, `customlabel`})
	api.FlagsAdd(ctx, []int64{inboxText.ID, inboxText.ID}, []string{`\seen`, `customlabel`}) // Same message twice.
	api.FlagsAdd(ctx, []int64{inboxText.ID}, []string{`another`})
	api.FlagsAdd(ctx, []int64{inboxText.ID}, []string{`another`})                           // No change.
	api.FlagsAdd(ctx, []int64{inboxText.ID}, []string{})                                    // Nothing to do.
	api.FlagsAdd(ctx, []int64{}, []string{})                                                // No messages, no flags.
	api.FlagsAdd(ctx, []int64{}, []string{`custom`})                                        // No message, new flag.
	api.FlagsAdd(ctx, []int64{inboxText.ID}, []string{`$junk`})                             // Trigger retrain.
	api.FlagsAdd(ctx, []int64{inboxText.ID}, []string{`$notjunk`})                          // Trigger retrain.
	api.FlagsAdd(ctx, []int64{inboxText.ID, testbox1Alt.ID}, []string{`$junk`, `$notjunk`}) // Trigger retrain, messages in different mailboxes.
	api.FlagsAdd(ctx, []int64{inboxHTML.ID, testbox1Alt.ID}, []string{`\Seen`, `newlabel`}) // Two mailboxes with counts and keywords changed.
	tneedError(t, func() { api.FlagsAdd(ctx, []int64{inboxText.ID}, []string{` bad syntax `}) })
	tneedError(t, func() { api.FlagsAdd(ctx, []int64{inboxText.ID}, []string{``}) })               // Empty is invalid.
	tneedError(t, func() { api.FlagsAdd(ctx, []int64{inboxText.ID}, []string{`\unknownsystem`}) }) // Only predefined system flags.

	// FlagsClear, inverse of FlagsAdd.
	api.FlagsClear(ctx, []int64{inboxText.ID}, []string{`\seen`, `customlabel`})
	api.FlagsClear(ctx, []int64{inboxText.ID, inboxHTML.ID}, []string{`\seen`, `customlabel`})
	api.FlagsClear(ctx, []int64{inboxText.ID, inboxText.ID}, []string{`\seen`, `customlabel`}) // Same message twice.
	api.FlagsClear(ctx, []int64{inboxText.ID}, []string{`another`})
	api.FlagsClear(ctx, []int64{inboxText.ID}, []string{`another`})
	api.FlagsClear(ctx, []int64{inboxText.ID}, []string{})
	api.FlagsClear(ctx, []int64{}, []string{})
	api.FlagsClear(ctx, []int64{}, []string{`custom`})
	api.FlagsClear(ctx, []int64{inboxText.ID}, []string{`$junk`})
	api.FlagsClear(ctx, []int64{inboxText.ID}, []string{`$notjunk`})
	api.FlagsClear(ctx, []int64{inboxText.ID, testbox1Alt.ID}, []string{`$junk`, `$notjunk`})
	api.FlagsClear(ctx, []int64{inboxHTML.ID, testbox1Alt.ID}, []string{`\Seen`}) // Two mailboxes with counts changed.
	tneedError(t, func() { api.FlagsClear(ctx, []int64{inboxText.ID}, []string{` bad syntax `}) })
	tneedError(t, func() { api.FlagsClear(ctx, []int64{inboxText.ID}, []string{``}) })
	tneedError(t, func() { api.FlagsClear(ctx, []int64{inboxText.ID}, []string{`\unknownsystem`}) })

	// MailboxSetSpecialUse
	var inbox, archive, sent, testbox1 store.Mailbox
	err = acc.DB.Read(ctx, func(tx *bstore.Tx) error {
		get := func(k string, v any) store.Mailbox {
			mb, err := bstore.QueryTx[store.Mailbox](tx).FilterEqual(k, v).Get()
			tcheck(t, err, "get special-use mailbox")
			return mb
		}
		get("Draft", true)
		sent = get("Sent", true)
		archive = get("Archive", true)
		get("Trash", true)
		get("Junk", true)

		inbox = get("Name", "Inbox")
		testbox1 = get("Name", "Testbox1")
		return nil
	})
	tcheck(t, err, "get mailboxes")
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: archive.ID, SpecialUse: store.SpecialUse{Draft: true}})  // Already set.
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: testbox1.ID, SpecialUse: store.SpecialUse{Draft: true}}) // New draft mailbox.
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: testbox1.ID, SpecialUse: store.SpecialUse{Sent: true}})
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: testbox1.ID, SpecialUse: store.SpecialUse{Archive: true}})
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: testbox1.ID, SpecialUse: store.SpecialUse{Trash: true}})
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: testbox1.ID, SpecialUse: store.SpecialUse{Junk: true}})
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: testbox1.ID, SpecialUse: store.SpecialUse{}})                                                                // None
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: testbox1.ID, SpecialUse: store.SpecialUse{Draft: true, Sent: true, Archive: true, Trash: true, Junk: true}}) // All
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: testbox1.ID, SpecialUse: store.SpecialUse{}})                                                                // None again.
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: sent.ID, SpecialUse: store.SpecialUse{Sent: true}})                                                          // Sent, for sending mail later.
	tneedError(t, func() { api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: 0}) })

	// MailboxRename
	api.MailboxRename(ctx, testbox1.ID, "Testbox2")
	api.MailboxRename(ctx, testbox1.ID, "Test/A/B/Box1")
	api.MailboxRename(ctx, testbox1.ID, "Test/A/Box1")
	api.MailboxRename(ctx, testbox1.ID, "Testbox1")
	tneedError(t, func() { api.MailboxRename(ctx, 0, "BadID") })
	tneedError(t, func() { api.MailboxRename(ctx, testbox1.ID, "Testbox1") }) // Already this name.
	tneedError(t, func() { api.MailboxRename(ctx, testbox1.ID, "Inbox") })    // Inbox not allowed.
	tneedError(t, func() { api.MailboxRename(ctx, inbox.ID, "Binbox") })      // Inbox not allowed.
	tneedError(t, func() { api.MailboxRename(ctx, testbox1.ID, "Archive") })  // Exists.

	// ParsedMessage
	// todo: verify contents
	api.ParsedMessage(ctx, inboxMinimal.ID)
	api.ParsedMessage(ctx, inboxText.ID)
	api.ParsedMessage(ctx, inboxHTML.ID)
	api.ParsedMessage(ctx, inboxAlt.ID)
	api.ParsedMessage(ctx, inboxAltRel.ID)
	api.ParsedMessage(ctx, testbox1Alt.ID)
	tneedError(t, func() { api.ParsedMessage(ctx, 0) })
	tneedError(t, func() { api.ParsedMessage(ctx, testmsgs[len(testmsgs)-1].ID+1) })

	// MailboxDelete
	api.MailboxDelete(ctx, testbox1.ID)
	testa, err := bstore.QueryDB[store.Mailbox](ctx, acc.DB).FilterEqual("Name", "Test/A").Get()
	tcheck(t, err, "get mailbox Test/A")
	tneedError(t, func() { api.MailboxDelete(ctx, testa.ID) })       // Test/A/B still exists.
	tneedError(t, func() { api.MailboxDelete(ctx, 0) })              // Bad ID.
	tneedError(t, func() { api.MailboxDelete(ctx, testbox1.ID) })    // No longer exists.
	tneedError(t, func() { api.MailboxDelete(ctx, inbox.ID) })       // Cannot remove inbox.
	tneedError(t, func() { api.ParsedMessage(ctx, testbox1Alt.ID) }) // Message was removed and no longer exists.

	api.MailboxCreate(ctx, "Testbox1")
	testbox1, err = bstore.QueryDB[store.Mailbox](ctx, acc.DB).FilterEqual("Name", "Testbox1").Get()
	tcheck(t, err, "get testbox1")
	tdeliver(t, acc, testbox1Alt)

	// MailboxEmpty
	api.MailboxEmpty(ctx, testbox1.ID)
	tneedError(t, func() { api.ParsedMessage(ctx, testbox1Alt.ID) }) // Message was removed and no longer exists.
	tneedError(t, func() { api.MailboxEmpty(ctx, 0) })               // Bad ID.

	// MessageMove
	tneedError(t, func() { api.MessageMove(ctx, []int64{testbox1Alt.ID}, inbox.ID) }) // Message was removed (with MailboxEmpty above).
	api.MessageMove(ctx, []int64{}, testbox1.ID)                                      // No messages.
	tdeliver(t, acc, testbox1Alt)
	tneedError(t, func() { api.MessageMove(ctx, []int64{testbox1Alt.ID}, testbox1.ID) }) // Already in destination mailbox.
	tneedError(t, func() { api.MessageMove(ctx, []int64{}, 0) })                         // Bad ID.
	api.MessageMove(ctx, []int64{inboxMinimal.ID, inboxHTML.ID}, testbox1.ID)
	api.MessageMove(ctx, []int64{inboxMinimal.ID, inboxHTML.ID, testbox1Alt.ID}, inbox.ID)                // From different mailboxes.
	api.FlagsAdd(ctx, []int64{inboxMinimal.ID}, []string{`minimallabel`})                                 // For move.
	api.MessageMove(ctx, []int64{inboxMinimal.ID}, testbox1.ID)                                           // Move causes new label for destination mailbox.
	api.MessageMove(ctx, []int64{rejectsMinimal.ID}, testbox1.ID)                                         // Move causing readjustment of MailboxOrigID due to Rejects mailbox.
	tneedError(t, func() { api.MessageMove(ctx, []int64{testbox1Alt.ID, inboxMinimal.ID}, testbox1.ID) }) // inboxMinimal already in destination.
	// Restore.
	api.MessageMove(ctx, []int64{inboxMinimal.ID}, inbox.ID)
	api.MessageMove(ctx, []int64{testbox1Alt.ID}, testbox1.ID)

	// MessageDelete
	api.MessageDelete(ctx, []int64{})                                               // No messages.
	api.MessageDelete(ctx, []int64{inboxMinimal.ID, inboxHTML.ID})                  // Same mailbox.
	api.MessageDelete(ctx, []int64{inboxText.ID, testbox1Alt.ID, inboxAltRel.ID})   // Multiple mailboxes, multiple times.
	tneedError(t, func() { api.MessageDelete(ctx, []int64{0}) })                    // Bad ID.
	tneedError(t, func() { api.MessageDelete(ctx, []int64{testbox1Alt.ID + 999}) }) // Bad ID
	tneedError(t, func() { api.MessageDelete(ctx, []int64{testbox1Alt.ID}) })       // Already removed.
	tdeliver(t, acc, testbox1Alt)
	tdeliver(t, acc, inboxAltRel)

	// MessageSubmit
	queue.Localserve = true // Deliver directly to us instead attempting actual delivery.
	api.MessageSubmit(ctx, SubmitMessage{
		From:      "mjl@mox.example",
		To:        []string{"mjl+to@mox.example", "mjl to2 <mjl+to2@mox.example>"},
		Cc:        []string{"mjl+cc@mox.example", "mjl cc2 <mjl+cc2@mox.example>"},
		Bcc:       []string{"mjl+bcc@mox.example", "mjl bcc2 <mjl+bcc2@mox.example>"},
		Subject:   "test email",
		TextBody:  "this is the content\n\ncheers,\nmox",
		ReplyTo:   "mjl replyto <mjl+replyto@mox.example>",
		UserAgent: "moxwebmail/dev",
	})
	// todo: check delivery of 6 messages to inbox, 1 to sent

	// Reply with attachments.
	api.MessageSubmit(ctx, SubmitMessage{
		From:     "mjl@mox.example",
		To:       []string{"mjl+to@mox.example"},
		Subject:  "Re: reply with attachments",
		TextBody: "sending you these fake png files",
		Attachments: []File{
			{
				Filename: "test1.png",
				DataURI:  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==",
			},
			{
				Filename: "test1.png",
				DataURI:  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==",
			},
		},
		ResponseMessageID: testbox1Alt.ID,
	})
	// todo: check answered flag

	// Forward with attachments.
	api.MessageSubmit(ctx, SubmitMessage{
		From:     "mjl@mox.example",
		To:       []string{"mjl+to@mox.example"},
		Subject:  "Fwd: the original subject",
		TextBody: "look what i got",
		Attachments: []File{
			{
				Filename: "test1.png",
				DataURI:  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==",
			},
		},
		ForwardAttachments: ForwardAttachments{
			MessageID: inboxAltRel.ID,
			Paths:     [][]int{{1, 1}, {1, 1}},
		},
		IsForward:         true,
		ResponseMessageID: testbox1Alt.ID,
	})
	// todo: check forwarded flag, check it has the right attachments.

	// Send from utf8 localpart.
	api.MessageSubmit(ctx, SubmitMessage{
		From:     "møx@mox.example",
		To:       []string{"mjl+to@mox.example"},
		TextBody: "test",
	})

	// Send to utf8 localpart.
	api.MessageSubmit(ctx, SubmitMessage{
		From:     "mjl@mox.example",
		To:       []string{"møx@mox.example"},
		TextBody: "test",
	})

	// Send to utf-8 text.
	api.MessageSubmit(ctx, SubmitMessage{
		From:     "mjl@mox.example",
		To:       []string{"mjl+to@mox.example"},
		Subject:  "hi ☺",
		TextBody: fmt.Sprintf("%80s", "tést"),
	})

	// Send without special-use Sent mailbox.
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: sent.ID, SpecialUse: store.SpecialUse{}})
	api.MessageSubmit(ctx, SubmitMessage{
		From:     "mjl@mox.example",
		To:       []string{"mjl+to@mox.example"},
		Subject:  "hi ☺",
		TextBody: fmt.Sprintf("%80s", "tést"),
	})

	// Message with From-address of another account.
	tneedError(t, func() {
		api.MessageSubmit(ctx, SubmitMessage{
			From:     "other@mox.example",
			To:       []string{"mjl+to@mox.example"},
			TextBody: "test",
		})
	})

	// Message with unknown address.
	tneedError(t, func() {
		api.MessageSubmit(ctx, SubmitMessage{
			From:     "doesnotexist@mox.example",
			To:       []string{"mjl+to@mox.example"},
			TextBody: "test",
		})
	})

	// Message without recipient.
	tneedError(t, func() {
		api.MessageSubmit(ctx, SubmitMessage{
			From:     "mjl@mox.example",
			TextBody: "test",
		})
	})

	api.maxMessageSize = 1
	tneedError(t, func() {
		api.MessageSubmit(ctx, SubmitMessage{
			From:     "mjl@mox.example",
			To:       []string{"mjl+to@mox.example"},
			Subject:  "too large",
			TextBody: "so many bytes",
		})
	})
	api.maxMessageSize = 1024 * 1024

	// Hit recipient limit.
	tneedError(t, func() {
		accConf, _ := acc.Conf()
		for i := 0; i <= accConf.MaxFirstTimeRecipientsPerDay; i++ {
			api.MessageSubmit(ctx, SubmitMessage{
				From:     fmt.Sprintf("user@mox%d.example", i),
				TextBody: "test",
			})
		}
	})

	// Hit message limit.
	tneedError(t, func() {
		accConf, _ := acc.Conf()
		for i := 0; i <= accConf.MaxOutgoingMessagesPerDay; i++ {
			api.MessageSubmit(ctx, SubmitMessage{
				From:     fmt.Sprintf("user@mox%d.example", i),
				TextBody: "test",
			})
		}
	})

	l, full := api.CompleteRecipient(ctx, "doesnotexist")
	tcompare(t, len(l), 0)
	tcompare(t, full, true)
	l, full = api.CompleteRecipient(ctx, "cc2")
	tcompare(t, l, []string{"mjl cc2 <mjl+cc2@mox.example>"})
	tcompare(t, full, true)

	// RecipientSecurity
	resolver := dns.MockResolver{}
	rs, err := recipientSecurity(ctx, resolver, "mjl@a.mox.example")
	tcompare(t, err, nil)
	tcompare(t, rs, RecipientSecurity{SecurityResultUnknown, SecurityResultNo, SecurityResultNo, SecurityResultNo, SecurityResultUnknown})
	err = acc.DB.Insert(ctx, &store.RecipientDomainTLS{Domain: "a.mox.example", STARTTLS: true, RequireTLS: false})
	tcheck(t, err, "insert recipient domain tls info")
	rs, err = recipientSecurity(ctx, resolver, "mjl@a.mox.example")
	tcompare(t, err, nil)
	tcompare(t, rs, RecipientSecurity{SecurityResultYes, SecurityResultNo, SecurityResultNo, SecurityResultNo, SecurityResultNo})
}
