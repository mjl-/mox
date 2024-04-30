package webmail

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

func TestView(t *testing.T) {
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
		acc.CheckClosed()
	}()

	api := Webmail{maxMessageSize: 1024 * 1024, cookiePath: "/"}

	respRec := httptest.NewRecorder()
	reqInfo := requestInfo{log, "mjl@mox.example", acc, "", respRec, &http.Request{RemoteAddr: "127.0.0.1:1234"}}
	ctx := context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)

	// Prepare loginToken.
	loginCookie := &http.Cookie{Name: "webmaillogin"}
	loginCookie.Value = api.LoginPrep(ctx)
	reqInfo.Request.Header = http.Header{"Cookie": []string{loginCookie.String()}}

	api.Login(ctx, loginCookie.Value, "mjl@mox.example", "test1234")
	var sessionCookie *http.Cookie
	for _, c := range respRec.Result().Cookies() {
		if c.Name == "webmailsession" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("missing session cookie")
	}
	sct := strings.SplitN(sessionCookie.Value, " ", 2)
	if len(sct) != 2 || sct[1] != "mjl" {
		t.Fatalf("unexpected accountname %q in session cookie", sct[1])
	}
	sessionToken := store.SessionToken(sct[0])

	reqInfo = requestInfo{log, "mjl@mox.example", acc, sessionToken, respRec, &http.Request{}}
	ctx = context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)

	api.MailboxCreate(ctx, "Lists/Go/Nuts")

	var zerom store.Message
	var (
		inboxMinimal       = &testmsg{"Inbox", store.Flags{}, nil, msgMinimal, zerom, 0}
		inboxFlags         = &testmsg{"Inbox", store.Flags{Seen: true}, []string{"testlabel"}, msgAltRel, zerom, 0} // With flags, and larger.
		listsMinimal       = &testmsg{"Lists", store.Flags{}, nil, msgMinimal, zerom, 0}
		listsGoNutsMinimal = &testmsg{"Lists/Go/Nuts", store.Flags{}, nil, msgMinimal, zerom, 0}
		trashMinimal       = &testmsg{"Trash", store.Flags{}, nil, msgMinimal, zerom, 0}
		junkMinimal        = &testmsg{"Trash", store.Flags{}, nil, msgMinimal, zerom, 0}
		trashAlt           = &testmsg{"Trash", store.Flags{}, nil, msgAlt, zerom, 0}
		inboxAltReply      = &testmsg{"Inbox", store.Flags{}, nil, msgAltReply, zerom, 0}
	)
	var testmsgs = []*testmsg{inboxMinimal, inboxFlags, listsMinimal, listsGoNutsMinimal, trashMinimal, junkMinimal, trashAlt, inboxAltReply}
	for _, tm := range testmsgs {
		tdeliver(t, acc, tm)
	}

	// Token
	tokens := []string{}
	for i := 0; i < 20; i++ {
		tokens = append(tokens, api.Token(ctx))
	}
	// Only last 10 tokens are still valid and around, checked below.

	// Request
	tneedError(t, func() { api.Request(ctx, Request{ID: 1, Cancel: true}) }) // Zero/invalid SSEID.

	// We start an actual HTTP server to easily get a body we can do blocking reads on.
	// With a httptest.ResponseRecorder, it's a bit more work to parse SSE events as
	// they come in.
	server := httptest.NewServer(http.HandlerFunc(Handler(1024*1024, "/webmail/", false, "")))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	tcheck(t, err, "parsing server url")
	_, port, err := net.SplitHostPort(serverURL.Host)
	tcheck(t, err, "parsing host port in server url")
	eventsURL := fmt.Sprintf("http://%s/events", net.JoinHostPort("localhost", port))

	request := Request{
		Page: Page{Count: 10},
	}
	requestJSON, err := json.Marshal(request)
	tcheck(t, err, "marshal request as json")

	testFail := func(method, path string, expStatusCode int) {
		t.Helper()
		req, err := http.NewRequest(method, path, nil)
		tcheck(t, err, "making request")
		resp, err := http.DefaultClient.Do(req)
		tcheck(t, err, "http transaction")
		resp.Body.Close()
		if resp.StatusCode != expStatusCode {
			t.Fatalf("got statuscode %d, expected %d", resp.StatusCode, expStatusCode)
		}
	}

	testFail("POST", eventsURL+"?token="+tokens[0]+"&request="+string(requestJSON), http.StatusMethodNotAllowed) // Must be GET.
	testFail("GET", eventsURL, http.StatusBadRequest)                                                            // Missing token.
	testFail("GET", eventsURL+"?token="+tokens[0]+"&request="+string(requestJSON), http.StatusBadRequest)        // Bad (old) token.
	testFail("GET", eventsURL+"?token="+tokens[len(tokens)-5]+"&request=bad", http.StatusBadRequest)             // Bad request.

	// Start connection for testing and filters below.
	req, err := http.NewRequest("GET", eventsURL+"?token="+tokens[len(tokens)-1]+"&request="+string(requestJSON), nil)
	tcheck(t, err, "making request")
	resp, err := http.DefaultClient.Do(req)
	tcheck(t, err, "http transaction")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got statuscode %d, expected %d (%s)", resp.StatusCode, http.StatusOK, readBody(resp.Body))
	}

	evr := eventReader{t, bufio.NewReader(resp.Body), resp.Body}
	var start EventStart
	evr.Get("start", &start)
	var viewMsgs EventViewMsgs
	evr.Get("viewMsgs", &viewMsgs)
	tcompare(t, len(viewMsgs.MessageItems), 3)
	tcompare(t, viewMsgs.ViewEnd, true)

	var inbox, archive, lists, trash store.Mailbox
	for _, mb := range start.Mailboxes {
		if mb.Archive {
			archive = mb
		} else if mb.Name == start.MailboxName {
			inbox = mb
		} else if mb.Name == "Lists" {
			lists = mb
		} else if mb.Name == "Trash" {
			trash = mb
		}
	}

	// Can only use a token once.
	testFail("GET", eventsURL+"?token="+tokens[len(tokens)-1]+"&request=bad", http.StatusBadRequest)

	// Check a few initial query/page combinations.
	testConn := func(token, more string, request Request, check func(EventStart, eventReader)) {
		t.Helper()

		reqJSON, err := json.Marshal(request)
		tcheck(t, err, "marshal request json")
		req, err := http.NewRequest("GET", eventsURL+"?token="+token+more+"&request="+string(reqJSON), nil)
		tcheck(t, err, "making request")
		resp, err := http.DefaultClient.Do(req)
		tcheck(t, err, "http transaction")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got statuscode %d, expected %d", resp.StatusCode, http.StatusOK)
		}

		xevr := eventReader{t, bufio.NewReader(resp.Body), resp.Body}
		var xstart EventStart
		xevr.Get("start", &xstart)
		check(start, xevr)
	}

	// Connection with waitMinMsec/waitMaxMsec, just exercising code path.
	waitReq := Request{
		Page: Page{Count: 10},
	}
	testConn(api.Token(ctx), "&waitMinMsec=1&waitMaxMsec=2", waitReq, func(start EventStart, evr eventReader) {
		var vm EventViewMsgs
		evr.Get("viewMsgs", &vm)
		tcompare(t, len(vm.MessageItems), 3)
	})

	// Connection with DestMessageID.
	destMsgReq := Request{
		Query: Query{
			Filter: Filter{MailboxID: inbox.ID},
		},
		Page: Page{DestMessageID: inboxFlags.ID, Count: 10},
	}
	testConn(tokens[len(tokens)-3], "", destMsgReq, func(start EventStart, evr eventReader) {
		var vm EventViewMsgs
		evr.Get("viewMsgs", &vm)
		tcompare(t, len(vm.MessageItems), 3)
		tcompare(t, vm.ParsedMessage.ID, destMsgReq.Page.DestMessageID)
	})
	// todo: destmessageid past count, needs large mailbox

	// Connection with missing DestMessageID, still fine.
	badDestMsgReq := Request{
		Query: Query{
			Filter: Filter{MailboxID: inbox.ID},
		},
		Page: Page{DestMessageID: inboxFlags.ID + 999, Count: 10},
	}
	testConn(api.Token(ctx), "", badDestMsgReq, func(start EventStart, evr eventReader) {
		var vm EventViewMsgs
		evr.Get("viewMsgs", &vm)
		tcompare(t, len(vm.MessageItems), 3)
	})

	// Connection with missing unknown AnchorMessageID, resets view.
	badAnchorMsgReq := Request{
		Query: Query{
			Filter: Filter{MailboxID: inbox.ID},
		},
		Page: Page{AnchorMessageID: inboxFlags.ID + 999, Count: 10},
	}
	testConn(api.Token(ctx), "", badAnchorMsgReq, func(start EventStart, evr eventReader) {
		var viewReset EventViewReset
		evr.Get("viewReset", &viewReset)

		var vm EventViewMsgs
		evr.Get("viewMsgs", &vm)
		tcompare(t, len(vm.MessageItems), 3)
	})

	// Connection that starts with a filter, without mailbox.
	searchReq := Request{
		Query: Query{
			Filter: Filter{Labels: []string{`\seen`}},
		},
		Page: Page{Count: 10},
	}
	testConn(api.Token(ctx), "", searchReq, func(start EventStart, evr eventReader) {
		var vm EventViewMsgs
		evr.Get("viewMsgs", &vm)
		tcompare(t, len(vm.MessageItems), 1)
		tcompare(t, vm.MessageItems[0][0].Message.ID, inboxFlags.ID)
	})

	// Paginate from previous last element. There is nothing new.
	var viewID int64 = 1
	api.Request(ctx, Request{ID: 1, SSEID: start.SSEID, ViewID: viewID, Query: Query{Filter: Filter{MailboxID: inbox.ID}}, Page: Page{Count: 10, AnchorMessageID: viewMsgs.MessageItems[len(viewMsgs.MessageItems)-1][0].Message.ID}})
	evr.Get("viewMsgs", &viewMsgs)
	tcompare(t, len(viewMsgs.MessageItems), 0)

	// Request archive mailbox, empty.
	viewID++
	api.Request(ctx, Request{ID: 1, SSEID: start.SSEID, ViewID: viewID, Query: Query{Filter: Filter{MailboxID: archive.ID}}, Page: Page{Count: 10}})
	evr.Get("viewMsgs", &viewMsgs)
	tcompare(t, len(viewMsgs.MessageItems), 0)
	tcompare(t, viewMsgs.ViewEnd, true)

	threadlen := func(mil [][]MessageItem) int {
		n := 0
		for _, l := range mil {
			n += len(l)
		}
		return n
	}

	// Request with threading, should also include parent message from Trash mailbox (trashAlt).
	viewID++
	api.Request(ctx, Request{ID: 1, SSEID: start.SSEID, ViewID: viewID, Query: Query{Filter: Filter{MailboxID: inbox.ID}, Threading: "unread"}, Page: Page{Count: 10}})
	evr.Get("viewMsgs", &viewMsgs)
	tcompare(t, len(viewMsgs.MessageItems), 3)
	tcompare(t, threadlen(viewMsgs.MessageItems), 3+1)
	tcompare(t, viewMsgs.ViewEnd, true)
	// And likewise when querying Trash, should also include child message in Inbox (inboxAltReply).
	viewID++
	api.Request(ctx, Request{ID: 1, SSEID: start.SSEID, ViewID: viewID, Query: Query{Filter: Filter{MailboxID: trash.ID}, Threading: "on"}, Page: Page{Count: 10}})
	evr.Get("viewMsgs", &viewMsgs)
	tcompare(t, len(viewMsgs.MessageItems), 3)
	tcompare(t, threadlen(viewMsgs.MessageItems), 3+1)
	tcompare(t, viewMsgs.ViewEnd, true)
	// Without threading, the inbox has just 3 messages.
	viewID++
	api.Request(ctx, Request{ID: 1, SSEID: start.SSEID, ViewID: viewID, Query: Query{Filter: Filter{MailboxID: inbox.ID}, Threading: "off"}, Page: Page{Count: 10}})
	evr.Get("viewMsgs", &viewMsgs)
	tcompare(t, len(viewMsgs.MessageItems), 3)
	tcompare(t, threadlen(viewMsgs.MessageItems), 3)
	tcompare(t, viewMsgs.ViewEnd, true)

	testFilter := func(orderAsc bool, f Filter, nf NotFilter, expIDs []int64) {
		t.Helper()
		viewID++
		api.Request(ctx, Request{ID: 1, SSEID: start.SSEID, ViewID: viewID, Query: Query{OrderAsc: orderAsc, Filter: f, NotFilter: nf}, Page: Page{Count: 10}})
		evr.Get("viewMsgs", &viewMsgs)
		ids := make([]int64, len(viewMsgs.MessageItems))
		for i, mi := range viewMsgs.MessageItems {
			ids[i] = mi[0].Message.ID
		}
		tcompare(t, ids, expIDs)
		tcompare(t, viewMsgs.ViewEnd, true)
	}

	// Test filtering.
	var znf NotFilter
	testFilter(false, Filter{MailboxID: lists.ID, MailboxChildrenIncluded: true}, znf, []int64{listsGoNutsMinimal.ID, listsMinimal.ID})              // Mailbox and sub mailbox.
	testFilter(true, Filter{MailboxID: lists.ID, MailboxChildrenIncluded: true}, znf, []int64{listsMinimal.ID, listsGoNutsMinimal.ID})               // Oldest first first.
	testFilter(false, Filter{MailboxID: -1}, znf, []int64{inboxAltReply.ID, listsGoNutsMinimal.ID, listsMinimal.ID, inboxFlags.ID, inboxMinimal.ID}) // All except trash/junk/rejects.
	testFilter(false, Filter{Labels: []string{`\seen`}}, znf, []int64{inboxFlags.ID})
	testFilter(false, Filter{MailboxID: inbox.ID}, NotFilter{Labels: []string{`\seen`}}, []int64{inboxAltReply.ID, inboxMinimal.ID})
	testFilter(false, Filter{Labels: []string{`testlabel`}}, znf, []int64{inboxFlags.ID})
	testFilter(false, Filter{MailboxID: inbox.ID}, NotFilter{Labels: []string{`testlabel`}}, []int64{inboxAltReply.ID, inboxMinimal.ID})
	testFilter(false, Filter{MailboxID: inbox.ID, Oldest: &inboxFlags.m.Received}, znf, []int64{inboxAltReply.ID, inboxFlags.ID})
	testFilter(false, Filter{MailboxID: inbox.ID, Newest: &inboxMinimal.m.Received}, znf, []int64{inboxMinimal.ID})
	testFilter(false, Filter{MailboxID: inbox.ID, SizeMin: inboxFlags.m.Size}, znf, []int64{inboxFlags.ID})
	testFilter(false, Filter{MailboxID: inbox.ID, SizeMax: inboxMinimal.m.Size}, znf, []int64{inboxMinimal.ID})
	testFilter(false, Filter{From: []string{"mjl+altrel@mox.example"}}, znf, []int64{inboxFlags.ID})
	testFilter(false, Filter{MailboxID: inbox.ID}, NotFilter{From: []string{"mjl+altrel@mox.example"}}, []int64{inboxAltReply.ID, inboxMinimal.ID})
	testFilter(false, Filter{To: []string{"mox+altrel@other.example"}}, znf, []int64{inboxFlags.ID})
	testFilter(false, Filter{MailboxID: inbox.ID}, NotFilter{To: []string{"mox+altrel@other.example"}}, []int64{inboxAltReply.ID, inboxMinimal.ID})
	testFilter(false, Filter{From: []string{"mjl+altrel@mox.example", "bogus"}}, znf, []int64{})
	testFilter(false, Filter{To: []string{"mox+altrel@other.example", "bogus"}}, znf, []int64{})
	testFilter(false, Filter{Subject: []string{"test", "alt", "rel"}}, znf, []int64{inboxFlags.ID})
	testFilter(false, Filter{MailboxID: inbox.ID}, NotFilter{Subject: []string{"alt"}}, []int64{inboxAltReply.ID, inboxMinimal.ID})
	testFilter(false, Filter{MailboxID: inbox.ID, Words: []string{"the text body", "body", "the "}}, znf, []int64{inboxFlags.ID})
	testFilter(false, Filter{MailboxID: inbox.ID}, NotFilter{Words: []string{"the text body"}}, []int64{inboxAltReply.ID, inboxMinimal.ID})
	testFilter(false, Filter{Headers: [][2]string{{"X-Special", ""}}}, znf, []int64{inboxFlags.ID})
	testFilter(false, Filter{Headers: [][2]string{{"X-Special", "testing"}}}, znf, []int64{inboxFlags.ID})
	testFilter(false, Filter{Headers: [][2]string{{"X-Special", "other"}}}, znf, []int64{})
	testFilter(false, Filter{Attachments: AttachmentImage}, znf, []int64{inboxFlags.ID})
	testFilter(false, Filter{MailboxID: inbox.ID}, NotFilter{Attachments: AttachmentImage}, []int64{inboxAltReply.ID, inboxMinimal.ID})

	// Test changes.
	getChanges := func(changes ...any) {
		t.Helper()
		var viewChanges EventViewChanges
		evr.Get("viewChanges", &viewChanges)
		if len(viewChanges.Changes) != len(changes) {
			t.Fatalf("got %d changes, expected %d", len(viewChanges.Changes), len(changes))
		}
		for i, dst := range changes {
			src := viewChanges.Changes[i]
			dstType := reflect.TypeOf(dst).Elem().Name()
			if src[0] != dstType {
				t.Fatalf("change %d is of type %s, expected %s", i, src[0], dstType)
			}
			// Marshal and unmarshal is easiest...
			buf, err := json.Marshal(src[1])
			tcheck(t, err, "marshal change")
			dec := json.NewDecoder(bytes.NewReader(buf))
			dec.DisallowUnknownFields()
			err = dec.Decode(dst)
			tcheck(t, err, "parsing change")
		}
	}

	// ChangeMailboxAdd
	api.MailboxCreate(ctx, "Newbox")
	var chmbadd ChangeMailboxAdd
	getChanges(&chmbadd)
	tcompare(t, chmbadd.Mailbox.Name, "Newbox")

	// ChangeMailboxRename
	api.MailboxRename(ctx, chmbadd.Mailbox.ID, "Newbox2")
	var chmbrename ChangeMailboxRename
	getChanges(&chmbrename)
	tcompare(t, chmbrename, ChangeMailboxRename{
		ChangeRenameMailbox: store.ChangeRenameMailbox{MailboxID: chmbadd.Mailbox.ID, OldName: "Newbox", NewName: "Newbox2", Flags: nil},
	})

	// ChangeMailboxSpecialUse
	api.MailboxSetSpecialUse(ctx, store.Mailbox{ID: chmbadd.Mailbox.ID, SpecialUse: store.SpecialUse{Archive: true}})
	var chmbspecialuseOld, chmbspecialuseNew ChangeMailboxSpecialUse
	getChanges(&chmbspecialuseOld, &chmbspecialuseNew)
	tcompare(t, chmbspecialuseOld, ChangeMailboxSpecialUse{
		ChangeMailboxSpecialUse: store.ChangeMailboxSpecialUse{MailboxID: archive.ID, MailboxName: "Archive", SpecialUse: store.SpecialUse{}},
	})
	tcompare(t, chmbspecialuseNew, ChangeMailboxSpecialUse{
		ChangeMailboxSpecialUse: store.ChangeMailboxSpecialUse{MailboxID: chmbadd.Mailbox.ID, MailboxName: "Newbox2", SpecialUse: store.SpecialUse{Archive: true}},
	})

	// ChangeMailboxRemove
	api.MailboxDelete(ctx, chmbadd.Mailbox.ID)
	var chmbremove ChangeMailboxRemove
	getChanges(&chmbremove)
	tcompare(t, chmbremove, ChangeMailboxRemove{
		ChangeRemoveMailbox: store.ChangeRemoveMailbox{MailboxID: chmbadd.Mailbox.ID, Name: "Newbox2"},
	})

	// ChangeMsgAdd
	inboxNew := &testmsg{"Inbox", store.Flags{}, nil, msgMinimal, zerom, 0}
	tdeliver(t, acc, inboxNew)
	var chmsgadd ChangeMsgAdd
	var chmbcounts ChangeMailboxCounts
	getChanges(&chmsgadd, &chmbcounts)
	tcompare(t, chmsgadd.ChangeAddUID.MailboxID, inbox.ID)
	tcompare(t, chmsgadd.MessageItems[0].Message.ID, inboxNew.ID)
	chmbcounts.Size = 0
	tcompare(t, chmbcounts, ChangeMailboxCounts{
		ChangeMailboxCounts: store.ChangeMailboxCounts{
			MailboxID:     inbox.ID,
			MailboxName:   inbox.Name,
			MailboxCounts: store.MailboxCounts{Total: 4, Unread: 3, Unseen: 3},
		},
	})

	// ChangeMsgFlags
	api.FlagsAdd(ctx, []int64{inboxNew.ID}, []string{`\seen`, `changelabel`, `aaa`})
	var chmsgflags ChangeMsgFlags
	var chmbkeywords ChangeMailboxKeywords
	getChanges(&chmsgflags, &chmbcounts, &chmbkeywords)
	tcompare(t, chmsgadd.ChangeAddUID.MailboxID, inbox.ID)
	tcompare(t, chmbkeywords, ChangeMailboxKeywords{
		ChangeMailboxKeywords: store.ChangeMailboxKeywords{
			MailboxID:   inbox.ID,
			MailboxName: inbox.Name,
			Keywords:    []string{`aaa`, `changelabel`},
		},
	})
	chmbcounts.Size = 0
	tcompare(t, chmbcounts, ChangeMailboxCounts{
		ChangeMailboxCounts: store.ChangeMailboxCounts{
			MailboxID:     inbox.ID,
			MailboxName:   inbox.Name,
			MailboxCounts: store.MailboxCounts{Total: 4, Unread: 2, Unseen: 2},
		},
	})

	// ChangeMsgRemove
	api.MessageDelete(ctx, []int64{inboxNew.ID, inboxMinimal.ID})
	var chmsgremove ChangeMsgRemove
	getChanges(&chmbcounts, &chmsgremove)
	tcompare(t, chmsgremove.ChangeRemoveUIDs.MailboxID, inbox.ID)
	tcompare(t, chmsgremove.ChangeRemoveUIDs.UIDs, []store.UID{inboxMinimal.m.UID, inboxNew.m.UID})
	chmbcounts.Size = 0
	tcompare(t, chmbcounts, ChangeMailboxCounts{
		ChangeMailboxCounts: store.ChangeMailboxCounts{
			MailboxID:     inbox.ID,
			MailboxName:   inbox.Name,
			MailboxCounts: store.MailboxCounts{Total: 2, Unread: 1, Unseen: 1},
		},
	})

	// ChangeMsgThread
	api.ThreadCollapse(ctx, []int64{inboxAltReply.ID}, true)
	var chmsgthread ChangeMsgThread
	getChanges(&chmsgthread)
	tcompare(t, chmsgthread.ChangeThread, store.ChangeThread{MessageIDs: []int64{inboxAltReply.ID}, Muted: false, Collapsed: true})

	// Now collapsing the thread root, the child is already collapsed so no change.
	api.ThreadCollapse(ctx, []int64{trashAlt.ID}, true)
	getChanges(&chmsgthread)
	tcompare(t, chmsgthread.ChangeThread, store.ChangeThread{MessageIDs: []int64{trashAlt.ID}, Muted: false, Collapsed: true})

	// Expand thread root, including change for child.
	api.ThreadCollapse(ctx, []int64{trashAlt.ID}, false)
	var chmsgthread2 ChangeMsgThread
	getChanges(&chmsgthread, &chmsgthread2)
	tcompare(t, chmsgthread.ChangeThread, store.ChangeThread{MessageIDs: []int64{trashAlt.ID}, Muted: false, Collapsed: false})
	tcompare(t, chmsgthread2.ChangeThread, store.ChangeThread{MessageIDs: []int64{inboxAltReply.ID}, Muted: false, Collapsed: false})

	// Mute thread, including child, also collapses.
	api.ThreadMute(ctx, []int64{trashAlt.ID}, true)
	getChanges(&chmsgthread, &chmsgthread2)
	tcompare(t, chmsgthread.ChangeThread, store.ChangeThread{MessageIDs: []int64{trashAlt.ID}, Muted: true, Collapsed: true})
	tcompare(t, chmsgthread2.ChangeThread, store.ChangeThread{MessageIDs: []int64{inboxAltReply.ID}, Muted: true, Collapsed: true})

	// And unmute Mute thread, including child. Messages are not expanded.
	api.ThreadMute(ctx, []int64{trashAlt.ID}, false)
	getChanges(&chmsgthread, &chmsgthread2)
	tcompare(t, chmsgthread.ChangeThread, store.ChangeThread{MessageIDs: []int64{trashAlt.ID}, Muted: false, Collapsed: true})
	tcompare(t, chmsgthread2.ChangeThread, store.ChangeThread{MessageIDs: []int64{inboxAltReply.ID}, Muted: false, Collapsed: true})

	// todo: check move operations and their changes, e.g. MailboxDelete, MailboxEmpty, MessageRemove.
}

type eventReader struct {
	t  *testing.T
	br *bufio.Reader
	r  io.Closer
}

func (r eventReader) Get(name string, event any) {
	timer := time.AfterFunc(2*time.Second, func() {
		r.r.Close()
		pkglog.Print("event timeout")
	})
	defer timer.Stop()

	t := r.t
	t.Helper()
	var ev string
	var data []byte
	var keepalive bool
	for {
		line, err := r.br.ReadBytes(byte('\n'))
		tcheck(t, err, "read line")
		line = bytes.TrimRight(line, "\n")
		// fmt.Printf("have line %s\n", line)

		if bytes.HasPrefix(line, []byte("event: ")) {
			ev = string(line[len("event: "):])
		} else if bytes.HasPrefix(line, []byte("data: ")) {
			data = line[len("data: "):]
		} else if bytes.HasPrefix(line, []byte(":")) {
			keepalive = true
		} else if len(line) == 0 {
			if keepalive {
				keepalive = false
				continue
			}
			if ev != name {
				t.Fatalf("got event %q (%s), expected %q", ev, data, name)
			}
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.DisallowUnknownFields()
			err := dec.Decode(event)
			tcheck(t, err, "unmarshal json")
			return
		}
	}
}
